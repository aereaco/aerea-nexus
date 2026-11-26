// UX Gateway - Salvo-based multi-port reverse proxy
// Architecture: HTTPS (443) + HTTP (80) + Optional direct access ports

use salvo::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::db::Database;
use crate::js::cell::CellManager;
use crate::storage::cas_store::{CasStore, ReconciliationReport, DEFAULT_DELETE_CLAIM_TTL_MS};
use crate::storage::BlobBridge;
use crate::ux::cell_router::CellGatewayHandler;
use crate::ux::surreal_ws::WebSocketHandler;
use crate::ux::s3_proxy::S3ProxyHandler;

/// Fail-closed middleware that blocks storage-dependent routes with `503 Service Unavailable`
/// until `UxGateway::reconcile_storage_on_boot()` has completed durably.
#[derive(Clone)]
struct BootRecoveryGateMiddleware {
    storage_ready: Arc<AtomicBool>,
}

#[async_trait]
impl Handler for BootRecoveryGateMiddleware {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if !self.storage_ready.load(Ordering::SeqCst) {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Json(serde_json::json!({
                "error": "Storage boot recovery has not completed yet"
            })));
            ctrl.skip_rest();
        }
    }
}

/// Readiness probe (`/ready`): returns `503 Service Unavailable` until startup storage
/// reconciliation completes, and `200 OK` once ready (distinct from `/health` liveness).
#[derive(Clone)]
struct ReadinessHandler {
    storage_ready: Arc<AtomicBool>,
}

#[async_trait]
impl Handler for ReadinessHandler {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        if self.storage_ready.load(Ordering::SeqCst) {
            res.status_code(StatusCode::OK);
            res.render(Json(serde_json::json!({ "ready": true })));
        } else {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Json(serde_json::json!({
                "ready": false,
                "reason": "storage_boot_recovery_pending"
            })));
        }
    }
}

/// Gateway configuration - controls which ports and web policies are exposed
#[derive(Clone)]
pub struct GatewayConfig {
    pub enable_https: bool,          // Port 443 (primary gateway)
    pub enable_http: bool,           // Port 80 (ACME + redirects)
    pub enable_surreal_direct: bool, // Port 8000 (direct DB access)
    pub enable_pgwire: bool,         // Port 5432 (PostgreSQL v3 wire protocol)
    pub pgwire_port: u16,            // Default 5432
    pub enable_mysqlwire: bool,      // Port 3306 (MySQL v10 wire protocol)
    pub mysqlwire_port: u16,         // Default 3306
    pub enable_s3_direct: bool,      // Port 3900 (S3 API)
    pub enable_metrics: bool,        // Port 9090 (Prometheus)
    pub acme_domain: Option<String>, // Domain for ACME certs
    pub acme_email: Option<String>,  // Contact email for Let's Encrypt
    pub web_root: Option<std::path::PathBuf>,
    pub dist_root: Option<std::path::PathBuf>,
    pub coop_header: Option<String>,
    pub coep_header: Option<String>,
}

fn parse_optional_header_env(var: &str, default_val: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("none")
                || trimmed.eq_ignore_ascii_case("off")
                || trimmed.eq_ignore_ascii_case("false")
            {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(_) => Some(default_val.to_string()),
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enable_https: true,
            enable_http: true,
            enable_surreal_direct: false,
            enable_pgwire: std::env::var("NEXUS_ENABLE_PGWIRE").as_deref() == Ok("1"),
            pgwire_port: std::env::var("NEXUS_PGWIRE_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5432),
            enable_mysqlwire: std::env::var("NEXUS_ENABLE_MYSQLWIRE").as_deref() == Ok("1"),
            mysqlwire_port: std::env::var("NEXUS_MYSQLWIRE_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3306),
            enable_s3_direct: false,
            enable_metrics: false,
            acme_domain: None,
            acme_email: None,
            web_root: std::env::var("NEXUS_WEB_ROOT")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(std::path::PathBuf::from),
            dist_root: std::env::var("NEXUS_DIST_ROOT")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(std::path::PathBuf::from),
            coop_header: parse_optional_header_env("NEXUS_WEB_COOP", "same-origin"),
            coep_header: parse_optional_header_env("NEXUS_WEB_COEP", "credentialless"),
        }
    }
}

/// UX Gateway - The browser's entry point to the Nexus-IO kernel
#[derive(Clone)]
pub struct UxGateway {
    db: Arc<Database>,
    garage: Arc<BlobBridge>,
    cells: Arc<CellManager>,
    config: GatewayConfig,
    storage_ready: Arc<AtomicBool>,
}

impl UxGateway {
    pub fn new(db: Arc<Database>, garage: Arc<BlobBridge>, config: GatewayConfig) -> Self {
        let cells = Arc::new(CellManager::new(db.clone(), garage.clone()));
        Self {
            db,
            garage,
            cells,
            config,
            storage_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Startup invariant: run `CasStore::reconcile_on_boot()` across both durable CAS buckets
    /// (`nexus-wasm-db` and `nexus-runtimes`) to replay any incomplete write-ahead `OwnershipTx`
    /// journals and recover expired `DeleteClaim`s BEFORE the gateway accepts cell work.
    pub async fn reconcile_storage_on_boot(
        &self,
    ) -> anyhow::Result<(ReconciliationReport, ReconciliationReport)> {
        let cas = CasStore::new(self.garage.clone());
        let empty = std::collections::HashSet::new();
        let db_rep = cas
            .reconcile_on_boot(
                "nexus-wasm-db",
                "blobs/",
                &empty,
                DEFAULT_DELETE_CLAIM_TTL_MS,
                false,
            )
            .await?;
        let rt_rep = cas
            .reconcile_on_boot(
                "nexus-runtimes",
                "cid/",
                &empty,
                DEFAULT_DELETE_CLAIM_TTL_MS,
                false,
            )
            .await?;
        self.storage_ready.store(true, Ordering::SeqCst);
        Ok((db_rep, rt_rep))
    }

    pub fn is_storage_ready(&self) -> bool {
        self.storage_ready.load(Ordering::SeqCst)
    }

    /// Start all configured gateway listeners (always completes storage boot recovery first).
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let (db_rep, rt_rep) = self.reconcile_storage_on_boot().await?;
        if !db_rep.skipped || !rt_rep.skipped {
            println!(
                "🔄 Storage boot recovery complete (wasm-db tx={}, claims={}; runtimes tx={}, claims={})",
                db_rep.tx_replayed,
                db_rep.expired_claims_recovered,
                rt_rep.tx_replayed,
                rt_rep.expired_claims_recovered
            );
        }

        println!("🌐 Nexus-IO Gateway starting...");
        println!("   HTTPS (443): {}", if self.config.enable_https { "✅" } else { "❌" });
        println!("   HTTP (80):   {}", if self.config.enable_http { "✅" } else { "❌" });
        println!("   DB Direct:   {}", if self.config.enable_surreal_direct { "✅" } else { "❌" });
        println!("   S3 Direct:   {}", if self.config.enable_s3_direct { "✅" } else { "❌" });
        println!("   Metrics:     {}", if self.config.enable_metrics { "✅" } else { "❌" });

        let mut handles = vec![];

        // Port 443: HTTPS Gateway (primary)
        if self.config.enable_https {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_https().await {
                    eprintln!("âŒ HTTPS gateway error: {}", e);
                }
            }));
        }

        // Port 5432: PostgreSQL v3 Wire Protocol (`PgWireSession`) — disabled by default
        #[cfg(feature = "db-pgwire")]
        if self.config.enable_pgwire {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_pgwire().await {
                    eprintln!("âŒ PgWire listener error: {}", e);
                }
            }));
        }

        // Port 3306: MySQL v10 Wire Protocol (`MySqlWireSession`) — disabled by default
        #[cfg(feature = "db-mysqlwire")]
        if self.config.enable_mysqlwire {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_mysqlwire().await {
                    eprintln!("âŒ MySQL wire listener error: {}", e);
                }
            }));
        }

        // Port 80: HTTP Redirect + ACME challenges
        if self.config.enable_http {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_http().await {
                    eprintln!("âŒ HTTP redirect error: {}", e);
                }
            }));
        }

        // Optional: Port 8000 (SurrealDB direct)
        if self.config.enable_surreal_direct {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_surreal_direct().await {
                    eprintln!("âŒ SurrealDB direct access error: {}", e);
                }
            }));
        }

        // Optional: Port 3900 (Garage S3 direct)
        if self.config.enable_s3_direct {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_s3_direct().await {
                    eprintln!("âŒ S3 direct access error: {}", e);
                }
            }));
        }

        // Optional: Port 9090 (Metrics)
        if self.config.enable_metrics {
            let gateway = self.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = gateway.serve_metrics().await {
                    eprintln!("âŒ Metrics server error: {}", e);
                }
            }));
        }

        // Wait for all services
        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    /// Primary gateway listener:
    /// - Uses real Rustls HTTPS/TLS ONLY when `NEXUS_TLS_CERT` + `NEXUS_TLS_KEY` PEM files are configured.
    /// - Otherwise runs an explicitly labeled plaintext dev HTTP listener on `127.0.0.1:8443` (or `NEXUS_HTTP_BIND`).
    async fn serve_https(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = self.build_main_router();

        if let (Ok(cert_path), Ok(key_path)) = (
            std::env::var("NEXUS_TLS_CERT"),
            std::env::var("NEXUS_TLS_KEY"),
        ) {
            let bind_addr =
                std::env::var("NEXUS_HTTPS_BIND").unwrap_or_else(|_| "0.0.0.0:443".to_string());
            let cert = std::fs::read(&cert_path)?;
            let key = std::fs::read(&key_path)?;
            let config = salvo::conn::rustls::RustlsConfig::new(
                salvo::conn::rustls::Keycert::new().cert(cert).key(key),
            );
            let acceptor = TcpListener::new(bind_addr.clone()).rustls(config).bind().await;
            println!("🔒 HTTPS/TLS Gateway listening on https://{}", bind_addr);
            Server::new(acceptor).serve(router).await;
            return Ok(());
        }

        let dev_bind =
            std::env::var("NEXUS_HTTP_BIND").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
        println!(
            "⚠️  Dev HTTP Gateway (TLS DISABLED — plaintext) listening on http://{}",
            dev_bind
        );
        println!("   Set NEXUS_TLS_CERT and NEXUS_TLS_KEY to enable real HTTPS/TLS.");
        let acceptor = TcpListener::new(dev_bind).bind().await;
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 80: HTTP redirect to HTTPS + ACME challenges
    async fn serve_http(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .get(redirect_to_https)
            .push(Router::with_path("<**rest>").get(redirect_to_https));

        let acceptor = TcpListener::new("0.0.0.0:8080").bind().await;
        println!("✅ HTTP Redirect listening on 0.0.0.0:8080 (dev: using 8080 instead of 80)");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 5432 (configurable): PostgreSQL v3 Wire Protocol TCP listener (`psql`, `pg`, Prisma, Drizzle).
    /// Binds loopback (`127.0.0.1`) by default, handles `SSLRequest`, enforces `AuthenticationCleartextPassword`
    /// backed by `nexus-db` RBAC, and uses streaming length-prefixed TCP framing.
    #[cfg(feature = "db-pgwire")]
    async fn serve_pgwire(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nexus_db::pgwire::{PgWireSession, StartupPacket};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let bind_host =
            std::env::var("NEXUS_PGWIRE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let is_loopback_bind = matches!(bind_host.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !is_loopback_bind {
            return Err(format!(
                "Refusing plaintext PgWire bind on non-loopback host '{}': remote wire-protocol access requires TLS",
                bind_host
            )
            .into());
        }
        let addr = format!("{}:{}", bind_host, self.config.pgwire_port);
        let trust_local_env = std::env::var("NEXUS_PGWIRE_TRUST_LOCAL").as_deref() == Ok("1");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!(
            "🐘 PostgreSQL v3 Wire Protocol (PgWire) listening on {} (auth: {})",
            addr,
            if trust_local_env { "trust-loopback-only" } else { "password-required" }
        );

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            let trust_local = trust_local_env && peer_addr.ip().is_loopback();
            let db = self.db.clone();
            tokio::spawn(async move {
                let mut stream_buf: Vec<u8> = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];

                // 1. Read & parse PG v3 startup packet (handling optional SSLRequest first)
                let (ns, database, user) = loop {
                    match PgWireSession::parse_startup_packet(&stream_buf) {
                        Ok(Some((consumed, StartupPacket::SslRequest))) => {
                            stream_buf.drain(..consumed);
                            if socket.write_all(b"N").await.is_err() {
                                return;
                            }
                        }
                        Ok(Some((consumed, StartupPacket::Startup { user, database, ns, .. }))) => {
                            stream_buf.drain(..consumed);
                            break (ns, database, user);
                        }
                        Ok(None) => {
                            let Ok(n) = socket.read(&mut chunk).await else { return; };
                            if n == 0 {
                                return;
                            }
                            stream_buf.extend_from_slice(&chunk[..n]);
                        }
                        Err(_) => return,
                    }
                };

                let mut pg = if trust_local {
                    PgWireSession::new(db.inner.clone(), ns, database)
                } else {
                    PgWireSession::new_authenticated(db.inner.clone(), ns, database, user)
                };

                if socket.write_all(&pg.startup_response()).await.is_err() {
                    return;
                }

                // 2. Streaming length-prefixed PG v3 message loop (handles fragmented & coalesced TCP reads)
                loop {
                    loop {
                        match PgWireSession::extract_next_frame(&mut stream_buf) {
                            Ok(Some(frame)) => {
                                let is_terminate = frame.first() == Some(&b'X');
                                match pg.handle_frame(&frame) {
                                    Ok(reply) => {
                                        if !reply.is_empty() && socket.write_all(&reply).await.is_err() {
                                            return;
                                        }
                                        if is_terminate {
                                            return;
                                        }
                                    }
                                    Err(_) => return,
                                }
                            }
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }

                    let Ok(n) = socket.read(&mut chunk).await else { return; };
                    if n == 0 {
                        return;
                    }
                    stream_buf.extend_from_slice(&chunk[..n]);
                }
            });
        }
    }

    /// Port 3306 (configurable): MySQL v10 Wire Protocol TCP listener (`mysql`, MySQL2, Prisma, Drizzle).
    /// Binds loopback (`127.0.0.1`) by default, requires `HandshakeResponse41` auth backed by `nexus-db` RBAC,
    /// and uses streaming 4-byte MySQL packet framing.
    #[cfg(feature = "db-mysqlwire")]
    async fn serve_mysqlwire(&self) -> Result<(), Box<dyn std::error::Error>> {
        use nexus_db::mysqlwire::MySqlWireSession;
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        static CONN_ID: AtomicU32 = AtomicU32::new(1);
        let bind_host =
            std::env::var("NEXUS_MYSQLWIRE_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let is_loopback_bind = matches!(bind_host.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !is_loopback_bind {
            return Err(format!(
                "Refusing plaintext MySqlWire bind on non-loopback host '{}': remote wire-protocol access requires TLS",
                bind_host
            )
            .into());
        }
        let addr = format!("{}:{}", bind_host, self.config.mysqlwire_port);
        let trust_local_env = std::env::var("NEXUS_MYSQLWIRE_TRUST_LOCAL").as_deref() == Ok("1");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!(
            "🐬 MySQL v10 Wire Protocol (MySqlWire) listening on {} (auth: {})",
            addr,
            if trust_local_env { "trust-loopback-only" } else { "password-required" }
        );

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            let trust_local = trust_local_env && peer_addr.ip().is_loopback();
            let db = self.db.clone();
            let cid = CONN_ID.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut my = if trust_local {
                    MySqlWireSession::new(db.inner.clone(), "nexus", "system")
                } else {
                    MySqlWireSession::new_authenticated(db.inner.clone(), "nexus", "system", cid)
                };
                if socket.write_all(&my.handshake_greeting()).await.is_err() {
                    return;
                }

                let mut stream_buf: Vec<u8> = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];
                let mut handshake_done = false;

                loop {
                    loop {
                        match MySqlWireSession::extract_next_packet(&mut stream_buf) {
                            Ok(Some((seq, payload))) => {
                                if !handshake_done {
                                    handshake_done = true;
                                    match my.handle_handshake_response(seq, &payload) {
                                        Ok(resp) => {
                                            if socket.write_all(&resp).await.is_err() || !my.authenticated {
                                                return;
                                            }
                                        }
                                        Err(_) => return,
                                    }
                                } else {
                                    match my.handle_command(seq, &payload) {
                                        Ok((close, resp)) => {
                                            if !resp.is_empty() && socket.write_all(&resp).await.is_err() {
                                                return;
                                            }
                                            if close {
                                                return;
                                            }
                                        }
                                        Err(_) => return,
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }

                    let Ok(n) = socket.read(&mut chunk).await else { return; };
                    if n == 0 {
                        return;
                    }
                    stream_buf.extend_from_slice(&chunk[..n]);
                }
            });
        }
    }

    /// Port 8000: Direct SurrealDB access (optional)
    async fn serve_surreal_direct(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .push(Router::with_path("/rpc").post(surreal_rpc_handler));

        let acceptor = TcpListener::new("0.0.0.0:8000").bind().await;
        println!("✅ SurrealDB Direct Access listening on 0.0.0.0:8000");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 3900: Direct S3 API access (optional)
    async fn serve_s3_direct(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .push(Router::with_path("<**path>")
                .get(s3_get_handler)
                .put(s3_put_handler)
                .delete(s3_delete_handler)
            );

        let acceptor = TcpListener::new("0.0.0.0:3900").bind().await;
        println!("✅ S3 Direct Access listening on 0.0.0.0:3900");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Port 9090: Prometheus metrics (optional)
    async fn serve_metrics(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = Router::new()
            .get(metrics_handler);

        let acceptor = TcpListener::new("127.0.0.1:9090").bind().await;
        println!("✅ Metrics listening on 127.0.0.1:9090");
        
        Server::new(acceptor).serve(router).await;

        Ok(())
    }

    /// Build the main application router.
    /// Every storage-dependent route (`/rpc`, `/sql`, `/export`, `/import`, `/key/*`, `/api/*`,
    /// `/query`, `/cells/*`, `/s3/*`, `/graphql`, `/v2/pipeline`) is guarded by
    /// `BootRecoveryGateMiddleware` (`503` until `reconcile_storage_on_boot()` succeeds).
    fn build_main_router(&self) -> Router {
        let gate = BootRecoveryGateMiddleware {
            storage_ready: self.storage_ready.clone(),
        };
        let router = Router::new()
            // WebSocket & HTTP JSON-RPC / CBOR Signal Hub (SurrealDB SDK wire protocol)
            .push({
                let db = self.db.clone();
                let ws_handler = WebSocketHandler { db: db.clone() };
                let http_rpc = crate::ux::surreal_http::SurrealHttpRpcHandler { db: db.clone() };
                let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                Router::with_path("/rpc")
                    .hoop(gate.clone())
                    .hoop(iam)
                    .get(ws_handler)
                    .post(http_rpc)
            })
            // SurrealDB-compatible HTTP REST API (/sql, /signin, /signup, /export, /import, /key, /api)
            .push(
                Router::with_path("/sql")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::SurrealSqlHandler { db: self.db.clone() }),
            )
            .push(Router::with_path("/signin").post(crate::ux::surreal_http::SurrealAuthHandler { db: self.db.clone(), is_signup: false }))
            .push(Router::with_path("/signup").post(crate::ux::surreal_http::SurrealAuthHandler { db: self.db.clone(), is_signup: true }))
            .push(
                Router::with_path("/export")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: false })
                    .post(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: false }),
            )
            .push(
                Router::with_path("/import")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                    .post(crate::ux::surreal_http::SurrealExportImportHandler { db: self.db.clone(), is_import: true }),
            )
            .push(
                Router::with_path("/key/{table}")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .post(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .delete(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() }),
            )
            .push(
                Router::with_path("/key/{table}/{id}")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .put(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .patch(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() })
                    .delete(crate::ux::surreal_http::SurrealKeyHandler { db: self.db.clone() }),
            )
            .push(
                Router::with_path("/api/{ns}/{db}/{**path}")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                    .post(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                    .put(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() })
                    .delete(crate::ux::surreal_http::SurrealCustomApiHandler { db: self.db.clone() }),
            )
            // Public liveness (/status, /health), storage-aware readiness (/ready), version, metrics
            .push(Router::with_path("/status").get(crate::ux::surreal_http::surreal_status))
            .push(Router::with_path("/ready").get(ReadinessHandler {
                storage_ready: self.storage_ready.clone(),
            }))
            .push(Router::with_path("/version").get(crate::ux::surreal_http::surreal_version))
            .push(Router::with_path("/_nexus/metrics").get(serve_metrics))
            // Unified External Multi-Flavor Query API (`POST /query`, `POST /cells/:app/:cell_id/query`)
            .push(
                Router::with_path("/query")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::UnifiedQueryHandler {
                        db: self.db.clone(),
                        cells: self.cells.clone(),
                        default_flavor: "surql",
                    }),
            )
            .push(
                Router::with_path("/cells/{app}/{cell_id}/query")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(crate::ux::surreal_http::UnifiedQueryHandler {
                        db: self.db.clone(),
                        cells: self.cells.clone(),
                        default_flavor: "surql",
                    }),
            )
            // Privileged Multi-node WAL replication transport (Admin tier)
            .push(
                Router::with_path("/_nexus/wal/entries")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                    .get(crate::ux::surreal_http::WalReplicationHandler { db: self.db.clone(), is_apply: false }),
            )
            .push(
                Router::with_path("/_nexus/wal/apply")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::admin(self.db.clone()))
                    .post(crate::ux::surreal_http::WalReplicationHandler { db: self.db.clone(), is_apply: true }),
            );

        #[cfg(feature = "db-graphql")]
        let router = router.push(
            Router::with_path("/graphql")
                .hoop(gate.clone())
                .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                .post(crate::ux::surreal_http::UnifiedQueryHandler {
                    db: self.db.clone(),
                    cells: self.cells.clone(),
                    default_flavor: "graphql",
                }),
        );

        #[cfg(feature = "db-sqlite")]
        let router = router.push(
            Router::with_path("/v2/pipeline")
                .hoop(gate.clone())
                .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                .post(crate::ux::surreal_http::SqliteHranaHandler { db: self.db.clone() }),
        );

        #[cfg(feature = "serve-web")]
        let web_handler = WebStaticHandler::from_config(&self.config);
        #[cfg(feature = "serve-web")]
        let dist_handler = DistStaticHandler::from_config(&self.config);

        #[cfg(feature = "serve-web")]
        let router = router
            .push(Router::with_path("/dist/{**path}").get(dist_handler))
            .push(Router::with_path("/web/{**path}").get(web_handler.clone()));

        #[cfg(feature = "serve-proxy")]
        let router = router.push(
            Router::with_path("/proxy/{upstream}/{**path}")
                .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                .get(crate::ux::reverse_proxy::ReverseProxyHandler::from_env())
                .post(crate::ux::reverse_proxy::ReverseProxyHandler::from_env())
                .put(crate::ux::reverse_proxy::ReverseProxyHandler::from_env())
                .delete(crate::ux::reverse_proxy::ReverseProxyHandler::from_env()),
        );

        #[cfg(feature = "runtime-wasm")]
        let router = router
            .push(
                Router::with_path("/_nexus/deploy")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .post(DeploySubmitHandler {
                        cells: self.cells.clone(),
                        garage: self.garage.clone(),
                    }),
            )
            .push(
                Router::with_path("/_nexus/deploy/{operation_id}")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(DeployOperationHandler {
                        garage: self.garage.clone(),
                    }),
            )
            .push(
                Router::with_path("/_nexus/apps/{app_id}")
                    .hoop(gate.clone())
                    .hoop(crate::ux::iam::IamMiddleware::authenticated(self.db.clone()))
                    .get(DeployedAppHandler {
                        garage: self.garage.clone(),
                    }),
            );

        let router = router
            
            // S3 Proxy (browser-friendly)
            .push({
                let db = self.db.clone();
                let garage = self.garage.clone();
                let s3_handler = S3ProxyHandler { garage };
                let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                Router::with_path("/s3/{**path}")
                    .hoop(gate.clone())
                    .hoop(iam)
                    .get(s3_handler.clone())
                    .put(s3_handler.clone())
                    .delete(s3_handler.clone())
                    .head(s3_handler)
            })
            
            // Unified Cell Ingress (/cells/<app>/<cell_id> & POST /cells/deploy-md)
            .push({
                let db = self.db.clone();
                let cell_handler = CellGatewayHandler {
                    db: db.clone(),
                    cells: self.cells.clone(),
                };
                let iam = crate::ux::iam::IamMiddleware::authenticated(db);
                Router::with_path("/cells/{**path}")
                    .hoop(gate)
                    .hoop(iam)
                    .get(cell_handler.clone())
                    .post(cell_handler.clone())
                    .put(cell_handler.clone())
                    .delete(cell_handler)
            })
            
            // Health check (liveness) & runtime capability diagnostics
            .push(Router::with_path("/health").get(health_check))
            .push(Router::with_path("/_nexus/capabilities").get(capabilities_handler));

        // Mount web application root & SPA fallback LAST so API, RPC, cell, S3, and probe routes
        // always take precedence and missing assets return genuine 404s.
        #[cfg(feature = "serve-web")]
        let router = router
            .push(Router::with_path("/").get(web_handler.clone()))
            .push(Router::with_path("/{**path}").get(web_handler));

        #[cfg(not(feature = "serve-web"))]
        let router = router.push(Router::with_path("/").get(serve_static));

        router
    }

    /// Expose the configured Salvo router for programmatic embedding and integration tests.
    ///
    /// **Embedder contract:** Storage-dependent routes fail closed (`503 Service Unavailable`)
    /// and `/ready` reports `503` until the embedder explicitly invokes
    /// `self.reconcile_storage_on_boot().await?`.
    pub fn router(&self) -> Router {
        self.build_main_router()
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct DeploySubmitHandler {
    cells: Arc<CellManager>,
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for DeploySubmitHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        use crate::compute::manifest::{AppManifest, ManifestReconciler};
        use crate::iam::capabilities::{Capability, CapabilitySet};

        let auth = crate::ux::iam::depot_auth_context(depot);
        let caller_caps = CapabilitySet::from_auth_context(auth.as_ref());
        if !caller_caps.has(Capability::CellSpawn) {
            crate::observability::global_metrics().inc_iam_auth_denial();
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(serde_json::json!({
                "error": "Missing required capability `cell.spawn` for /_nexus/deploy"
            })));
            return;
        }

        let Ok(raw_body) = req.payload_with_max_size(1024 * 1024).await else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "Failed to read manifest body" })));
            return;
        };
        let Ok(body_str) = std::str::from_utf8(raw_body) else {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(serde_json::json!({ "error": "Manifest body must be valid UTF-8" })));
            return;
        };

        let trimmed = body_str.trim();
        let parsed = if trimmed.starts_with('{') {
            AppManifest::from_json(trimmed)
        } else {
            AppManifest::from_toml(trimmed)
        };
        let manifest = match parsed {
            Ok(m) => m,
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
                return;
            }
        };
        let validated = match manifest.validate() {
            Ok(v) => v,
            Err(e) => {
                res.status_code(StatusCode::UNPROCESSABLE_ENTITY);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
                return;
            }
        };

        match ManifestReconciler::apply(
            &self.cells,
            &self.garage,
            &validated,
            &CapabilitySet::admin_all(),
            auth.as_ref(),
        )
        .await
        {
            Ok(op) => {
                res.status_code(StatusCode::ACCEPTED);
                res.render(Json(op));
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct DeployOperationHandler {
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for DeployOperationHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let op_id = req.param::<String>("operation_id").unwrap_or_default();
        match crate::compute::manifest::ManifestReconciler::get_operation(&self.garage, &op_id).await
        {
            Ok(Some(op)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(op));
            }
            Ok(None) => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(serde_json::json!({ "error": "Deployment operation not found" })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "runtime-wasm")]
#[derive(Clone)]
struct DeployedAppHandler {
    garage: Arc<BlobBridge>,
}

#[cfg(feature = "runtime-wasm")]
#[async_trait]
impl Handler for DeployedAppHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let app_id = req.param::<String>("app_id").unwrap_or_default();
        match crate::compute::manifest::ManifestReconciler::get_app(&self.garage, &app_id).await {
            Ok(Some(rec)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(rec));
            }
            Ok(None) => {
                res.status_code(StatusCode::NOT_FOUND);
                res.render(Json(serde_json::json!({ "error": "Application deployment not found" })));
            }
            Err(e) => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                res.render(Json(serde_json::json!({ "error": e.to_string() })));
            }
        }
    }
}

#[cfg(feature = "serve-web")]
fn resolve_asset_root(
    explicit: Option<&std::path::PathBuf>,
    subdir: &str,
) -> Option<std::path::PathBuf> {
    // 1. Explicitly configured path (`GatewayConfig` / `NEXUS_WEB_ROOT` / `NEXUS_DIST_ROOT`)
    if let Some(p) = explicit {
        if p.is_dir() {
            return Some(p.clone());
        }
        // Explicit path configured but missing — do NOT silently fall through to an unrelated directory.
        return None;
    }

    // 2. Path relative to executable directory (packaged / deployed binary layout)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let candidate = exe_dir.join(subdir);
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }

    // 3. Development-only repository-relative fallback (never active in release builds)
    #[cfg(debug_assertions)]
    {
        for rel in [
            std::path::PathBuf::from(subdir),
            std::path::PathBuf::from("..").join(subdir),
        ] {
            if rel.is_dir() {
                return Some(rel);
            }
        }
    }

    None
}

#[cfg(feature = "serve-web")]
fn safe_join_within(
    root: &std::path::Path,
    rel_path: &str,
) -> Result<std::path::PathBuf, StatusCode> {
    let trimmed = rel_path.trim_start_matches('/');
    if trimmed.contains('\0') || trimmed.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut joined = root.to_path_buf();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains(':') {
            return Err(StatusCode::BAD_REQUEST);
        }
        joined.push(seg);
    }
    Ok(joined)
}

#[cfg(feature = "serve-web")]
fn mime_for_path(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") | Some("cjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") | Some("map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("md") | Some("markdown") => "text/markdown; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}

#[cfg(feature = "serve-web")]
fn is_reserved_non_spa_prefix(rel_path: &str) -> bool {
    let normalized = format!("/{}", rel_path.trim_start_matches('/'));
    const RESERVED: &[&str] = &[
        "/api/",
        "/dist/",
        "/rpc",
        "/sql",
        "/cells/",
        "/s3/",
        "/_nexus/",
        "/key/",
        "/graphql",
        "/v2/",
        "/proxy/",
        "/signin",
        "/signup",
        "/export",
        "/import",
        "/query",
        "/health",
        "/ready",
        "/status",
        "/version",
    ];
    RESERVED.iter().any(|prefix| {
        normalized == *prefix || normalized.starts_with(prefix)
    })
}

#[cfg(feature = "serve-web")]
fn accepts_html(req: &Request) -> bool {
    match req
        .headers()
        .get(salvo::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    {
        Some(accept) => accept.contains("text/html") || accept.contains("*/*"),
        None => true,
    }
}

#[cfg(feature = "serve-web")]
fn apply_isolation_headers(
    res: &mut Response,
    coop: Option<&str>,
    coep: Option<&str>,
) {
    if let Some(val) = coop {
        if let Ok(hv) = salvo::http::header::HeaderValue::from_str(val) {
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("cross-origin-opener-policy"),
                hv,
            );
        }
    }
    if let Some(val) = coep {
        if let Ok(hv) = salvo::http::header::HeaderValue::from_str(val) {
            res.headers_mut().insert(
                salvo::http::header::HeaderName::from_static("cross-origin-embedder-policy"),
                hv,
            );
        }
    }
}

#[cfg(feature = "serve-web")]
#[derive(Clone)]
struct DistStaticHandler {
    dist_root: Option<std::path::PathBuf>,
    coep_header: Option<String>,
}

#[cfg(feature = "serve-web")]
impl DistStaticHandler {
    fn from_config(config: &GatewayConfig) -> Self {
        Self {
            dist_root: resolve_asset_root(config.dist_root.as_ref(), "dist"),
            coep_header: config.coep_header.clone(),
        }
    }
}

#[cfg(feature = "serve-web")]
#[async_trait]
impl Handler for DistStaticHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let Some(root) = &self.dist_root else {
            res.status_code(StatusCode::NOT_FOUND);
            return;
        };
        let rel = req.param::<String>("path").unwrap_or_default();
        let target = match safe_join_within(root, &rel) {
            Ok(p) => p,
            Err(code) => {
                res.status_code(code);
                return;
            }
        };
        if !target.is_file() {
            res.status_code(StatusCode::NOT_FOUND);
            return;
        }
        match tokio::fs::read(&target).await {
            Ok(bytes) => {
                let ct = mime_for_path(&target);
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_TYPE,
                    salvo::http::HeaderValue::from_static(ct),
                );
                res.headers_mut().insert(
                    salvo::http::header::CACHE_CONTROL,
                    salvo::http::HeaderValue::from_static("public, max-age=300"),
                );
                res.headers_mut().insert(
                    salvo::http::header::HeaderName::from_static("cross-origin-resource-policy"),
                    salvo::http::HeaderValue::from_static("same-origin"),
                );
                // Chromium requires dedicated Web Worker scripts (e.g. logic.worker.js) to carry
                // matching COEP when the parent document is cross-origin isolated.
                if ct.starts_with("application/javascript") {
                    apply_isolation_headers(res, None, self.coep_header.as_deref());
                }
                res.body(bytes);
            }
            Err(_) => {
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
    }
}

#[cfg(feature = "serve-web")]
#[derive(Clone)]
struct WebStaticHandler {
    web_root: Option<std::path::PathBuf>,
    coop_header: Option<String>,
    coep_header: Option<String>,
}

#[cfg(feature = "serve-web")]
impl WebStaticHandler {
    fn from_config(config: &GatewayConfig) -> Self {
        Self {
            web_root: resolve_asset_root(config.web_root.as_ref(), "site"),
            coop_header: config.coop_header.clone(),
            coep_header: config.coep_header.clone(),
        }
    }
}

#[cfg(feature = "serve-web")]
#[async_trait]
impl Handler for WebStaticHandler {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let rel = req
            .param::<String>("path")
            .unwrap_or_else(|| req.uri().path().trim_start_matches('/').to_string());

        let Some(root) = &self.web_root else {
            if rel.is_empty() && accepts_html(req) {
                render_bundle_unavailable(res);
            } else {
                res.status_code(StatusCode::NOT_FOUND);
            }
            return;
        };

        let candidate = match safe_join_within(root, &rel) {
            Ok(p) => p,
            Err(code) => {
                res.status_code(code);
                return;
            }
        };

        // 1. Direct file match (or directory index.html for root)
        let exact_target = if rel.is_empty() {
            let idx = root.join("index.html");
            if idx.is_file() { Some(idx) } else { None }
        } else if candidate.is_file() {
            Some(candidate)
        } else {
            None
        };

        let (target, is_spa_fallback) = if let Some(file) = exact_target {
            (file, false)
        } else {
            // 2. Strict SPA fallback: ONLY for HTML navigation requests with no file extension
            //    and outside reserved API / RPC / dist / asset prefixes.
            let has_ext = std::path::Path::new(&rel).extension().is_some();
            if !has_ext && !is_reserved_non_spa_prefix(&rel) && accepts_html(req) {
                let idx = root.join("index.html");
                if idx.is_file() {
                    (idx, true)
                } else {
                    if rel.is_empty() {
                        render_bundle_unavailable(res);
                    } else {
                        res.status_code(StatusCode::NOT_FOUND);
                    }
                    return;
                }
            } else {
                res.status_code(StatusCode::NOT_FOUND);
                return;
            }
        };

        match tokio::fs::read(&target).await {
            Ok(bytes) => {
                let ct = mime_for_path(&target);
                let is_html = ct.starts_with("text/html");
                res.headers_mut().insert(
                    salvo::http::header::CONTENT_TYPE,
                    salvo::http::HeaderValue::from_static(ct),
                );
                res.headers_mut().insert(
                    salvo::http::header::CACHE_CONTROL,
                    salvo::http::HeaderValue::from_static(if is_html || is_spa_fallback {
                        "no-cache"
                    } else {
                        "public, max-age=300"
                    }),
                );
                if is_html {
                    apply_isolation_headers(
                        res,
                        self.coop_header.as_deref(),
                        self.coep_header.as_deref(),
                    );
                }
                res.body(bytes);
            }
            Err(_) => {
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
    }
}

fn render_bundle_unavailable(res: &mut Response) {
    res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    res.render(Text::Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nexus-IO Gateway — Application Bundle Unavailable</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 720px; margin: 60px auto; padding: 0 20px; line-height: 1.6; color: #1f2937; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #fef3c7; color: #92400e; font-weight: 600; font-size: 0.85em; }
  </style>
</head>
<body>
  <h1>Nexus-IO Gateway</h1>
  <p><span class="badge">Application Bundle Unavailable</span></p>
  <p>The Nexus-IO kernel gateway is online, but no frontend application bundle (<code>index.html</code>) was found at the configured web root.</p>
  <p>Configure <code>NEXUS_WEB_ROOT</code> (and optionally <code>NEXUS_DIST_ROOT</code>) to serve a Nexus-UX application, or query <code>/health</code>, <code>/ready</code>, <code>/rpc</code>, <code>/cells/*</code>, and <code>/s3/*</code> directly.</p>
</body>
</html>"#,
    ));
}

#[handler]
async fn serve_metrics(res: &mut Response) {
    res.render(Json(crate::observability::global_metrics().snapshot()));
}

#[handler]
async fn capabilities_handler(res: &mut Response) {
    let reg = crate::runtime::CapabilityRegistry::new();
    reg.set_state("database", crate::runtime::CapabilityState::Active, Some("nexus-db".into()));
    reg.set_state("gateway", crate::runtime::CapabilityState::Active, Some("salvo".into()));
    reg.set_state("cells", crate::runtime::CapabilityState::Active, Some("wasmtime".into()));
    res.render(Json(reg.snapshot_json()));
}

// ============================================================================
// Route Handlers
// ============================================================================

#[cfg(not(feature = "serve-web"))]
#[handler]
async fn serve_static(res: &mut Response) {
    render_bundle_unavailable(res);
}

#[handler]
async fn health_check(res: &mut Response) {
    res.render(Json(serde_json::json!({
        "status": "ok",
        "service": "nexus-io-gateway",
        "version": env!("CARGO_PKG_VERSION"),
    })));
}

#[handler]
async fn redirect_to_https(req: &mut Request, res: &mut Response) {
    let host = req.header::<String>("host").unwrap_or_else(|| "localhost".to_string());
    let path = req.uri().path();
    let target = format!("https://{}{}", host, path);
    
    res.status_code(StatusCode::MOVED_PERMANENTLY);
    res.add_header("Location", target, true).ok();
}

// Optional port handlers (stubs for now)

#[handler]
async fn surreal_rpc_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct SurrealDB RPC not yet implemented"));
}

#[handler]
async fn s3_get_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct S3 GET not yet implemented"));
}

#[handler]
async fn s3_put_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct S3 PUT not yet implemented"));
}

#[handler]
async fn s3_delete_handler(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Text::Plain("Direct S3 DELETE not yet implemented"));
}

#[handler]
async fn metrics_handler(res: &mut Response) {
    // TODO: Integrate with prometheus crate
    res.render(Text::Plain("# Nexus-IO Metrics\n# TODO: Implement Prometheus integration"));
}
