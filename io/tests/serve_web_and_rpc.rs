#![cfg(feature = "serve-web")]

use nexus_io::db::Database;
use nexus_io::storage::BlobBridge;
use nexus_io::ux::{GatewayConfig, UxGateway};
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use salvo::Service;
use std::path::PathBuf;
use std::sync::Arc;

fn repo_site_and_dist() -> (PathBuf, PathBuf) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().expect("io/ parent is aerea-nexus root");
    (root.join("site"), root.join("dist"))
}

#[tokio::test]
async fn serve_web_serves_real_site_dist_spa_fallback_404_and_isolation_headers() {
    let (site_dir, dist_dir) = repo_site_and_dist();
    assert!(site_dir.join("index.html").is_file(), "site/index.html must exist");
    assert!(dist_dir.join("nexus-ux.js").is_file(), "dist/nexus-ux.js must exist");

    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let config = GatewayConfig {
        web_root: Some(site_dir.clone()),
        dist_root: Some(dist_dir.clone()),
        coop_header: Some("same-origin".to_string()),
        coep_header: Some("credentialless".to_string()),
        ..GatewayConfig::default()
    };
    let gw = UxGateway::new(db.clone(), blobs.clone(), config);
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // 1. Root HTML + COOP/COEP headers
    let mut root_res = TestClient::get("http://127.0.0.1/")
        .add_header("accept", "text/html", true)
        .send(&service)
        .await;
    assert_eq!(root_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        root_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        root_res
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|v| v.to_str().ok()),
        Some("same-origin")
    );
    assert_eq!(
        root_res
            .headers()
            .get("cross-origin-embedder-policy")
            .and_then(|v| v.to_str().ok()),
        Some("credentialless")
    );
    let root_body = root_res.take_string().await.unwrap();
    assert!(root_body.contains("app-layout"), "expected real site/index.html");

    // 2. Real dist bundle (/dist/nexus-ux.js) + matching COEP for dedicated Web Workers
    let dist_res = TestClient::get("http://127.0.0.1/dist/nexus-ux.js")
        .send(&service)
        .await;
    assert_eq!(dist_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        dist_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/javascript; charset=utf-8")
    );
    assert_eq!(
        dist_res
            .headers()
            .get("cross-origin-embedder-policy")
            .and_then(|v| v.to_str().ok()),
        Some("credentialless")
    );

    // 3. Real site JSON & SVG assets with proper MIME types
    let manifest_res = TestClient::get("http://127.0.0.1/_pages/manifest.json")
        .send(&service)
        .await;
    assert_eq!(manifest_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        manifest_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json; charset=utf-8")
    );

    let svg_res = TestClient::get("http://127.0.0.1/_assets/images/emblem.svg")
        .send(&service)
        .await;
    assert_eq!(svg_res.status_code, Some(StatusCode::OK));
    assert_eq!(
        svg_res.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("image/svg+xml")
    );

    // 4. SPA HTML navigation fallback for nested route
    let mut spa_res = TestClient::get("http://127.0.0.1/labs/attributes/signal")
        .add_header("accept", "text/html", true)
        .send(&service)
        .await;
    assert_eq!(spa_res.status_code, Some(StatusCode::OK));
    let spa_body = spa_res.take_string().await.unwrap();
    assert!(spa_body.contains("app-layout"));

    // 5. Genuine 404 for missing static assets and unknown non-HTML API routes
    let missing_js = TestClient::get("http://127.0.0.1/missing.js")
        .send(&service)
        .await;
    assert_eq!(missing_js.status_code, Some(StatusCode::NOT_FOUND));

    let missing_dist = TestClient::get("http://127.0.0.1/dist/does-not-exist.js")
        .send(&service)
        .await;
    assert_eq!(missing_dist.status_code, Some(StatusCode::NOT_FOUND));

    let missing_api = TestClient::get("http://127.0.0.1/api/unknown-endpoint")
        .add_header("accept", "application/json", true)
        .send(&service)
        .await;
    assert_eq!(missing_api.status_code, Some(StatusCode::NOT_FOUND));

    // 6. Path traversal rejection (400 Bad Request)
    let traversal = TestClient::get("http://127.0.0.1/web/..%2FCargo.toml")
        .send(&service)
        .await;
    assert!(
        traversal.status_code == Some(StatusCode::BAD_REQUEST)
            || traversal.status_code == Some(StatusCode::NOT_FOUND),
        "traversal must be rejected, got {:?}",
        traversal.status_code
    );

    // 7. Liveness (/health) and readiness (/ready) remain unaffected
    let health = TestClient::get("http://127.0.0.1/health").send(&service).await;
    assert_eq!(health.status_code, Some(StatusCode::OK));
    let ready = TestClient::get("http://127.0.0.1/ready").send(&service).await;
    assert_eq!(ready.status_code, Some(StatusCode::OK));
}

#[tokio::test]
async fn serve_web_respects_disabled_coop_coep_and_reports_unavailable_bundle() {
    let (site_dir, dist_dir) = repo_site_and_dist();
    let db = Arc::new(Database::open_mem());
    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());

    // 1. Disabled COOP/COEP headers
    let no_iso_cfg = GatewayConfig {
        web_root: Some(site_dir),
        dist_root: Some(dist_dir),
        coop_header: None,
        coep_header: None,
        ..GatewayConfig::default()
    };
    let gw = UxGateway::new(db.clone(), blobs.clone(), no_iso_cfg);
    let service = Service::new(gw.router());
    let res = TestClient::get("http://127.0.0.1/")
        .add_header("accept", "text/html", true)
        .send(&service)
        .await;
    assert_eq!(res.status_code, Some(StatusCode::OK));
    assert!(res.headers().get("cross-origin-opener-policy").is_none());
    assert!(res.headers().get("cross-origin-embedder-policy").is_none());

    // 2. Explicit missing web_root returns 503 bundle unavailable page (never silently falls back)
    let missing_cfg = GatewayConfig {
        web_root: Some(PathBuf::from("nonexistent_nexus_bundle_dir_12345")),
        dist_root: None,
        ..GatewayConfig::default()
    };
    let gw2 = UxGateway::new(db, blobs, missing_cfg);
    let service2 = Service::new(gw2.router());
    let mut unavail = TestClient::get("http://127.0.0.1/")
        .add_header("accept", "text/html", true)
        .send(&service2)
        .await;
    assert_eq!(unavail.status_code, Some(StatusCode::SERVICE_UNAVAILABLE));
    let body = unavail.take_string().await.unwrap();
    assert!(body.contains("Application Bundle Unavailable"));
}

#[tokio::test]
async fn rpc_session_matches_sql_sprite_positional_json_rpc_and_live_lifecycle() {
    let db = Arc::new(Database::open_mem());
    let mut session = db.inner.rpc_session("erp", "main");

    // 1. Positional `use` -> ["erp", "main"]
    let use_reply: serde_json::Value =
        serde_json::from_str(&session.handle_json(r#"{"id":"1","method":"use","params":["erp","main"]}"#))
            .unwrap();
    assert!(use_reply.get("error").is_none(), "use failed: {:?}", use_reply);

    // 2. Subscribe via positional `live` -> ["task"]
    let live_reply: serde_json::Value =
        serde_json::from_str(&session.handle_json(r#"{"id":"2","method":"live","params":["task"]}"#))
            .unwrap();
    assert!(live_reply.get("error").is_none(), "live failed: {:?}", live_reply);
    let live_id = live_reply["result"].as_str().expect("live returns uuid string").to_string();

    // 3. Mutate via positional `query` -> [sql, vars]
    let create_reply: serde_json::Value = serde_json::from_str(&session.handle_json(
        r#"{"id":"3","method":"query","params":["CREATE task:1 SET title = $title, done = false;",{"title":"Verify RPC"}]}"#,
    ))
    .unwrap();
    assert!(create_reply.get("error").is_none(), "create failed: {:?}", create_reply);

    // 4. Drain LIVE notifications -> SurrealDB v2 push frame { result: { id, action, result } }
    let frames = session.drain_live_notifications();
    assert!(!frames.is_empty(), "expected CREATE live notification");
    let pushed: serde_json::Value = serde_json::from_str(&frames[0]).unwrap();
    assert_eq!(pushed["result"]["id"].as_str(), Some(live_id.as_str()));
    assert_eq!(pushed["result"]["action"].as_str(), Some("CREATE"));
    assert_eq!(pushed["result"]["result"]["title"].as_str(), Some("Verify RPC"));

    // 5. Kill subscription via positional `kill` -> [live_id]
    let kill_req = serde_json::json!({ "id": "4", "method": "kill", "params": [live_id] });
    let kill_reply: serde_json::Value =
        serde_json::from_str(&session.handle_json(&kill_req.to_string())).unwrap();
    assert!(kill_reply.get("error").is_none(), "kill failed: {:?}", kill_reply);

    // 6. Further mutations after `kill` produce zero notifications
    let _ = session.handle_json(
        r#"{"id":"5","method":"query","params":["CREATE task:2 SET title = 'After kill';",{}]}"#,
    );
    assert!(session.drain_live_notifications().is_empty());
}

#[tokio::test]
async fn iam_session_cookie_auth_me_and_server_rbac_enforcement() {
    // Ensure local unauth bypass is OFF so real IAM enforcement is exercised
    std::env::remove_var("NEXUS_ALLOW_UNAUTH_LOCAL");

    let db = Arc::new(Database::open_mem());
    // Seed two real Nexus-DB users with distinct RBAC roles
    db.inner
        .query_scoped_multi(
            "nexus",
            "system",
            "DEFINE USER director ON DATABASE PASSWORD 'director-pass' ROLES OWNER;
             DEFINE USER auditor ON DATABASE PASSWORD 'auditor-pass' ROLES VIEWER;
             CREATE erp_po:po_088 SET title = 'PO #2026-Q3-088', status = 'Pending Review', amount = '$14,250.00';",
            vec![],
        )
        .expect("seed users and PO");

    let blobs = Arc::new(BlobBridge::new(db.clone()).await.unwrap());
    let gw = UxGateway::new(db.clone(), blobs, GatewayConfig::default());
    gw.reconcile_storage_on_boot().await.unwrap();
    let service = Service::new(gw.router());

    // 1. Anonymous GET /_nexus/auth/me reports unauthenticated
    let mut anon_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .send(&service)
        .await;
    assert_eq!(anon_me.status_code, Some(StatusCode::OK));
    let anon_json: serde_json::Value = serde_json::from_str(&anon_me.take_string().await.unwrap()).unwrap();
    assert_eq!(anon_json["authenticated"], false);
    assert!(anon_json["roles"].as_array().unwrap().is_empty());

    // 2. Anonymous POST /sql is rejected with 401 Unauthorized
    let anon_sql = TestClient::post("http://127.0.0.1/sql")
        .body("SELECT * FROM erp_po;")
        .send(&service)
        .await;
    assert_eq!(anon_sql.status_code, Some(StatusCode::UNAUTHORIZED));

    // 3. Sign in as VIEWER (`auditor`) -> sets HttpOnly nexus_session cookie
    let viewer_signin = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "auditor", "pass": "auditor-pass", "ns": "nexus", "db": "system" }))
        .send(&service)
        .await;
    assert_eq!(viewer_signin.status_code, Some(StatusCode::OK));
    let set_cookie = viewer_signin
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header must be present")
        .to_string();
    assert!(set_cookie.contains("nexus_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let viewer_cookie = set_cookie.split(';').next().unwrap().to_string();

    // 4. GET /_nexus/auth/me with VIEWER cookie returns verified identity + read-only capabilities
    let mut viewer_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .add_header("cookie", &viewer_cookie, true)
        .send(&service)
        .await;
    assert_eq!(viewer_me.status_code, Some(StatusCode::OK));
    let viewer_json: serde_json::Value = serde_json::from_str(&viewer_me.take_string().await.unwrap()).unwrap();
    assert_eq!(viewer_json["authenticated"], true);
    assert_eq!(viewer_json["actor"], "auditor");
    assert_eq!(viewer_json["roles"], serde_json::json!(["VIEWER"]));
    let viewer_caps = viewer_json["capabilities"].as_array().unwrap();
    assert!(viewer_caps.contains(&serde_json::json!("db.read")));
    assert!(!viewer_caps.contains(&serde_json::json!("db.write")));

    // 5. VIEWER can SELECT via cookie, but server REJECTS mutating UPDATE
    let mut viewer_read = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &viewer_cookie, true)
        .body("SELECT * FROM erp_po;")
        .send(&service)
        .await;
    assert_eq!(viewer_read.status_code, Some(StatusCode::OK));
    let read_body = viewer_read.take_string().await.unwrap();
    assert!(read_body.contains("PO #2026-Q3-088"));

    let mut viewer_write = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &viewer_cookie, true)
        .body("UPDATE erp_po:po_088 SET status = 'Approved';")
        .send(&service)
        .await;
    let write_status = viewer_write.status_code;
    let write_body = viewer_write.take_string().await.unwrap();
    assert!(
        write_status == Some(StatusCode::BAD_REQUEST)
            || write_status == Some(StatusCode::FORBIDDEN)
            || write_body.contains("\"status\":\"ERR\""),
        "VIEWER write must be rejected by server RBAC, got {:?}: {}",
        write_status,
        write_body
    );

    // 6. Sign in as OWNER (`director`) -> can mutate erp_po:po_088
    let owner_signin = TestClient::post("http://127.0.0.1/signin")
        .json(&serde_json::json!({ "user": "director", "pass": "director-pass", "ns": "nexus", "db": "system" }))
        .send(&service)
        .await;
    assert_eq!(owner_signin.status_code, Some(StatusCode::OK));
    let owner_cookie = owner_signin
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let mut owner_me = TestClient::get("http://127.0.0.1/_nexus/auth/me")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    let owner_json: serde_json::Value = serde_json::from_str(&owner_me.take_string().await.unwrap()).unwrap();
    assert_eq!(owner_json["authenticated"], true);
    assert_eq!(owner_json["actor"], "director");
    assert_eq!(owner_json["roles"], serde_json::json!(["OWNER"]));
    assert!(owner_json["capabilities"].as_array().unwrap().contains(&serde_json::json!("db.write")));

    let mut owner_write = TestClient::post("http://127.0.0.1/sql")
        .add_header("cookie", &owner_cookie, true)
        .body("UPDATE erp_po:po_088 SET status = 'Approved', approved_by = 'director';")
        .send(&service)
        .await;
    assert_eq!(owner_write.status_code, Some(StatusCode::OK));
    let owner_write_body = owner_write.take_string().await.unwrap();
    assert!(owner_write_body.contains("Approved"), "expected Approved in {}", owner_write_body);

    // 7. POST /signout clears the cookie
    let signout = TestClient::post("http://127.0.0.1/signout")
        .add_header("cookie", &owner_cookie, true)
        .send(&service)
        .await;
    assert_eq!(signout.status_code, Some(StatusCode::OK));
    let clear_hdr = signout.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(clear_hdr.contains("nexus_session=;"));
    assert!(clear_hdr.contains("Max-Age=0"));
}
