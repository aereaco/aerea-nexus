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
