# Nexus-IO Deployment Profiles & Empirical Footprint Benchmarks

This document records empirical measurements across Nexus-IO's configurable deployment profiles, OS target profiles, and optional native GUI flag.

## 1. Architecture Summary

- **Single platform, zero unnecessary runtime overhead:** `surrealdb 4.0.1` has been removed from all default and production builds in favor of the clean-room, MIT-licensed `crates/nexus-db` embedded multi-model engine (`redb` + `BTreeMap`).
- **Opt-in differential oracle:** `surrealdb 4.0.1` remains available strictly behind `--features surrealdb-ref` / `profile-dev` to run the automated differential conformance test suite (`db::state_engine::differential_tests`).
- **Compile-time modularity + lazy runtime activation:** `CapabilityRegistry` (`GET /_nexus/capabilities`) distinguishes `not_compiled`, `compiled`, `configured`, `initialized`, `active`, and `suspended` states. Subsystems such as the WireGuard VPN mesh (`NEXUS_ENABLE_MESH=1`) and native GUI remain dormant unless explicitly activated.
- **Device-native GUI (`--features gui`):** Uses `wry` + `tao` on desktop (`WebView2` on Windows, `WKWebView` on macOS, `WebKitGTK` on Linux) and OS-native WebView host bridges on mobile (`Android System WebView`, iOS `WKWebView`), avoiding Electron or bundled third-party browsers.

---

## 2. Workload Deployment Profiles

| Profile | Cargo Command | Resolved Crate Count | Unit Tests (`--lib`) | Highlights |
| :--- | :--- | ---: | :--- | :--- |
| **`profile-core`** *(default)* | `cargo build` | **1,107** | 13 passed (0.28s) | Embedded `nexus-db`, Salvo HTTP/WS gateway, QuickJS + OXC TS, Cells, IAM. No Wasmtime, K8s YAML, VPN, NVML, GUI, or SurrealDB. |
| **`profile-app`** | `cargo build --no-default-features --features profile-app` | **1,107** | 13 passed | Adds `nexus-db` FTS (BM25), HNSW vector search, Files/Buckets, Auth, and CBOR wire codec with zero external crate bloat. |
| **`profile-full`** | `cargo build --no-default-features --features profile-full` | **1,187** | 15 passed (0.18s) | Adds Wasmtime 51 Crystal cells, K8s YAML bridge (`serde_norway`), WireGuard VPN (`boringtun` / `wintun`), NVML GPU telemetry, and `nexus-db/full` (Geo, Crypto, GraphQL, ML, ISO GQL, PgWire). |
| **`profile-dev`** | `cargo build --no-default-features --features profile-dev` | **1,406** | Differential suite | Adds opt-in `surrealdb-ref` (SurrealDB 4.0.1) strictly for automated differential conformance testing (**+219 transitive crates** and multi-GB `rustc` memory/disk footprint kept out of production). |

---

## 3. OS Target Profiles & Optional Native `gui` Flag

Measured on Windows x86_64 host via `cargo tree --no-default-features --features <profile> --prefix none | sort -u`:

| Profile / Flag | Resolved Crate Count (Windows host) | Native Web Rendering Engine (`--features gui`) | Notes |
| :--- | ---: | :--- | :--- |
| **`profile-windows`** | **1,186** | `WebView2` (Windows Native) | `Wintun` WireGuard + NVML + Cranelift Wasm |
| **`profile-linux`** | **1,187** | `WebKitGTK` (Linux Native) | Linux `TUN` WireGuard + K8s bridge + NVML + Cranelift Wasm |
| **`profile-macos`** | **1,177** | `WKWebView` (Apple Native) | macOS `utun` WireGuard + Cranelift Wasm (no NVML) |
| **`profile-android`** | **1,161** *(smaller on `aarch64-linux-android`)* | `Android System WebView` | Excludes desktop CLI (`nu-cli`/`rustyline`), NVML, and desktop TUN drivers via `cfg(target_os)` |
| **`profile-ios`** | **1,161** *(smaller on `aarch64-apple-ios`)* | `WKWebView` (Apple Native) | **Apple `W^X` compliant:** `wasmtime` compiled in `runtime`-only mode (AOT `.cwasm`, no Cranelift JIT) |
| **`profile-windows,gui`** | **1,209** *(+23 crates)* | `WebView2` via `wry` + `tao` | 14 passed (0.22s); zero bundled Chromium/Electron overhead |

---

## 4. Runtime Observability (`GET /_nexus/capabilities`)

Every running Nexus-IO gateway exposes its active profile, OS target, resolved native WebView engine, and live capability lifecycle map at `GET /_nexus/capabilities`:

```json
{
  "profile": "profile-core",
  "os_profile": "profile-windows",
  "target_os": "windows",
  "native_webview_engine": "WebView2 (Windows Native)",
  "capabilities": [
    { "name": "database", "state": "active", "detail": "nexus-db (redb)" },
    { "name": "gui", "state": "compiled", "detail": "WebView2 (Windows Native)" },
    { "name": "vpn", "state": "not_compiled", "detail": null }
  ]
}
```
