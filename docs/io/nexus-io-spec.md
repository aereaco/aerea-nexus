# Nexus-IO Specification (v2026.11.24)

**The Universal System Runtime: Single-Process Shared-Memory Infrastructure with Native Cross-Platform Parity & `celld` Compatibility**

> "The best infrastructure is invisible. The best runtime feels inevitable."

---

## Table of Contents

1. [Running Changelog](#1-running-changelog)
2. [Vision & Core Architectural Thesis](#2-vision--core-architectural-thesis)
3. [Foundational Design Rules](#3-foundational-design-rules)
4. [System Architecture: The Unified Kernel](#4-system-architecture-the-unified-kernel)
   - [4.1. Data Plane: SurrealDB 4.0 & `BlobBridge` (`s3s` + `iroh-blobs`)](#41-data-plane-surrealdb-40--blobbridge-s3s--iroh-blobs)
   - [4.2. Logic Plane: Nushell, OXC & QuickJS-NG (Tiered Execution)](#42-logic-plane-nushell-oxc--quickjs-ng-tiered-execution)
   - [4.3. Presentation & Ingress Plane: Salvo & Nexus-UX](#43-presentation--ingress-plane-salvo--nexus-ux)
   - [4.4. Security Fabric: `GuardedCommand` IAM Kernel](#44-security-fabric-guardedcommand-iam-kernel)
   - [4.5. Zero-Trust Mesh: `boringtun`, `wintun` & `iroh` QUIC](#45-zero-trust-mesh-boringtun-wintun--iroh-quic)
5. [Unified Policy Model (`pinned` vs `elastic`) & `celld` Compatibility](#5-unified-policy-model-pinned-vs-elastic--celld-compatibility)
   - [5.1. Why One Unified Policy Model Beats Both Pure `celld` and a Two-Tier Split](#51-why-one-unified-policy-model-beats-both-pure-celld-and-a-two-tier-split)
   - [5.2. Cell Lifecycle, CAS Leases & Hibernation](#52-cell-lifecycle-cas-leases--hibernation)
   - [5.3. Dual Storage Surface (`ctx.storage.sql` + `ctx.storage.surreal`)](#53-dual-storage-surface-ctxstoragesql--ctxstoragesurreal)
6. [Distributed Compute Layer: The AI-Native Mesh](#6-distributed-compute-layer-the-ai-native-mesh)
7. [First-Class Native Cross-Platform Parity (Windows, Linux, macOS, Android, iOS)](#7-first-class-native-cross-platform-parity-windows-linux-macos-android-ios)
8. [Future Horizon: Semantic OS (`.md` Runtime) & Vertical Applications](#8-future-horizon-semantic-os-md-runtime--vertical-applications)
9. [Living Roadmap & Active TODO List](#9-living-roadmap--active-todo-list)

---

## 1. Running Changelog

### `v2026.11.24` — Stage 1 Verified on Native Windows, Garage Purged, Spec Unified
* **Stage 1 Completed & Verified (`814054e`):**
  * Compiled and tested natively on Windows (`x86_64-pc-windows-msvc`) via `cargo test --bin nexus -j 2` (`2 passed; 0 failed`).
  * Upgraded upstream dependencies in [Cargo.toml](file:///c:/Users/verno/Development/nexus-io/Cargo.toml): `surrealdb` `4.0.1`, `salvo` `1.1.1` (resolved `1.2.1`), `nu-*` `0.117.0`, `rusqlite` `0.41.1`, `boringtun` `0.7.1`, `wintun-bindings` `0.7.6` (resolved `0.7.40`), `s3s` `0.17.0`, `iroh` `1.0.3` (resolved `1.4.1`), `iroh-blobs` `0.104.1`.
* **Complete Removal of Garage Naming & Files:**
  * Purged all `garage_*` crates, `garage_bridge.rs`, `garage_bridge.rs.backup`, `garage_config.rs`, and `GarageBridge` references—greenfield codebase with zero legacy shims.
  * Replaced with [blob_bridge.rs](file:///c:/Users/verno/Development/nexus-io/src/storage/blob_bridge.rs) (`BlobBridge`), [storage_config.rs](file:///c:/Users/verno/Development/nexus-io/src/storage/storage_config.rs), `impl s3s::S3 for BlobBridge`, `iroh::Endpoint` + `BlobsProtocol`, `select_hrw_replicas` (`blake3` HRW placement), `repair_once` / `spawn_repair_loop`, and S3 CAS (`If-Match` / `If-None-Match: *`) wired into [s3_proxy.rs](file:///c:/Users/verno/Development/nexus-io/src/ux/s3_proxy.rs).
* **Empirical Windows & SurrealDB 4.0 Learnings Baked Into Spec:**
  * Added `DEFINE TABLE IF NOT EXISTS` initialization in `BlobBridge::new` for SurrealDB 4.0 strict empty-table query behavior.
  * Added [.cargo/config.toml](file:///c:/Users/verno/Development/nexus-io/.cargo/config.toml) (`/STACK:8388608`), `[profile.dev] debug = 0`, and `[profile.dev.package.surrealdb-core] opt-level = 1` to match Linux's 8MB stack, prevent SurrealDB 4.0 unoptimized async stack overflows on Windows, and keep dev `target/` disk usage lean.
  * Replaced hardcoded `/tmp` paths in `src/db/mod.rs` and `src/shell/host.rs` with `std::env::temp_dir()`.
  * Consolidated `nu-protocol` `0.117.0` `ShellError::Generic` construction into `crate::shell_err` in [src/main.rs](file:///c:/Users/verno/Development/nexus-io/src/main.rs).
* **Pure-Rust JS Baseline (`quickrs-core` `0.16.2`), Native TS (`oxc` `0.144.0`) & Pluggable Non-iOS JIT:**
  * Replaced `quickjs-rusty` + `libquickjs-ng-sys` (eliminating `bindgen` / `libclang` on Windows and mobile) with **`quickrs-core` (`0.16.2`)** after head-to-head benchmarking against `boa_engine` (`0.22.0`, no default features) on native Windows: **6 vs. 158 transitive crates**, **4.1x faster JSON parse/stringify**, **1.25x faster numeric loops**, `#![no_std]` + `alloc` capable, and 100% iOS `W^X` compliant.
  * Native TypeScript execution across all 5 platforms via in-process **`oxc` (`0.144.0`)** type-stripping/transpilation.
  * Designed the JS runtime behind a pluggable `JsEngine` boundary so non-iOS targets (`#[cfg(not(target_os = "ios"))]`) can opt into a JIT/Wasmtime backend while iOS uses `quickrs-core` + AOT + `WKWebView`/JSC.
* **Native Mobile Requirement (Android & iOS) & `StateEngine` Boundary:**
  * Added first-class native **Android (`aarch64-linux-android`)** and **iOS (`aarch64-apple-ios`)** architecture: `src/lib.rs` core library + `uniffi` FFI (`cdylib`/`staticlib`), `WKWebView`/`WebView` hosting Nexus-UX, `QuickJS-NG` (iOS `W^X` JIT-free compliance), `NEPacketTunnelProvider`/`VpnService` → `boringtun::noise::Tunn`, explicit app-sandbox `data_dir`, target-gated desktop crates (`nvml-wrapper`, `nu-cli`, `rustyline`, subprocess `cc`), and aggressive `elastic` hibernation for mobile memory limits.
  * Added internal `StateEngine` trait boundary in `src/db/` to isolate `surrealdb::*` (BSL 1.1) so Nexus-IO can cleanly swap to an Apache-2.0 KV-backed custom multi-model engine later if offering hosted third-party PaaS schemas.

### `v2026.11.18` — Cross-Platform Pivot, `celld` Policy Model & Compute Mesh Refinement
* **Native Windows Parity Decision:** Dropped Unix-only Deuxfleurs Garage (`std::os::unix` / `nix::sys::statvfs`) in favor of `s3s` + `iroh` + `iroh-blobs` + HRW Rendezvous Hashing + anti-entropy repair, paired with `wintun-bindings` on Windows.
* **Unified Policy Model (`pinned` vs `elastic`):** Collapsed the initial two-tier hybrid concept into a single SurrealDB + QuickJS + `BlobBridge` kernel governed by per-`(Namespace, Database)` lifecycle policy—adding `celld` / Cloudflare Durable Objects compatibility (`ctx.storage.sql` via `sqlparser` AST + `ctx.storage.surreal`) without introducing a second database engine or sync bridge.
* **Section 2.6 Compute Mesh Alignment:** Unified Layer 1 (`Lunatic`) into `CellManager`, aligned Layer 2 (`DataFusion` → `Ballista`) to scan `s3s`/`iroh-blobs` (solving `celld` cross-cell analytics), paired Layer 3 (`InferMesh`) with `elastic` AI agents and `pinned` `sys::gpu` telemetry, and targeted `wgpu` + CUDA/ROCm in Layer 4 (`CubeCL`).
* **Scope Discipline:** Explicitly sequenced infrastructure lockdown (Stages 1–3) ahead of `.md` `SystemNode` runtime and parked Tier B AOT (`porffor` / `inkwell`) until core workloads warrant native AOT acceleration.

### `v2026.02.04` — Initial Baseline Specification
* Established the original Three-Plane Kernel vision (SurrealDB + Nushell + QuickJS + Garage + WireGuard + Nexus-UX), `GuardedCommand` IAM, SD-Storage, AI-powered content revocation, and Phases 6–23 platform roadmap.

---

## 2. Vision & Core Architectural Thesis

### The Problem: The Cloud Glue Tax
Modern cloud applications are forced to stitch together 6+ separately metered networked services—Postgres, Redis, S3, Node/Python containers, API Gateways, VPNs, and Kubernetes. Every boundary adds TCP round-trips, JSON/gRPC serialization overhead (50–200ms end-to-end), fragmented IAM, and operational fragility.

### The Nexus-IO Solution
Nexus-IO collapses the entire backend into a **single, sovereign, cross-platform Rust binary** sharing one memory address space:

```text
Multi-Model DB (SurrealDB)
+ Object/Blob Mesh (s3s + iroh-blobs)
+ Structured Shell & JS/TS Logic (Nushell + OXC + QuickJS-NG)
+ Zero-Trust Mesh (boringtun + wintun + iroh QUIC)
+ HTTP/QUIC/WS Gateway (Salvo + Nexus-UX)
= Single Shared-Memory Process
```

### Why Single-Process Shared Memory Works Now
Historically, co-locating user logic, database storage, and networking inside one address space was unsafe in C/C++ (one memory bug crashed the database) or unpredictable in GC-heavy runtimes. **Rust + lightweight sandboxes (QuickJS-NG / Wasm)** changes the equation: Rust enforces memory safety across kernel subsystems at native speed with zero GC pauses, while isolated JS/Wasm contexts and capability-based IAM (`GuardedCommand`) fence off application code inside the same process.

---

## 3. Foundational Design Rules

1. **Zero-Copy, Zero-Serialization (ZCZS):** Pass direct Rust handles, `bytes::Bytes`, and typed values across internal boundaries. Eliminate `serde_json::Value` round-trips between SurrealDB, Nushell, QuickJS, and `BlobBridge`.
2. **All Upstream, Zero Forks:** Never fork SurrealDB, Nushell, QuickJS-NG, OXC, `iroh`, `s3s`, or Salvo. Nexus-IO stays a lean integration kernel that inherits upstream performance and security improvements automatically.
3. **First-Class Native Cross-Platform Parity:** Windows (`x86_64-pc-windows-msvc`), Linux, macOS, **Android (`aarch64-linux-android`)**, and **iOS (`aarch64-apple-ios`)** are equal native targets. No Unix-only crate dependencies, no WSL workarounds, and no JIT-only runtimes that violate iOS `W^X` restrictions.
4. **Greenfield Cleanliness:** Never carry dead legacy names or compatibility shims for replaced components (e.g., Garage was removed completely, not aliased).
5. **Vertical-Slice Discipline:** Lock down the core infrastructure and `celld`-compatible runtime (Stages 1–3) before layering on the `.md` `SystemNode` execution surface, Tier B AOT (`porffor`/`inkwell`), or vertical SaaS suites.

---

## 4. System Architecture: The Unified Kernel

```text
┌──────────────────────────────────────────────────────────────────┐
│  PRESENTATION & INGRESS PLANE (Salvo 1.2 + Nexus-UX)             │
│  HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSockets, S3 Gateway, ACME   │
└──────────────────────────────┬───────────────────────────────────┘
                               │ Shared Memory (Zero-Copy)
┌──────────────────────────────▼───────────────────────────────────┐
│  LOGIC & ACTOR PLANE (Nushell 0.117 + OXC + QuickJS-NG)          │
│  CellManager (pinned & elastic), GuardedCommand IAM, sqlparser   │
└──────────────────────────────┬───────────────────────────────────┘
                               │ Shared Memory (Zero-Copy)
┌──────────────────────────────▼───────────────────────────────────┐
│  DATA & MESH PLANE                                               │
│  SurrealDB 4.0 (SurrealKv/Mem) + BlobBridge (s3s + iroh-blobs)   │
│  WireGuard (boringtun + wintun) + iroh QUIC P2P Mesh             │
└──────────────────────────────────────────────────────────────────┘
```

### 4.1. Data Plane: SurrealDB 4.0 & `BlobBridge` (`s3s` + `iroh-blobs`)

#### SurrealDB `4.0.1` (`kv-mem`, `kv-surrealkv`)
SurrealDB is the **single source of truth** for both structured application data and cluster control-plane metadata:
* **Multi-Model:** Relational tables, nested documents, native graph edges (`RELATE`), key-value, and real-time `LIVE SELECT` streams.
* **Native Multi-Tenancy:** Every application or `celld` actor maps to an isolated `(Namespace, Database)` pair.
* **Control-Plane Tables (`nexus::system`):**
  * `sys::node` — active cluster peers (`NodeId`, endpoint, status, capabilities)
  * `sys::bucket` — S3 bucket registry
  * `sys::object` — object metadata (`bucket`, `key`, `blake3`, `etag`, `size`, `deleted`)
  * `sys::gpu` — live GPU/VRAM telemetry from `nvml-wrapper` + `sysinfo`
  * `user`, `role`, `sys::storage`, `sys::file` — IAM & host projections
* **SurrealDB 4.0 Contract:** Storage/control-plane modules self-initialize tables via `DEFINE TABLE IF NOT EXISTS` before querying, ensuring clean behavior on fresh databases.
* **`StateEngine` Abstraction Boundary (BSL 1.1 Future-Proofing):** Keep `surrealdb::*` types isolated inside `src/db/` behind an internal `StateEngine` trait (`query`, `scoped_session(ns, db)`, `live_subscribe`, `snapshot_export` / `snapshot_import`). While SurrealDB BSL 1.1 permits commercial embedded apps/SaaS, isolating it preserves a clean future swap path to an Apache-2.0 KV-backed custom multi-model engine (e.g., on `SurrealKV`, `redb`, or `fjall`) for hosted third-party PaaS workloads or reduced binary size.

#### `BlobBridge` (`s3s` `0.17.0` + `iroh` `1.4.1` + `iroh-blobs` `0.104.1`)
Implemented in [src/storage/blob_bridge.rs](file:///c:/Users/verno/Development/nexus-io/src/storage/blob_bridge.rs), `BlobBridge` replaces Unix-only Garage while preserving all three distributed object-storage guarantees natively on Windows, Linux, and macOS:

1. **Turnkey S3-to-Cluster Wiring (`impl s3s::S3 for BlobBridge`):**
   * Implements `CreateBucket`, `ListBuckets`, `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, and `ListObjectsV2`.
   * Enforces **S3 Compare-And-Swap (`If-Match` / `If-None-Match: *`)** via `put_object_cas`, returning `412 Precondition Failed` (`CasConflictError`) on ETag mismatch and strong `blake3` ETags on success.
   * Exposed over HTTP via Salvo in [src/ux/s3_proxy.rs](file:///c:/Users/verno/Development/nexus-io/src/ux/s3_proxy.rs) and directly usable in-process via zero-copy `bytes::Bytes`.
2. **Automatic Placement (HRW Rendezvous Hashing):**
   * `select_hrw_replicas(object_key, peers, n)` uses `blake3` to deterministically rank active `sys::node` peers for every `(bucket, key)` or `cell_id`—achieving balanced `N`-way placement with zero consensus cluster (no Raft/etcd).
3. **Background Anti-Entropy Repair & P2P Streaming (`iroh-blobs`):**
   * Every node binds an `iroh::Endpoint` (`presets::N0`) running `BlobsProtocol` (`iroh_blobs::ALPN`) with built-in QUIC NAT traversal and relay fallback.
   * `spawn_repair_loop` / `repair_once` periodically verifies that every `sys::object` assigned to the local node by HRW exists in the local `FsStore`; missing or rebalanced blobs are pulled and BLAKE3-verified from peers via `store.remote().fetch(conn, hash)`.

---

### 4.2. Logic Plane: Nushell, OXC & `quickrs-core` (Tiered Execution)

* **Nushell (`0.117.0`):** Embedded structured-data shell (`nu-engine`, `nu-protocol`, `nu-command`, `nu-parser`; `nu-cli` gated to desktop/server) powering CLI commands, pipelines, and administrative automation. Unified error construction via `crate::shell_err` (`ShellError::Generic`).
* **Tier S — Native TypeScript (`oxc_*` `0.144.0`):** In-process TypeScript/JSX/ESM parsing and transpilation in pure Rust across all 5 platforms with zero Node.js dependency.
* **Tier A — Universal Pure-Rust JS Baseline (`quickrs-core` `0.16.2`):** Pure-Rust QuickJS-NG reimplementation (only 6 transitive crates, `#![no_std]`-capable, ES2023+ classes/`Proxy`/`Uint8Array`/`SharedArrayBuffer`/`async`+`await`, zero C/`libclang`, 100% iOS `W^X` compliant).
* **Tier A+ — Optional Non-iOS JIT / Crystal Tier (`wasmtime`):** AOT Wasm on iOS and JIT/AOT Wasm on desktop/server/Android behind `CellManager` for native-speed compute hot paths, while `WKWebView`/JSC handles UI JS on iOS.

---

### 4.3. Presentation & Ingress Plane: Salvo & Nexus-UX

* **Salvo (`1.1.1` / `1.2.1`):** Single ingress gateway ([src/ux/gateway.rs](file:///c:/Users/verno/Development/nexus-io/src/ux/gateway.rs)) handling HTTP/1.1, HTTP/2, HTTP/3 (QUIC), ACME TLS, SurrealDB WebSocket RPC (`/rpc`), S3 object requests (`/s3/*`), and `celld` cell HTTP/WebSocket routing (including WebSocket hibernation).
* **Nexus-UX:** HTML-declarative-first reactive frontend mirroring live SurrealDB queries directly into fine-grained reactive DOM signals.

---

### 4.4. Security Fabric: `GuardedCommand` IAM Kernel

* Implemented in [src/iam/kernel.rs](file:///c:/Users/verno/Development/nexus-io/src/iam/kernel.rs).
* Every privileged command and cell capability validates against SurrealDB ABAC policies before execution—preventing privilege escalation inside the shared-memory process.
* `elastic` cells run in isolated QuickJS contexts pinned to their own `(Namespace, Database)` with explicit capability grants.

---

### 4.5. Zero-Trust Mesh: `boringtun`, `wintun` & `iroh` QUIC

* **L3 WireGuard Mesh (`boringtun` `0.7.1`):**
  * Core WireGuard cryptography compiles cross-platform across Windows, Linux, and macOS (using `x25519-dalek 2.0.1`, cleanly aligned with `surrealdb 4.0.1`).
  * `#[cfg(unix)]` enables `boringtun`'s `device` TUN backend; `#[cfg(windows)]` pairs `boringtun` with **`wintun-bindings` (`0.7.40`)** in [src/storage/wireguard.rs](file:///c:/Users/verno/Development/nexus-io/src/storage/wireguard.rs) for native Windows L3 TUN parity.
* **P2P QUIC Transport (`iroh` `1.4.1`):** Handles NAT-traversing blob sync (`iroh-blobs`) and remote cell request forwarding even when nodes sit behind residential/corporate NATs.

---

## 5. Unified Policy Model (`pinned` vs `elastic`) & `celld` Compatibility

### 5.1. Why One Unified Policy Model Beats Both Pure `celld` and a Two-Tier Split
* **Why not pure `celld`?** Sharding *everything* into isolated, hibernating SQLite actors destroys always-hot shared-memory access, cross-entity SurrealQL graph traversals (`RELATE`), and global live **Nexus-UX** queries.
* **Why not a Two-Tier split?** Maintaining two separate database engines (SQLite + SurrealDB) or two runtimes requires a custom sync/projection bridge and doubles maintenance surface.
* **The Nexus-IO Unified Policy Model:** Every SurrealDB `(Namespace, Database)` runs on the **exact same** SurrealDB + QuickJS + `BlobBridge` kernel, differing only by lifecycle policy:

| Policy | Intended Workloads | Runtime & Storage Behavior |
| :--- | :--- | :--- |
| **`pinned`** *(Default)* | `nexus::system`, IAM, shared catalogs, `sys::gpu`, global Nexus-UX dashboards | Always hot in `SurrealKv` shared memory. Zero CAS lease hops, zero hibernation, sub-millisecond global relational/graph/live queries. |
| **`elastic`** *(`celld` Mode)* | Per-user workspaces, AI agent sessions, chat/multiplayer rooms, Cloudflare Durable Object ports (`app::cell_<id>`) | Single-writer CAS lease via `BlobBridge` (`If-Match` / `If-None-Match`); remote requests forwarded over `iroh`/WireGuard; idle cells flush snapshot to `iroh-blobs` and evict from hot RAM, rehydrating on wake. |

Because both policies share one kernel, an `elastic` cell can read `pinned` shared scopes directly in-process—no dual-database sync bridge required.

### 5.2. Cell Lifecycle, CAS Leases & Hibernation
* **`CellManager` Actor Pool:** Replaces the single-thread `JsClient` in [src/js/mod.rs](file:///c:/Users/verno/Development/nexus-io/src/js/mod.rs) with a concurrent actor pool keyed by `(app, cell_id)`.
* **Durable Objects / `celld` Contract:** Implements `fetch(request)`, `alarm()`, `webSocketMessage()`, `webSocketClose()`, and `blockConcurrencyWhile()`, plus WinterCG globals (`Request`, `Response`, `Headers`, `WebSocketPair`).
* **Request Routing Pipeline in Salvo:**
  1. Resolve target `(ns, db)` and policy (`pinned` vs `elastic`).
  2. If `pinned` → execute directly in shared memory.
  3. If `elastic` → check local lease → if owned by another node, forward over `iroh`/WireGuard; if hibernated, acquire CAS lease via `BlobBridge::put_object_cas` (`If-None-Match: *` / `If-Match`), hydrate snapshot from `iroh-blobs`, execute, and reset idle hibernation timer.

### 5.3. Dual Storage Surface (`ctx.storage.sql` + `ctx.storage.surreal`)
* **Scoped `(NS, DB)` Sessions:** Each cell owns a dedicated `Surreal` session pinned to its `(Namespace, Database)`, eliminating the shared `use_ns`/`use_db` race.
* **ZCZS Value Mapping:** Map `surrealdb::Value` directly to/from QuickJS `JSValue` without `serde_json::Value` round-trips.
* **Drop-In SQLite Compatibility (`ctx.storage.sql`):**
  * `ctx.storage.sql.exec(sql, ...bindings)` is parsed into a real AST using **`sqlparser` (`0.64+`, `SQLiteDialect`)**—never regex heuristics—and compiled to SurrealQL against the cell's `(NS, DB)`.
  * `ctx.storage` KV (`get`, `put`, `delete`, `list`, `transaction`) maps to a reserved KV table in the same `(NS, DB)`.
* **Native SurrealQL Upgrade Path (`ctx.storage.surreal`):**
  * Exposed alongside `ctx.storage.sql` on the exact same cell data, allowing apps ported from Cloudflare Durable Objects or `celld` to immediately adopt SurrealQL graph relations (`RELATE`), `LIVE SELECT` queries, and vector search without migrating databases.

---

## 6. Distributed Compute Layer: The AI-Native Mesh

With `celld` compatibility and cross-platform `BlobBridge` in place, the 4-layer compute mesh becomes cohesive and cross-platform:

```text
Layer 4: CubeCL (Cross-Platform GPU Kernels — WGPU DX12/Vulkan/Metal + CUDA/ROCm)
         ↓
Layer 3: InferMesh (Stateless GPU-Aware Routing + Elastic AI Agent Cells)
         ↓
Layer 2: Cross-Cell Snapshot Analytics (In-Process BlobBridge Hibernated Scans)
         ↓
Layer 1: Unified CellManager + CrystalEngine (quickrs-core Cells + Wasmtime 51.0 AOT/JIT)
```

* **Layer 1 — Unified `CellManager` + `CrystalEngine`:** `quickrs-core` (`oxc` native TS) handles dynamic `pinned`/`elastic` cells, while **`wasmtime` (`51.0.0`) Crystal cells** run polyglot Wasm (`Rust`, `Zig`, `Go`, `C`, `AssemblyScript`, inline `wat`) with fuel metering—AOT-only on iOS and Cranelift JIT/AOT everywhere else.
* **Layer 2 — Cross-Cell Snapshot Analytics (`analytics.rs`):** Scans hibernated `elastic` cell snapshots directly out of `BlobBridge` (`s3s`/`iroh-blobs`) without waking cells—keeping the core binary lean without pulling in big-data OLAP stacks (`DataFusion`/`Ballista`).
* **Layer 3 — `InferMesh` + `elastic` AI Agents:** `nvml-wrapper` (desktop/server) + `sysinfo` project real-time GPU/VRAM availability into a `pinned` `sys::gpu` table; `InferenceRouter` scores by free VRAM + green-node bonus, and `iroh-blobs` distributes model weights.
* **Layer 4 — `CubeCL`:** Targets `wgpu` (DirectX 12 on Windows, Vulkan on Linux, Metal on macOS) alongside CUDA/ROCm so Surface/Windows nodes participate in GPU compute natively.

---

## 7. First-Class Native Cross-Platform Parity (Windows, Linux, macOS, Android, iOS)

### 7.1. Desktop & Server (Windows, Linux, macOS)
Validated empirically on Windows (`AMD64` / `x86_64-pc-windows-msvc`):
* **Required Windows Toolchain:** Rust (`x86_64-pc-windows-msvc`), Visual Studio 2022 Build Tools (`VC.Tools.x86.x64`), `CMake`, and `LLVM` (`LIBCLANG_PATH` for `libquickjs-ng-sys` `bindgen`).
* **Stack & Profile Tuning:**
  * [.cargo/config.toml](file:///c:/Users/verno/Development/nexus-io/.cargo/config.toml): `rustflags = ["-C", "link-arg=/STACK:8388608"]` on `x86_64-pc-windows-msvc` to match Linux's 8MB stack.
  * [Cargo.toml](file:///c:/Users/verno/Development/nexus-io/Cargo.toml): `[profile.dev] debug = 0` (prevents multi-GB `.pdb`/debug bloat on dev disks) and `[profile.dev.package.surrealdb-core] opt-level = 1` (prevents SurrealDB 4.0 unoptimized async stack overflows in debug/test).
* **OS-Agnostic Paths & Networking:** `std::env::temp_dir()` instead of `/tmp`; `wintun-bindings` on `cfg(windows)` and `boringtun` `device` on `cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))`.

### 7.2. Native Mobile (Android & iOS)
Nexus-IO's core stack (`QuickJS-NG`, `oxc`, `SurrealDB` pure-Rust KV, `iroh`/`iroh-blobs`, `s3s`, `salvo`, `boringtun`) is naturally mobile-compatible—unlike V8-based runtimes (`celld`) whose JIT is blocked by Apple's iOS `W^X` security policy:
* **Core Library + FFI Shell:** Split `nexus-io` into a reusable library crate (`src/lib.rs`, compiled as `cdylib` for Android JNI and `staticlib`/XCFramework for iOS Swift via `uniffi`) plus a thin desktop/server CLI binary (`src/main.rs`).
* **UI Presentation:** Host **Nexus-UX** inside native `WKWebView` (iOS) and `WebView` (Android), bound to the embedded localhost `salvo` gateway or direct FFI bridge.
* **Mobile VPN Integration:** Feed OS tunnel packets from iOS **`NEPacketTunnelProvider`** and Android **`VpnService`** directly into `boringtun::noise::Tunn`, while `iroh` handles QUIC connection migration across Wi-Fi ↔ cellular handoffs.
* **Target-Gated Desktop Dependencies:** Gate `nvml-wrapper`, `nu-cli`, `rustyline`, and subprocess `cc` (`--harden`) behind `#[cfg(not(any(target_os = "android", target_os = "ios")))]`.
* **Sandbox Storage & Memory Policy:** Pass the OS-provided writable app-sandbox `data_dir` explicitly into `Database::init(data_dir)` and `BlobBridge::new(db, data_dir)` (no relative `./nexus.db` or `./nexus-blobs`), and default mobile cells to `elastic` with aggressive idle hibernation to respect iOS Jetsam memory limits.

---

## 8. Future Horizon: Semantic OS (`.md` Runtime) & Vertical Applications

Intentionally sequenced **after** Stages 1–3 lock down the core infrastructure:
* **Semantic OS (`.md` → `SystemNode`):** Compile declarative `.md` service files (frontmatter `policy: pinned | elastic`, `yaml`/`json` → `data-signal`, fenced directive blocks → typed `Cell` / `GuardedCommand` / SurrealQL primitives) onto `CellManager` with strict ABAC validation and `emitCrashBeacon()` diagnostics.
* **Flagship Vertical First:** Build one flagship vertical (e.g., **Nexus Locker + Nexus AI** or **Nexus Drive**) on top of the verified kernel rather than attempting 6+ SaaS suites simultaneously.

---

## 9. Living Roadmap & Active TODO List

### Stage 1 — Data, Cross-Platform Storage, Mesh & Gateway ✅ *(Complete — Commit `814054e`)*
- [x] Upgrade `surrealdb` → `4.0.1`, `salvo` → `1.1.1`, `nu-*` → `0.117.0`, `rusqlite` → `0.41.1`, `boringtun` → `0.7.1`
- [x] Remove all Unix-only `garage_*` crates and legacy `GarageBridge` naming
- [x] Implement `BlobBridge` ([blob_bridge.rs](file:///c:/Users/verno/Development/nexus-io/src/storage/blob_bridge.rs)) with `s3s::S3`, `iroh` + `iroh-blobs`, `select_hrw_replicas` (HRW), `repair_once` / `spawn_repair_loop`, and `put_object_cas` (`If-Match` / `If-None-Match: *`)
- [x] Wire `wintun-bindings` (`cfg(windows)`) + `boringtun` `device` (`cfg(unix)`), replace `/tmp` with `std::env::temp_dir()`, and add Windows 8MB stack / dev profile config
- [x] Verify native Windows `cargo test --bin nexus -j 2` (`2 passed; 0 failed`)

### Stage 2 — JS/TS Compiler Upgrade (`oxc_*` + `quickrs-core`) & Library/Mobile Preparation ✅ *(Complete)*
- [x] Replaced `quickjs-rusty` + `libquickjs-ng-sys` with pure-Rust `quickrs-core` (`0.16.2`) — 6 transitive crates, zero C/`libclang`, iOS `W^X` safe
- [x] Upgraded `oxc_allocator`, `oxc_parser`, `oxc_semantic`, `oxc_transformer`, `oxc_codegen`, `oxc_span`, `oxc_ast` from `0.13` → `0.144.0` in [Cargo.toml](file:///c:/Users/verno/Development/nexus-io/Cargo.toml)
- [x] Updated [src/js/transformer.rs](file:///c:/Users/verno/Development/nexus-io/src/js/transformer.rs) and [src/js/mod.rs](file:///c:/Users/verno/Development/nexus-io/src/js/mod.rs) with direct `surreal_to_js` ZCZS conversion
- [x] Extracted [src/lib.rs](file:///c:/Users/verno/Development/nexus-io/src/lib.rs) (`nexus_io`), parameterized explicit `data_dir` (`Database::init_in`, `BlobBridge::new_in`), and target-gated desktop-only crates (`nvml-wrapper`, `nu-cli`, `rustyline`) for Android/iOS readiness
- [x] Verified `cargo test --lib -j 2` (`4 passed; 0 failed`) and `cargo check --tests --bins -j 2` (`0 errors`) on native Windows

### Stage 3 — Unified Policy Model (`pinned` vs `elastic`) & `celld` Compatibility ✅ *(Complete)*
- [x] Added `sqlparser` (`0.64.0`, `SQLiteDialect`) to [Cargo.toml](file:///c:/Users/verno/Development/nexus-io/Cargo.toml)
- [x] Introduced internal `StateEngine` trait ([state_engine.rs](file:///c:/Users/verno/Development/nexus-io/src/db/state_engine.rs)) isolating `surrealdb::*` behind scoped `(NS, DB)` sessions, KV, and snapshot export/import
- [x] Built `CellManager` ([cell.rs](file:///c:/Users/verno/Development/nexus-io/src/js/cell.rs)) with `CellPolicy::Pinned`, `CellPolicy::Elastic`, `CellPolicy::elastic_mobile()`, and idle hibernation
- [x] Implemented `ctx.storage.sql` ([sql_compiler.rs](file:///c:/Users/verno/Development/nexus-io/src/db/sql_compiler.rs) AST → SurrealQL), `ctx.storage` KV, and `ctx.storage.surreal` with ZCZS `surreal_to_js` mapping
- [x] Wired `elastic` CAS leases (`BlobBridge::put_object_cas`) and `iroh-blobs` snapshot hibernation
- [x] Mounted HTTP & WebSocket `/cells/<**path>` ingress ([cell_router.rs](file:///c:/Users/verno/Development/nexus-io/src/ux/cell_router.rs)) in [gateway.rs](file:///c:/Users/verno/Development/nexus-io/src/ux/gateway.rs)
- [x] Verified `cargo test --lib -j 2` (`7 passed; 0 failed`) and `cargo check --tests --bins -j 2` (`0 errors`) on native Windows

### Stage 4 — Compute Mesh & Semantic OS ✅ *(Core Complete)*
- [x] Gated `nvml-wrapper` for mobile parity and added `NodeResources::project_to_state` ([telemetry.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/telemetry.rs)) → `pinned` `sys::gpu` + VRAM/green-aware scoring in `InferenceRouter` ([router.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/router.rs))
- [x] Implemented cross-cell hibernated snapshot analytics ([analytics.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/analytics.rs)) scanning `BlobBridge` snapshots without waking cells
- [x] Implemented Semantic OS `.md` → `SystemNode` declarative runtime ([md_runtime.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/md_runtime.rs)) deploying Markdown frontmatter + `sql`/`surql`/`ts`/`js`/`json` blocks onto `CellManager` + `StateEngine`
- [x] Pinned `BlobBridge::system_db()` to `nexus::system` so concurrent `elastic` cell `(ns, db)` switches never leak into storage metadata
- [x] Implemented `wasmtime` (`51.0.0`) Crystal Cells ([crystal.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/crystal.rs)) — AOT-only `runtime` on iOS, Cranelift JIT/AOT + WAT on non-iOS, with fuel metering
- [x] Wired `deploy_markdown` into `POST /cells/deploy-md` ([cell_router.rs](file:///c:/Users/verno/Development/nexus-io/src/ux/cell_router.rs)) and `cell deploy <path.md>` CLI/Nushell `GuardedCommand` ([md_runtime.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/md_runtime.rs), [main.rs](file:///c:/Users/verno/Development/nexus-io/src/main.rs))
- [x] Added polyglot Wasm (`wat` / `wasm` / `cwasm`) Crystal block support in [md_runtime.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/md_runtime.rs) wired to `CrystalEngine`
- [x] Implemented bidirectional Kubernetes YAML ↔ Nexus `.md` bridge ([k8s_bridge.rs](file:///c:/Users/verno/Development/nexus-io/src/compute/k8s_bridge.rs)) with `k8s import` / `k8s export` CLI commands and `POST /cells/import-k8s` / `POST /cells/export-k8s` HTTP routes (reusing `serde_norway 0.9` with zero new transitive crates)
- [x] Built clean-room, MIT-licensed `nexus-db` ([crates/nexus-db](file:///c:/Users/verno/Development/nexus-io/crates/nexus-db/Cargo.toml)) Synchronous Volcano SurrealQL engine on `redb` + `BTreeMap` with full SurrealDB 3.0/4.0 parity (binary codec, atomic MVCC rollback, `IndexSeek` planner, persisted FTS postings, Graph `RELATE`/`@{min..max}`/shortest path, `SCHEMAFULL`/`UNIQUE`/`COMPUTED`/`READONLY`/`REFERENCE ON DELETE`, `LIVE SELECT`/`KILL`, `CHANGEFEED`/`VERSION`, `DEFINE SEQUENCE`/`API`/`MODULE` Surrealism hook, `ALTER`/`REMOVE`/`OVERWRITE`, modular feature flags `fts`/`vector`/`files`/`auth`/`geo`/`crypto`/`cbor`/`graphql`/`ml`/`gql`/`pgwire`/`full`) and SurrealDB 4.0 differential tests
- [x] Added WinterCG Web Standard globals (`Headers`, `URL`, `URLSearchParams`, `Request`, `Response`, `TextEncoder`/`TextDecoder`, `atob`/`btoa`, `crypto`, `console`, `structuredClone`, `queueMicrotask`) + `Deno.openKv()` bridge in [wintercg.rs](file:///c:/Users/verno/Development/nexus-io/src/js/wintercg.rs) wired to `CellManager` and `CellGatewayHandler`
- [x] Verified `cargo test -p nexus-db -j 2` (`2 passed; 0 failed`), `cargo test --lib -j 2` (`13 passed; 0 failed`), and `cargo check --tests --bins -j 2` (`0 errors`) on native Windows

---

**Document Version:** `v2026.11.24`
**Maintained by:** Aerea Co.
**License:** Proprietary (Specification), Nexus-IO & `nexus-db` Source Code: MIT
