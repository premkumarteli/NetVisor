# Engineering Project Audit: NetVisor

**Date of Audit:** 2026-11-18  
**Audit Scope:** Full repository (Backend, Detection Engines, Ingestion Pipeline, Agent DPI, Gateway, Frontends, Android, Database, Security, Tests).  
**Evidence Grounding:** Real codebase inspection, runtime health checks, and test execution results.

---

## Findings Summary

| ID | Component | Severity | Title | Effort |
| :--- | :--- | :---: | :--- | :---: |
| **AUD-001** | `frontend-v2` | **P1 (High)** | Incomplete Sub-Routes: 6 SOC workflows mapped to PlaceholderPage | **M** |
| **AUD-002** | `Android_Application` | **P1 (High)** | Unwired Navigation Graph: 4 core bottom-nav tabs left as TODO stubs | **S** |
| **AUD-003** | `agent/dpi` | **P1 (High)** | Unwired Header Redaction Pipeline: Intercepted headers dropped | **S** |
| **AUD-004** | `backend/flow_service` | **P1 (High)** | Ingestion Hot Path Bottleneck: Synchronous detection engine serialization | **M** |
| **AUD-005** | `packet_engine` | **P2 (Med)** | QUIC Initial Parser Decryption Absence & TLS Blindspot | **M** |
| **AUD-006** | `collector/` | **P3 (Low)** | Legacy Forwarding Shims & Redundant Module Facades | **S** |
| **AUD-007** | `netvisor_frontend_3.0`| **P3 (Low)** | Stale Prototype Directory & Build Artifact Clutter | **S** |
| **AUD-008** | `backend/api/auth.py` | **P2 (Med)** | Deprecation Warnings for Legacy HS256 Token Fallback | **S** |
| **AUD-009** | `infra/docker` | **P2 (Med)** | Docker Compose Frontend Target Divergence (v1 vs v2) | **S** |
| **AUD-010** | `packet_engine` | **P3 (Low)** | Object Pool Unreferenced on Hot Path Ingestion | **M** |

---

## Detailed Audit Findings

### AUD-001: Incomplete Sub-Routes in Next-Gen Console (`frontend-v2`)
- **Component:** `frontend-v2/src/App.jsx`
- **Severity:** P1 (High)
- **Evidence:** `frontend-v2/src/App.jsx` lines 38-89 explicitly map routes `/agents`, `/apps`, `/threats`, `/activity`, `/vpn`, and `/settings` to `<PlaceholderPage />`.
- **Root Cause:** Next-generation frontend rewrite prioritized 3D WebGL topology visualization and main dashboard layout, leaving the detailed SOC workflows to be ported from `frontend/` (v1).
- **Proposed Fix:** Incrementally port mature workflows from `frontend/src/pages/` into `frontend-v2/` adhering to the Tailwind v4 design system, keeping existing API contracts intact.
- **Dependencies:** `frontend-v2/src/services/api.js`, `lucide-react`, `@tailwindcss/vite`.
- **Verification Criteria:** Routes `/agents`, `/apps`, `/threats`, `/activity`, `/vpn`, `/settings` render interactive data tables, drawers, and action controls; `npm --prefix frontend-v2 run build` succeeds cleanly.
- **Effort:** Medium (M)

---

### AUD-002: Unwired Navigation Graph in Android Application
- **Component:** `Android_Application/app/src/main/java/com/netvisor/mobile/navigation/NavGraph.kt`
- **Severity:** P1 (High)
- **Evidence:** `NavGraph.kt` lines 59-71 contains:
  ```kotlin
  composable("home") { /* TODO: HomeScreen */ }
  composable("network") { /* TODO: NetworkScreen */ }
  composable("threats") { /* TODO: ThreatsScreen */ }
  composable("more") { /* TODO: MoreScreen */ }
  ```
  Meanwhile, all corresponding composables (`HomeScreen.kt`, `NetworkScreen.kt`, `ThreatsScreen.kt`, `MoreScreen.kt`) and their ViewModels exist and are fully implemented in `com.netvisor.mobile.ui.*`.
- **Root Cause:** Navigation graph integration was left incomplete after individual screen UI components were authored.
- **Proposed Fix:** Instantiate appropriate ViewModels and invoke the corresponding Screen composables inside `NavGraph.kt`.
- **Dependencies:** Android Jetpack Compose runtime, `androidx.navigation.compose`.
- **Verification Criteria:** NavGraph routes call `HomeScreen()`, `NetworkScreen()`, `ThreatsScreen()`, and `MoreScreen()` with proper navigation callbacks.
- **Effort:** Small (S)

---

### AUD-003: Unwired Header Redaction Pipeline in Agent DPI
- **Component:** `agent/dpi/event_buffer.py` & `agent/dpi/mitm_addon.py`
- **Severity:** P1 (High)
- **Evidence:** `agent/dpi/event_buffer.py` line 222 executes `redact_headers(raw_event.get("headers") or {})`. However, in `agent/dpi/mitm_addon.py`, the `DpiObservation` data structure does not populate `headers`, causing `raw_event.get("headers")` to always evaluate to `{}`. Sensitive authentication headers (`Authorization`, `Cookie`) are dropped or bypassed rather than systematically scrubbed.
- **Root Cause:** Disconnect between the mitmproxy event emitter model and the downstream redaction worker model.
- **Proposed Fix:** Ensure `mitm_addon.py` extracts HTTP headers into the observation payload, passes them through `redact_headers()`, and strips raw credentials before forwarding to the event buffer.
- **Dependencies:** `agent/dpi/redaction.py`, `tests/test_dpi_redaction.py`.
- **Verification Criteria:** Tests in `test_dpi_redaction.py` confirm intercepted `Authorization` and `Cookie` headers are properly redacted to `[REDACTED]` in persisted event streams.
- **Effort:** Small (S)

---

### AUD-004: Ingestion Hot Path Bottleneck & Detection Engine Serialization
- **Component:** `backend/services/flow_service.py`
- **Severity:** P1 (High)
- **Evidence:** `flow_service.py` allocates a `ThreadPoolExecutor(max_workers=4)` for DB writes. On high packet flow bursts, when Redis stream queueing falls back to sync MySQL, batches queue synchronously and all 5 detection engines evaluate sequentially on the thread, creating backpressure rejections (HTTP 429).
- **Root Cause:** Tight coupling of flow ingestion endpoint with synchronous database writes and detection analysis when Redis is bypassed.
- **Proposed Fix:** Enforce Redis stream queue ingestion on the primary path; run batch persistence and detection analysis via the decoupled background `flow_writer` and `correlation` worker processes.
- **Dependencies:** `backend/services/worker_supervisor.py`, `backend/services/flow_service.py`.
- **Verification Criteria:** Ingestion endpoint returns HTTP 202 Accepted in under 5ms under simulated burst load; zero dropped flows.
- **Effort:** Medium (M)

---

### AUD-005: QUIC Initial Parser Decryption Absence & TLS Blindspot
- **Component:** `packet_engine/quic_parser.py`
- **Severity:** P2 (Medium)
- **Evidence:** `quic_parser.py` lines 83-94 extracts Initial header fields but treats the crypto payload as plaintext. Unit tests only passed using synthetic unencrypted payloads. On live UDP/443 traffic, ClientHello SNI is undetectable unless QUIC is blocked and forced to fall back to TCP.
- **Root Cause:** Initial design assumed QUIC ClientHello could be extracted without implementing RFC 9001 Initial Secret derivation (HKDF + AES-GCM / ChaCha20-Poly1305).
- **Proposed Fix:** Document limitation clearly in architecture and defense notes; maintain the agent firewall/DPI rule `NETVISOR_DPI_ENABLE_QUIC_BLOCK=true` to force browser fallback to standard TLS over TCP for full inspection visibility.
- **Dependencies:** `agent/dpi/proxy_manager.py`, `packet_engine/quic_parser.py`.
- **Verification Criteria:** When QUIC blocking is enabled, browser HTTP/3 traffic gracefully downgrades to HTTP/2 over TLS, enabling 100% inspection coverage.
- **Effort:** Medium (M)

---

### AUD-006: Legacy Forwarding Shims in `collector/`
- **Component:** `collector/*.py`
- **Severity:** P3 (Low)
- **Evidence:** Files `collector/analysis.py`, `capture.py`, `flow_manager.py`, `observations.py`, `preflight.py`, `traffic_metadata.py` are trivial 1-line re-exports from `packet_engine/`.
- **Root Cause:** Historical refactoring preserved backward compatibility for older imports.
- **Proposed Fix:** Mark `collector/` as a deprecated compatibility facade; ensure internal imports point directly to `packet_engine/`.
- **Dependencies:** Repository internal imports.
- **Verification Criteria:** All tests continue passing without relying on circular imports.
- **Effort:** Small (S)

---

### AUD-007: Stale Prototype Directory & Build Clutter
- **Component:** `netvisor_frontend_3.0/`, `*.zip`, `all_code.txt`
- **Severity:** P3 (Low)
- **Evidence:** `netvisor_frontend_3.0` is an unreferenced prototype from August 2026. Root directory contains 36MB of ignored zip archives (`frontend-v2.zip`, `agent.zip`, `NetVisor_project.zip`).
- **Root Cause:** Manual backups and experimental UI trials stored locally.
- **Proposed Fix:** Document deprecation of `netvisor_frontend_3.0/` and safely remove stale root archives from local workspace to conserve disk and prevent confusion.
- **Dependencies:** None.
- **Verification Criteria:** Clean git workspace; `frontend/` and `frontend-v2/` remain the sole active UI codebases.
- **Effort:** Small (S)

---

### AUD-008: Deprecation Warnings for Legacy HS256 Token Fallback
- **Component:** `backend/api/auth.py`
- **Severity:** P2 (Medium)
- **Evidence:** Pytest outputs 1,012 deprecation warnings: `HS256 is deprecated for access tokens. Use RS256 with NETVISOR_JWT_PRIVATE_KEY/NETVISOR_JWT_PUBLIC_KEY.`
- **Root Cause:** Tests and development default configuration fall back to HS256 when RSA key pairs are omitted or when test clients instantiate basic tokens.
- **Proposed Fix:** Standardize RS256 test fixtures to use ephemeral test RSA key pairs, reducing log noise and reinforcing cryptographic best practice.
- **Dependencies:** `backend/core/security.py`, `tests/conftest.py`.
- **Verification Criteria:** Test suite runs with zero HS256 deprecation warnings.
- **Effort:** Small (S)

---

### AUD-009: Docker Compose Frontend Target Divergence
- **Component:** `docker-compose.yml`, `infra/docker/Dockerfile.frontend`
- **Severity:** P2 (Medium)
- **Evidence:** `docker-compose.yml` builds `frontend` container using `Dockerfile.frontend` which copies from `frontend/` (v1). As `frontend-v2` matures to feature parity, Docker configuration must support switching to `frontend-v2`.
- **Root Cause:** `frontend-v2` has not yet completed all sub-routes, so v1 remains the deployment default.
- **Proposed Fix:** Keep v1 as default until v2 reaches 100% route completion; create a parameterized build argument or target in `Dockerfile.frontend`.
- **Dependencies:** AUD-001 completion.
- **Verification Criteria:** Docker production image can be built from either `frontend` or `frontend-v2` with matching Nginx routing.
- **Effort:** Small (S)

---

### AUD-010: Object Pool Unreferenced on Hot Path Ingestion
- **Component:** `packet_engine/object_pool.py`, `packet_engine/dpkt_parser.py`
- **Severity:** P3 (Low)
- **Evidence:** `object_pool.py` defines pre-allocated packet and buffer pools, but `dpkt_parser.py` directly allocates new dictionary and object instances per parsed packet.
- **Root Cause:** Simplification during initial integration to favor python garbage collector over manual pool leasing.
- **Proposed Fix:** Retain current design for simplicity and stability unless profiling under 50,000+ packets/sec reveals GC pauses.
- **Dependencies:** Benchmarks in `benchmarks/`.
- **Verification Criteria:** Profiling confirms memory allocations remain bounded.
- **Effort:** Medium (M)
