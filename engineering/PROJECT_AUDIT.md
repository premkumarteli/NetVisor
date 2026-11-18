# Engineering Project Audit: NetVisor

**Date of Audit:** 2026-11-18 (Updated Stage 2b Reconciliation)  
**Audit Scope:** Full repository (Backend, Detection Engines, Ingestion Pipeline, Agent DPI, Gateway, Frontends, Android, Database, Security, Tests).  
**Confidentiality Notice:** Detailed exploit payloads and reproduction scripts for unpatched vulnerabilities are sequestered in gitignored file `engineering/SECURITY_VULNERABILITIES_PRIVATE.md` to prevent exposing security issues on this public GitHub repository.

---

## 1. Historical Audit Reconciliation Register

| Historical Issue | Severity | Status | Evidence / Reference | Engineering Verdict |
| :--- | :---: | :---: | :--- | :--- |
| **Reset-Data Cross-Tenant Wipe (incl. flushdb)** | **P0** | **FIXED** | Commit `47d1739` & `dfdada32` (`backend/services/system_service.py`) | Replaced global `r.flushdb()` with tenant-scoped Redis key deletion patterns (`dashboard:*:{org_id}`). Regression verified in `tests/test_audit_remediations.py`. |
| **Cert-Revoke Fall-Through** | **P1** | **FIXED** | Commit `2484e87` & `47d1739` (`backend/api/certificates.py:157-225`) | Fixed lookup fall-through when certificate serial was absent from `agents`. Now checks `agents` then `gateways` with strict `organization_id` boundary checks. |
| **Certificates.py Cross-Tenant Access** | **P1** | **FIXED** | Commit `2484e87` (`backend/api/certificates.py:33-79`) | Certificate listing and revocation endpoints enforce `require_org_scoped_role` and filter by `organization_id`. |
| **`apply_*.py` Migration Path Bug** | **P2** | **FIXED** | Commit `dfdada32` (`infra/database/migrations/apply_*.py`) | Repaired `_find_project_root` across all 12 migration runner scripts to verify `(parent / "backend").exists() and (parent / "agent").exists()`. |
| **HS256 JWT Fallback** | **P1** | **STILL PRESENT** | `backend/core/security.py:53-56, 80-84` | Fallback allows symmetric token signing via `NETVISOR_SECRET_KEY` if configured. Poses an authentication downgrade attack surface if RSA key configuration fails. |
| **SINGLE_ORG_MODE Inactive Multi-Tenancy** | **P1** | **STILL PRESENT** | `backend/core/config.py:192`, `backend/api/agents.py:137` | Single-organization mode is hardcoded as default (`SINGLE_ORG_MODE=True`). Device enrollments force all devices into `DEFAULT_ORGANIZATION_ID`. |
| **`/api/v1/auth/refresh` Missing Rate Limit** | **P1** | **STILL PRESENT** | `backend/api/auth.py:297-362` | Unlike `/login` (which enforces 20 req/min), `/refresh` has zero rate-limiting decorators or IP throttling, risking token rotation spam. |
| **Unwired IsolationForest ML Engine** | **P2** | **STILL PRESENT** | `backend/services/ml_service.py:11` | `MLService` / `IsolationForest` is trained on synthetic data but has zero incoming calls from `flow_service.py` or risk scoring pipelines. |
| **Unwired TLSAccumulator** | **P2** | **STILL PRESENT** | `packet_engine/tls_consumer.py:269`, `stream_registry.py:28` | Multi-segment ClientHello reassembly is unit-tested but uncalled in `FlowManager` or `agent/main.py`. Multi-segment TLS handshakes miss SNI extraction. |
| **Unwired DeviceEngine** | **P2** | **STILL PRESENT** | `backend/engines/registry.py:17`, `flow_service.py:1337` | `DeviceEngine` is registered in `EngineRegistry`, but `flow_service.py` explicitly calls `analyze_selective` with only `["threat", "vpn", "application", "risk", "ai"]`, omitting `"device"`. |
| **WinDivert Kernel Capture** | **P2** | **NOT IMPLEMENTED** | `packet_engine/types.py:10` | WinDivert is not implemented in code; only mentioned in a comment string. Packet capture relies on Scapy/raw sockets. |

---

## 2. Active Findings Register

### AUD-001: Frontend Strategy Alignment (Owner Decision)
- **Component:** `frontend-v2/` vs `frontend/`
- **Severity:** P3 (Informational / Closed)
- **Status:** **CLOSED (won't do: owner decision)**
- **Evidence:** `frontend-v2/` is personal owner work and declared off-limits to the team. `frontend/` (v1) is the production UI deployed via `docker-compose.yml`.
- **Resolution:** No porting to `frontend-v2`. Team maintenance strictly targets `frontend/`.

---

### AUD-002: Android Navigation Graph Integration
- **Component:** `Android_Application/.../NavGraph.kt`
- **Severity:** P2 (Medium)
- **Status:** **IMPLEMENTED-unverified**
- **Evidence:** `NavGraph.kt` previously contained unmounted `// TODO:` stubs for `home`, `network`, `threats`, and `more`.
- **Fix Applied:** Wired all 12 Jetpack Compose screens and ViewModels into `NavGraph.kt` to mirror `MainActivity.kt`.
- **Verification Note:** Marked `IMPLEMENTED-unverified` because Android Gradle build environment is not available in this CLI container.

---

### AUD-003: Redaction Engine Duplication & Header Omission
- **Component:** `agent/dpi/mitm_addon.py` vs `agent/dpi/redaction.py`
- **Severity:** P2 (Medium)
- **Evidence:** `mitm_addon.py` defines a local regex `redact_url_secrets()` and `sanitize_snippet()` while `agent/dpi/redaction.py` implements AST-based `redact_url()` and byte-level sanitization. Currently, no HTTP request/response headers are extracted or stored into `DpiObservation`.
- **Security Assessment:** Omission of headers is **safe by omission** (prevents token leakage). The primary defect is redundant regex implementation.
- **Proposed Action:** Proposed ADR `0001-dpi-header-capture-allowlist.md` for opt-in allow-listed header capture. Awaiting owner decision before implementing.

---

### AUD-004: Ingestion Hot Path Bottleneck & Detection Engine Serialization
- **Component:** `backend/services/flow_service.py`
- **Severity:** P1 (High)
- **Evidence:** `flow_service.py:88` (`ThreadPoolExecutor(max_workers=4)`) and `1337` (`analyze_selective`). On Redis stream fallback, batches queue synchronously and all 5 detection engines evaluate sequentially on the worker thread, producing backpressure rejections.
- **Proposed Fix:** Decouple ingestion into asynchronous background worker threads (`flow_writer` and `correlation` worker processes).
- **Effort:** Medium (M)

---

### AUD-008: JWT HS256 Fallback Auth-Downgrade Risk
- **Component:** `backend/core/security.py:53-56, 80-84`
- **Severity:** P1 (High)
- **Evidence:** While `create_access_token` emits a `DeprecationWarning` when `HS256` is configured, `_get_signing_key` and `_get_verification_key` still accept `HS256` using `NETVISOR_SECRET_KEY`. If RSA key pairs are missing or misconfigured in production, setting `JWT_ALGORITHM=HS256` silently downgrades token signing to a shared symmetric secret.
- **Proposed Fix:** Enforce fail-closed behavior: reject `HS256` at startup if `ENVIRONMENT=production`, requiring valid RS256 RSA keypairs.
- **Effort:** Small (S)

---

### AUD-009: Docker Compose Frontend Build Target
- **Component:** `docker-compose.yml`, `infra/docker/Dockerfile.frontend`
- **Severity:** P3 (Informational / Closed)
- **Status:** **CLOSED (won't do: owner decision)**
- **Evidence:** `docker-compose.yml` builds `frontend` from `frontend/` (v1). This is aligned with the owner decision that `frontend/` is the sole production UI.
- **Resolution:** No action required.
