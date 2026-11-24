# NetVisor Issue Tracker

**Live Status:** Active  
**Last Updated:** 2026-11-18 (Updated Stage 2b Reconciliation)  

---

### Status Definitions
- **NOT STARTED:** Work has not yet begun.
- **IN PROGRESS:** Actively being investigated or implemented.
- **BLOCKED:** Blocked by external dependency or missing credential (documented with reason).
- **IMPLEMENTED-unverified:** Code written and committed, but unverified due to missing local build toolchain (e.g., Android Gradle).
- **VERIFIED:** Automated test or acceptance command actually ran in this session and passed with evidence recorded.
- **CLOSED:** Resolved or concluded as won't do per owner decision.
- **DEFERRED:** Postponed with documented technical justification and risk assessment.

---

## Prioritized Task & Finding Registry (P0/P1 Security First)

| Issue ID | Priority | Owner Role | Status | Description |
| :--- | :---: | :--- | :---: | :--- |
| **ISSUE-SEC-01** | P1 | Security Engineer | **VERIFIED** | Enforce fail-closed RS256 token verification; reject HS256 in production environments. |
| **ISSUE-SEC-02** | P1 | Security Engineer | **VERIFIED** | Add rate limiting to `/api/v1/auth/refresh` to prevent token rotation spam. |
| **ISSUE-004** | P1 | Backend / SRE | **NOT STARTED** | Decouple flow batch ingestion from synchronous detection engine evaluation using background workers. |
| **ISSUE-MOB-01** | P1 | Mobile / Android | **IMPLEMENTED-unverified** | Wire unmounted Jetpack Compose screens into `NavGraph.kt` matching `MainActivity.kt`. |
| **ISSUE-SEC-03** | P2 | Security Engineer | **NOT STARTED** | Consolidate duplicate URL redaction engines (`mitm_addon.py` vs `agent/dpi/redaction.py`). |
| **ISSUE-SEC-04** | P2 | Architect / Security| **NOT STARTED** | Multi-tenancy enforcement review if `SINGLE_ORG_MODE=False` is enabled. |
| **ISSUE-005** | P2 | Security / Tech Writer | **DEFERRED** | QUIC Initial packet decryption; deferred in favor of UDP/443 blocking fallback. |
| **ISSUE-008** | P3 | Architect / Tech Writer| **NOT STARTED** | Document `collector/` backward compatibility shims in architecture documentation. |
| **ISSUE-007** | P3 | DevOps / Architect | **DOCUMENTED** | Stale archives (`*.zip`, `all_code.txt`) and `netvisor_frontend_3.0`: document only, ask owner before deleting. |
| **ISSUE-001** | P3 | Frontend / UX | **CLOSED** | Port SOC workflows to `frontend-v2`. Closed as "won't do: owner decision" (`frontend/` is production UI). |
| **AUD-009** | P3 | DevOps / SRE | **CLOSED** | Docker Compose frontend build divergence. Closed as "won't do: owner decision" (v1 is production target). |

---

## Task Details & Verification Records

### ISSUE-SEC-01: Enforce Fail-Closed RS256 Token Verification
- **Description:** Remove or strictly disable HS256 JWT fallback when `ENVIRONMENT=production`. Require valid RS256 RSA keypairs at application startup, raising a fatal configuration error if keys are absent.
- **Priority:** P1
- **Owner:** Security Engineer
- **Status:** VERIFIED
- **Implementation & Verification:** Updated `backend/main.py::_validate_runtime_config` using dynamic `get_settings()` to reject HS256 when `cfg.ENVIRONMENT == "production"` and fail closed if RSA public/private keys cannot be loaded. Verified via `test_validate_runtime_config_rejects_hs256_in_production` and `test_validate_runtime_config_rejects_missing_rs256_keys_in_production` in `tests/test_refresh_token.py`.

### ISSUE-SEC-02: Add Rate Limiting to `/api/v1/auth/refresh`
- **Description:** Implement rate limiting on `/api/v1/auth/refresh` (matching `/login` limit of 20 requests/minute) to mitigate brute-force and token rotation flooding.
- **Priority:** P1
- **Owner:** Security Engineer
- **Status:** VERIFIED
- **Implementation & Verification:** Added `AUTH_REFRESH_RATE_LIMIT_PER_MINUTE` (default: 20) to `backend/core/config.py`. Attached `refresh_rate_limit = request_rate_limit(...)` dependency to `@router.post("/refresh")` in `backend/api/auth.py`. Verified via `test_refresh_session_rate_limiter_blocks_excessive_requests` in `tests/test_refresh_token.py`.

### ISSUE-004: Decouple Flow Ingestion Hot Path
- **Description:** Offload flow batch detection analysis from `flow_service.py` ingestion handler to background worker processes (`flow_writer` and `correlation` workers).
- **Priority:** P1
- **Owner:** Backend Engineer / SRE
- **Status:** NOT STARTED
- **Implementation Plan:** Route batches directly to Redis Stream `XADD`, allowing HTTP response to return immediately without evaluating 5 detection engines synchronously.

### ISSUE-MOB-01: Wire Android Navigation Graph
- **Description:** Wire `HomeScreen`, `NetworkScreen`, `ThreatsScreen`, `MoreScreen`, `AppsScreen`, `VpnScreen`, `DpiScreen`, `AgentsScreen`, `LogsScreen`, and `SettingsScreen` into `NavGraph.kt`.
- **Priority:** P1
- **Owner:** Mobile / Android Engineer
- **Status:** IMPLEMENTED-unverified
- **Implementation Details:** Rewrote `Android_Application/app/src/main/java/com/netvisor/mobile/navigation/NavGraph.kt` to instantiate all screens and ViewModels matching `MainActivity.kt`. Marked unverified due to lack of local Android SDK / Gradle execution environment.

### ISSUE-001: Port SOC Workflows to `frontend-v2`
- **Status:** CLOSED (won't do: owner decision)
- **Technical Note:** Per explicit owner directive, `frontend-v2/` is the owner's personal work and off-limits to the team. The production application deployed by `docker-compose.yml` is `frontend/` (v1). All future UI/UX and accessibility engineering will target `frontend/` exclusively.

### AUD-009: Docker Compose Frontend Target Divergence
- **Status:** CLOSED (won't do: owner decision)
- **Technical Note:** `docker-compose.yml` correctly builds from `frontend/` (v1) via `Dockerfile.frontend`. Aligned with owner directive.
