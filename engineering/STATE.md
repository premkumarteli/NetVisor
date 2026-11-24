# NetVisor Live Engineering State

## 1. Project Summary
- **Type:** Cyber-security workspace for network flow visibility, endpoint telemetry, and threat detection.
- **Stack:** Python 3.13, FastAPI, MySQL 8.0, Redis 7.0, React 18, Tailwind CSS, Scapy/dpkt, mitmproxy.
- **Purpose:** Self-hosted dual-plane monitoring combining managed endpoint telemetry with privacy-safe BYOD gateway metadata.
- **Deployment:** Docker Compose multi-container architecture (`frontend/` v1 production console) and native host daemons.
- **Tenancy:** Single-organization in practice (`SINGLE_ORG_MODE=True` default).

## 2. Current Stage & Status
- **Current Stage:** Stage 2b Complete / Stage 3 Execution (Security & Telemetry Optimization).
- **Overall Status:** P1 Security Fixes Implemented & Verified; ClickHouse Telemetry Flusher Implemented & Verified.
- **Execution Date:** 2026-11-24.

## 3. Decisions Made
- **DEC-001:** `frontend/` is the team's production frontend; `frontend-v2/` is owner-managed and out of scope per owner decision ([TEAM_REVIEW.md](TEAM_REVIEW.md)).
- **DEC-002:** Android `NavGraph.kt` routes wired to mirror `MainActivity.kt` ([TEAM_REVIEW.md](TEAM_REVIEW.md)).
- **DEC-003:** Security first roadmap: address `/refresh` rate limiting, fail-closed RS256 token verification, and duplicate URL sanitizers ([PROJECT_AUDIT.md](PROJECT_AUDIT.md)).
- **DEC-004:** Preserve Redis stream queuing for flow ingestion to prevent synchronous database write lock contention ([TEAM_REVIEW.md](TEAM_REVIEW.md)).
- **DEC-005:** Retain UDP/443 QUIC blocking for browser inspection rather than building high-overhead in-memory QUIC crypto reassembly ([ISSUE_TRACKER.md](ISSUE_TRACKER.md)).
- **DEC-006:** Safe header capture proposed via explicit allow-list in ADR-0001; awaiting owner approval before implementation ([0001-dpi-header-capture-allowlist.md](adr/0001-dpi-header-capture-allowlist.md)).
- **DEC-007:** ClickHouse telemetry ingestion implements a non-blocking double-buffer with atomic pointer swapping and a JSONL disk-spool Write-Ahead Log (WAL) to survive network drops without memory exhaustion or blocking the fast path ([docs/netvisor-next-phase-options-evaluation.md](../docs/netvisor-next-phase-options-evaluation.md)).

## 4. Open Issues
- **ISSUE-SEC-01 (P1):** Enforce fail-closed RS256 token verification; reject HS256 in production ([VERIFIED]).
- **ISSUE-SEC-02 (P1):** Add rate limiting to `/api/v1/auth/refresh` ([VERIFIED]).
- **ISSUE-004 (P1):** Decouple flow batch ingestion from synchronous detection engine evaluation.
- **ISSUE-MOB-01 (P1):** Android `NavGraph.kt` wiring complete ([IMPLEMENTED-unverified]).
- **ISSUE-SEC-03 (P2):** Consolidate duplicate URL redaction engines (`mitm_addon.py` vs `agent/dpi/redaction.py`).
- **ISSUE-SEC-04 (P2):** Multi-tenancy enforcement review if `SINGLE_ORG_MODE=False` is enabled.
- **ISSUE-005 (P2):** QUIC Initial packet decryption; deferred in favor of UDP/443 blocking fallback.
- **ISSUE-008 (P3):** Document `collector/` backward compatibility shims in architecture documentation.
- **ISSUE-007 (P3):** Stale archives (`*.zip`, `all_code.txt`) and `netvisor_frontend_3.0`: document only, ask owner before deleting.
- **ISSUE-001 (P3):** Port SOC workflows to `frontend-v2` ([CLOSED - won't do: owner decision]).
- **AUD-009 (P3):** Docker Compose frontend build divergence ([CLOSED - won't do: owner decision]).

## 5. What is Verified vs Unverified Right Now
- **VERIFIED:**
  - Backend startup & health check: `.\.venv\Scripts\python.exe run_server.py --health-check` (Exit code 0, all DB, schema, and security checks pass).
  - P1 Security (ISSUE-SEC-01): Fail-closed RS256 startup verification in production environment; rejects HS256 with fatal error, validates RSA key existence (`test_validate_runtime_config_rejects_hs256_in_production`, `test_validate_runtime_config_rejects_missing_rs256_keys_in_production`).
  - P1 Security (ISSUE-SEC-02): `/api/v1/auth/refresh` rate limiting (20 req/min) active via `request_rate_limit` dependency (`test_refresh_session_rate_limiter_blocks_excessive_requests`).
  - ClickHouse Telemetry Flusher: Double-buffer flusher with background worker, JSONL disk-spool WAL, and analytics fallback bridge verified (`tests/test_clickhouse_flusher.py` - 11 passed; `tests/stress/test_challenger2_empirical_scenarios.py` - 3 passed).
  - Python test suite: Comprehensive auth, security, and flusher test suite passes (56 passed, 0 failed in 45s).
  - Full regression test suite: With `NETVISOR_DB_PASSWORD` set, **969 passed, 3 skipped, 0 failed** across 121 test modules.
  - Frontend v1 Vitest suite: `npm --prefix frontend test` (8 test files passed, 61 passed, 0 failed in 39s).
  - Frontend v1 production build: `npm --prefix frontend run build` (Exit code 0, built in 13.03s).
  - Git history secret scan: Analyzed 164,193,410 characters across 3,223,424 lines of git diffs; zero committed RSA private keys. 19 hardcoded historical test/bootstrap strings found and logged.
  - Local gitignored secrets: Confirmed `keys/*.pem` and `all_code.txt` are gitignored; confidential vulnerability register secured in gitignored `engineering/SECURITY_VULNERABILITIES_PRIVATE.md`.
  - Static API Keys: `AGENT_API_KEY` and `GATEWAY_API_KEY` verified bootstrap-only on `/register`; operational endpoints reject static keys and enforce HMAC+nonce signatures.
- **UNVERIFIED / NOT IMPLEMENTED:**
  - Android application compilation via Gradle: [IMPLEMENTED-unverified] (no local Android SDK / JVM).
  - WinDivert kernel driver capture: [NOT IMPLEMENTED] (Scapy/raw sockets only).

## 6. NEXT ACTION
- **Exact Next Step:**
  1. Await owner feedback on ADR-0001 (opt-in allow-listed DPI header capture).
  2. Implement ISSUE-004 (Decouple flow batch ingestion from synchronous detection engine evaluation via Redis streams).
  3. Consolidate duplicate URL redaction engines (ISSUE-SEC-03).

## 7. Verified Commands to Run
- **Run Backend Health Check:**
  ```powershell
  .\.venv\Scripts\python.exe run_server.py --health-check
  ```
- **Run Backend Server:**
  ```powershell
  .\.venv\Scripts\python.exe run_server.py
  ```
- **Run Production Frontend Console (`frontend/`):**
  ```powershell
  npm --prefix frontend run dev
  ```
- **Run Full Python Test Suite (with scratch test DB password):**
  ```powershell
  $env:NETVISOR_DB_PASSWORD="your_password"; .\.venv\Scripts\pytest.exe -q --disable-warnings
  ```
- **Run Frontend Unit Tests:**
  ```powershell
  npm --prefix frontend test
  ```
