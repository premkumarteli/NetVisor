# NetVisor Live Engineering State

## 1. Project Summary
- **Type:** Cyber-security workspace for network flow visibility, endpoint telemetry, and threat detection.
- **Stack:** Python 3.13, FastAPI, MySQL 8.0, Redis 7.0, React 18, Tailwind CSS v4, Scapy/dpkt, mitmproxy.
- **Purpose:** Self-hosted dual-plane monitoring combining rich managed endpoint telemetry with privacy-safe BYOD gateway metadata.
- **Deployment:** Docker Compose multi-container architecture and native Windows/Linux service daemons.
- **Maturity:** Core backend, packet engine, and detection platform are production-grade (936 passing tests); frontend modernization and mobile route wiring in progress.

## 2. Current Stage & Status
- **Current Stage:** Stage 1 (Discover) & Stage 2 (Team Conference & Project Audit) COMPLETE.
- **Overall Status:** Ready for Stage 3 (Plan) and Stage 4 (Fix Critical Problems).
- **Execution Date:** 2026-11-18.

## 3. Decisions Made
- **DEC-001:** Preserve `frontend/` (v1) as stable baseline while incrementally porting placeholder workflows into `frontend-v2/` ([TEAM_REVIEW.md](file:///c:/Users/prem/Network/engineering/TEAM_REVIEW.md)).
- **DEC-002:** Wire existing 12 Jetpack Compose screens into Android `NavGraph.kt` stubs ([TEAM_REVIEW.md](file:///c:/Users/prem/Network/engineering/TEAM_REVIEW.md)).
- **DEC-003:** Rectify header redaction pipeline between `mitm_addon.py` and `event_buffer.py` to scrub auth tokens ([TEAM_REVIEW.md](file:///c:/Users/prem/Network/engineering/TEAM_REVIEW.md)).
- **DEC-004:** Preserve Redis stream queuing for flow ingestion to prevent synchronous database write lock contention ([TEAM_REVIEW.md](file:///c:/Users/prem/Network/engineering/TEAM_REVIEW.md)).
- **DEC-005:** Retain UDP/443 QUIC blocking for browser inspection rather than building high-overhead in-memory QUIC crypto reassembly ([ISSUE_TRACKER.md](file:///c:/Users/prem/Network/engineering/ISSUE_TRACKER.md)).

## 4. Open Issues
- **ISSUE-001 (P1):** Port 6 SOC workflows (`/agents`, `/apps`, `/threats`, `/activity`, `/vpn`, `/settings`) into `frontend-v2`.
- **ISSUE-002 (P1):** Wire Jetpack Compose screen composables into Android `NavGraph.kt`.
- **ISSUE-003 (P1):** Wire HTTP header extraction in `agent/dpi/mitm_addon.py` through `redact_headers()`.
- **ISSUE-004 (P1):** Enforce asynchronous worker decoupling for flow ingestion batch processing.
- **ISSUE-006 (P2):** Inject RS256 test key fixtures in `tests/conftest.py` to eliminate HS256 deprecation warnings.
- **ISSUE-007 (P3):** Clean stale prototype `netvisor_frontend_3.0` and archive clutter.
- **ISSUE-008 (P3):** Document `collector/` backward compatibility shims in architecture documentation.

## 5. What is Verified vs Unverified Right Now
- **VERIFIED:**
  - Backend startup & health check: `.\.venv\Scripts\python.exe run_server.py --health-check` (Exit code 0, all DB and schema checks pass).
  - Python test suite: `.\.venv\Scripts\pytest.exe -q --disable-warnings` (936 passed, 37 skipped, 0 failed in 337s).
  - Frontend v1 Vitest suite: `npm --prefix frontend test` (8 test files passed, 61 passed, 0 failed in 39s).
  - Frontend v1 production build: `npm --prefix frontend run build` (Exit code 0, built in 13.03s).
  - Frontend v2 production build: `npm --prefix frontend-v2 run build` (Exit code 0, built in 9.87s).
  - Git secrets scan: Zero committed private keys found in git history.
- **UNVERIFIED:**
  - Android application compilation via Gradle (requires Android SDK / JVM environment).
  - Live WinDivert packet interception on active physical hotspot network interfaces.

## 6. NEXT ACTION
- **Exact Next Step:** Begin Stage 3 (Plan & Target Architecture) and Stage 4 (Fix Critical Problems):
  1. Author `engineering/ARCHITECTURE.md` establishing target architecture and porting plan.
  2. Implement fix for ISSUE-003 (Wire HTTP header extraction and redaction in `agent/dpi/mitm_addon.py`).
  3. Wire Android `NavGraph.kt` routes (ISSUE-002).

## 7. Verified Commands to Run
- **Run Backend Health Check:**
  ```powershell
  .\.venv\Scripts\python.exe run_server.py --health-check
  ```
- **Run Backend Server:**
  ```powershell
  .\.venv\Scripts\python.exe run_server.py
  ```
- **Run Frontend v1 Console:**
  ```powershell
  npm --prefix frontend run dev
  ```
- **Run Frontend v2 Console:**
  ```powershell
  npm --prefix frontend-v2 run dev
  ```
- **Run Full Python Test Suite:**
  ```powershell
  .\.venv\Scripts\pytest.exe -q --disable-warnings
  ```
- **Run Frontend Unit Tests:**
  ```powershell
  npm --prefix frontend test
  ```
