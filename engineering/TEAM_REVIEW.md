# Team Conference & Review: NetVisor Architecture & Audit Resolution

**Date:** 2026-11-18  
**Context:** Formal project handover review across engineering roles prior to code modifications.

---

### Evidence-Based Role Dialogue & Disagreements

- **Tech Lead / Architect:** The backend core (FastAPI), detection engines, and packet engine are architecturally mature with 936 passing unit/stress tests. However, we have fragmentation across three frontend directories (`frontend`, `frontend-v2`, `netvisor_frontend_3.0`) and unrouted screens in the Android app. We must unify the client surface without destabilizing the working system.
- **Backend Engineer:** Ingestion scalability is constrained: `ThreadPoolExecutor(max_workers=4)` serializes MySQL operations when Redis is unavailable, and all 5 detection engines evaluate synchronously per flow batch. We need asynchronous background dispatch for high-throughput packet bursts.
- **Frontend / UX Engineer:** `frontend/` (v1) is 100% complete with 61 passing Vitest tests, but visually dated. `frontend-v2/` introduces a modern glassmorphism design system, Tailwind v4, and an interactive 3D WebGL topology graph, but has 6 routes mapped to `PlaceholderPage.jsx`. We should port the complete SOC workflows from v1 into v2 to make v2 the single production UI.
- **Database Engineer:** Agree on Redis streaming for ingestion, but MySQL schema integrity is sound. We have 14 structured migrations, foreign key constraints, and automatic CSV dumps to `db_dump/`. Any move to ClickHouse must be additive, keeping MySQL as the transactional system of record.
- **Security Engineer:** Threat modeling confirms strong data-plane protection (HMAC-SHA256 nonces, RS256 JWTs, CSRF tokens). However, two security gaps require remediation: (1) `agent/dpi/event_buffer.py` drops intercepted HTTP headers before redaction because `mitm_addon.py` doesn't populate the field, and (2) QUIC parser doesn't decrypt Initial handshakes, creating a TLS inspection blind spot unless UDP/443 is blocked.
- **QA / SDET:** Pytest suite passes 936 tests cleanly. Any refactoring in `frontend-v2` or `backend/` must have automated regression tests. We also need end-to-end component tests for the ported v2 pages.
- **DevOps / SRE:** `docker-compose.yml` still points to `frontend/` (v1). Stale archives (`*.zip`, `all_code.txt`) and orphaned `tmp/` folders should be purged, and the legacy `netvisor_frontend_3.0/` folder should be deprecated.

---

### Concrete Engineering Decisions Resolved

1. **DECISION 1 (Frontend Modernization Strategy):** Maintain `frontend/` (v1) as the proven stable baseline while systematically porting the 6 placeholder SOC workflows into `frontend-v2/`, backed by unit tests. Retire `netvisor_frontend_3.0/`.
2. **DECISION 2 (Android Navigation Connection):** Wire the 12 existing Jetpack Compose screens into `NavGraph.kt`, eliminating the 4 `// TODO:` placeholders.
3. **DECISION 3 (Security Pipeline Hardening):** Fix the header redaction pipeline between `mitm_addon.py` and `event_buffer.py` to ensure credentials in HTTP headers are sanitized before persistence.
4. **DECISION 4 (Ingestion Concurrency):** Retain Redis as the primary real-time stream queue for flows with bounded asynchronous background worker processing, avoiding synchronous MySQL row lock contention.
