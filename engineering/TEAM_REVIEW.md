# Team Conference & Review: NetVisor Architecture & Audit Resolution

**Date:** 2026-11-18 (Updated Stage 2b Reconciliation)  
**Context:** Formal project handover review across engineering roles prior to code modifications.

---

### Evidence-Based Role Dialogue & Disagreements

- **Tech Lead / Architect:** The backend core (FastAPI), detection engines, and packet engine are architecturally mature with 969 passing unit/stress tests when database credentials are supplied. Regarding frontends: `frontend-v2/` is an experimental prototype authored by the owner and is declared off-limits to the team. The team's authoritative frontend is `frontend/` (v1), which is the one deployed by `docker-compose.yml`.
- **Backend Engineer:** Ingestion scalability remains constrained: `ThreadPoolExecutor(max_workers=4)` serializes MySQL operations when Redis is unavailable, and all 5 detection engines evaluate synchronously per flow batch. We need asynchronous background dispatch for high-throughput packet bursts.
- **Frontend / UX Engineer:** Aligned with owner directive. `frontend/` (v1) is 100% complete with 61 passing Vitest tests and full SOC coverage. All future UI/UX polish, WCAG 2.2 accessibility, and responsive refinements will target `frontend/` exclusively.
- **Database Engineer:** Agree on Redis streaming for ingestion, but MySQL schema integrity is sound. We have 14 structured migrations, foreign key constraints, and automatic CSV dumps to `db_dump/`. Any move to ClickHouse must be additive, keeping MySQL as the transactional system of record.
- **Security Engineer:** Threat modeling confirms strong data-plane protection (HMAC-SHA256 nonces on agent and gateway operational data). However, three security items require remediation: (1) `/api/v1/auth/refresh` lacks rate limiting, (2) HS256 JWT fallback poses an auth-downgrade risk if RS256 key loading fails in production, and (3) URL redaction logic is duplicated between `mitm_addon.py` and `agent/dpi/redaction.py`.
- **QA / SDET:** Test suite verification confirms 969 passed, 3 skipped (due to live Uvicorn server absence on port 8000), 0 failed when database password is provided. Any refactoring in `backend/` or `frontend/` must have automated regression tests.
- **DevOps / SRE:** `docker-compose.yml` points to `frontend/` (v1). Stale archives (`*.zip`, `all_code.txt`) and `netvisor_frontend_3.0/` will remain documented without deletion until explicit owner approval is received.

---

### Concrete Engineering Decisions Resolved

1. **DEC-001 (Production Frontend Boundary):** `frontend/` is the team's production frontend; `frontend-v2/` is owner-managed and out of scope per owner decision.
2. **DEC-002 (Android Navigation Connection):** Wire all 12 existing Jetpack Compose screens into `NavGraph.kt`, eliminating the unmounted `// TODO:` placeholders to mirror `MainActivity.kt`.
3. **DEC-003 (Security Pipeline Hardening):** Address P1 security items first: implement rate limiting on `/api/v1/auth/refresh`, enforce fail-closed RS256 authentication, and consolidate duplicate URL sanitizers.
4. **DEC-004 (Ingestion Concurrency):** Retain Redis as the primary real-time stream queue for flows with bounded asynchronous background worker processing, avoiding synchronous MySQL row lock contention.
