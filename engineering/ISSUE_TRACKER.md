# NetVisor Issue Tracker

**Live Status:** Active  
**Last Updated:** 2026-11-18  

---

### Status Definitions
- **NOT STARTED:** Work has not yet begun.
- **IN PROGRESS:** Actively being investigated or implemented.
- **BLOCKED:** Blocked by external dependency or missing credential (documented with reason).
- **IMPLEMENTED:** Code changes made and committed, but not yet verified by automated test.
- **VERIFIED:** Automated test or acceptance command actually ran in this session and passed with evidence recorded.
- **DEFERRED:** Postponed with documented technical justification and risk assessment.

---

## Active Task & Finding Registry

| Issue ID | Priority | Owner Role | Status | Description |
| :--- | :---: | :--- | :---: | :--- |
| **ISSUE-001** | P1 | Frontend / UX | **NOT STARTED** | Port 6 SOC workflows (`/agents`, `/apps`, `/threats`, `/activity`, `/vpn`, `/settings`) from v1 to `frontend-v2`. |
| **ISSUE-002** | P1 | Mobile / Android | **NOT STARTED** | Connect unmounted Jetpack Compose screens into `NavGraph.kt`. |
| **ISSUE-003** | P1 | Security Engineer | **NOT STARTED** | Fix unwired HTTP header redaction pipeline in `agent/dpi/mitm_addon.py` -> `event_buffer.py`. |
| **ISSUE-004** | P1 | Backend / SRE | **NOT STARTED** | Decouple flow batch ingestion from synchronous detection engine evaluation using background workers. |
| **ISSUE-005** | P2 | Security / Tech Writer | **DEFERRED** | QUIC Initial packet decryption; deferred in favor of standard QUIC UDP/443 blocking fallback. |
| **ISSUE-006** | P2 | Security / QA | **NOT STARTED** | Standardize RS256 RSA key fixtures in tests to eliminate 1,012 HS256 deprecation warnings. |
| **ISSUE-007** | P3 | DevOps / Architect | **NOT STARTED** | Retire stale `netvisor_frontend_3.0/` prototype and clean up local archive artifacts. |
| **ISSUE-008** | P3 | Architect / Tech Writer| **NOT STARTED** | Document `collector/` backward compatibility shims in architecture documentation. |

---

## Task Details & Verification Records

### ISSUE-001: Port 6 SOC Workflows to `frontend-v2`
- **Description:** Replace `<PlaceholderPage />` stubs in `frontend-v2/src/App.jsx` with full interactive pages for Fleet Monitoring (`/agents`), Application Intel (`/apps`), Threat Triage (`/threats`), Traffic Activity (`/activity`), VPN Intelligence (`/vpn`), and Administration (`/settings`).
- **Priority:** P1
- **Owner:** Frontend / UX Engineer
- **Status:** NOT STARTED
- **Implementation Details:** Re-use mature component logic from `frontend/src/pages/`, refactoring styles to match `frontend-v2` Tailwind v4 design tokens and Glassmorphism styling.
- **Verification Evidence:** None yet.

### ISSUE-002: Connect Android Screens in `NavGraph.kt`
- **Description:** Replace `// TODO:` stubs in `NavGraph.kt` with actual screen composables: `HomeScreen()`, `NetworkScreen()`, `ThreatsScreen()`, and `MoreScreen()`.
- **Priority:** P1
- **Owner:** Mobile / Android Engineer
- **Status:** NOT STARTED
- **Implementation Details:** Import screens from `com.netvisor.mobile.ui.*`, wire bottom nav bar callbacks and navigation actions.
- **Verification Evidence:** None yet.

### ISSUE-003: Fix DPI Header Redaction Pipeline
- **Description:** Ensure intercepted HTTP headers are extracted in `mitm_addon.py` and passed into `redact_headers()` in `event_buffer.py` before event persistence.
- **Priority:** P1
- **Owner:** Security Engineer
- **Status:** NOT STARTED
- **Implementation Details:** Update `DpiObservation` payload dictionary to include sanitized header map.
- **Verification Evidence:** None yet.

### ISSUE-004: Decouple Synchronous Flow Ingestion Hot Path
- **Description:** Shift synchronous detection engine execution out of `flow_service.py` ingestion loop into asynchronous background workers.
- **Priority:** P1
- **Owner:** Backend Engineer / SRE
- **Status:** NOT STARTED
- **Implementation Details:** Leverage Redis stream `XADD` for non-blocking ingestion; let `flow_writer` and `correlation` workers consume batches and run detection out-of-band.
- **Verification Evidence:** None yet.

### ISSUE-005: QUIC Initial Packet Decryption Limitation
- **Description:** Document QUIC ClientHello decryption limitation and verify `NETVISOR_DPI_ENABLE_QUIC_BLOCK=true` fallback behavior.
- **Priority:** P2
- **Owner:** Security Engineer / Tech Writer
- **Status:** DEFERRED
- **Technical Justification:** Implementing RFC 9001 TLS 1.3 crypto derivation in pure Python packet sniffer requires extensive cryptographic state machine with high CPU overhead. Blocking UDP/443 reliably forces all major browsers (Chrome, Edge, Firefox) to fall back to TLS 1.3 over TCP, which NetVisor inspects with 100% fidelity.
- **Risk Assessment:** Low residual risk in corporate/managed environments where firewall rules or local agent blocks UDP/443.

### ISSUE-006: Standardize RS256 Test Key Fixtures
- **Description:** Update test fixtures in `tests/conftest.py` to supply ephemeral RS256 keys to suppress 1,012 HS256 deprecation warnings.
- **Priority:** P2
- **Owner:** Security Engineer / QA
- **Status:** NOT STARTED
- **Implementation Details:** Generate RSA 2048-bit keypair in `conftest.py` session fixture and inject via settings override.
- **Verification Evidence:** None yet.

### ISSUE-007: Clean Stale Prototypes & Workspace Clutter
- **Description:** Deprecate and remove stale `netvisor_frontend_3.0` prototype and remove untracked zip files from workspace root.
- **Priority:** P3
- **Owner:** DevOps / Architect
- **Status:** NOT STARTED
- **Implementation Details:** Verify no production scripts or Docker files reference `netvisor_frontend_3.0`, then clean up.
- **Verification Evidence:** None yet.

### ISSUE-008: Document Compatibility Facade for `collector/`
- **Description:** Clarify in architectural documentation that `collector/*.py` is an alias facade for `packet_engine/`.
- **Priority:** P3
- **Owner:** Architect / Tech Writer
- **Status:** NOT STARTED
- **Implementation Details:** Add section to `ARCHITECTURE.md`.
- **Verification Evidence:** None yet.
