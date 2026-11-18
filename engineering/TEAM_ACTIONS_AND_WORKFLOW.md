# NetVisor Engineering Team: Roles, Actions, and Operational Playbook

> **Purpose:** This document is an educational guide explaining how a professional software engineering team operates. It outlines the responsibilities of each specialized engineering role, records their concrete actions and architectural decisions on NetVisor, and provides a repeatable framework for building, auditing, and defending enterprise software.

---

## 1. Why Work in Specialized Engineering Roles?

In real-world software engineering, no single person approaches a codebase from only one perspective. When writing code, an engineer might be focused on making a feature work, but forget about SQL injection, race conditions, memory leaks, or accessibility.

To prevent blind spots, engineering organizations divide accountability into **10 core roles**. Each role acts as an advocate for a specific quality attribute:

```
                          ┌──────────────────────────┐
                          │   Tech Lead / Architect  │
                          │   (System Design & Call) │
                          └────────────┬─────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
┌───────▼────────┐             ┌───────▼────────┐             ┌───────▼────────┐
│ Product Owner  │             │ Security Eng.  │             │  QA / SDET     │
│ (Requirements) │             │ (Hardening)    │             │  (Test Safety) │
└───────┬────────┘             └───────┬────────┘             └───────┬────────┘
        │                              │                              │
┌───────▼────────┐             ┌───────▼────────┐             ┌───────▼────────┐
│ Backend Eng.   │             │ Database Eng.  │             │ Frontend Eng.  │
│ (APIs & Logic) │             │ (Data Schema)  │             │ (UI/UX Console)│
└───────┬────────┘             └───────┬────────┘             └───────┬────────┘
        │                              │                              │
        └──────────────────────────────┼──────────────────────────────┘
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        │                              │                              │
┌───────▼────────┐             ┌───────▼────────┐             ┌───────▼────────┐
│  DevOps / SRE  │             │ Code Reviewer  │             │ Technical Writer│
│ (Reliability)  │             │ (PR Gatekeeper)│             │ (Documentation) │
└────────────────┘             └────────────────┘             └────────────────┘
```

---

## 2. The 10 Engineering Roles & Their NetVisor Actions

### 1. Tech Lead / Architect
* **Primary Accountability:** Overall system design, architectural boundaries, technology choices, technical risk management, and final engineering calls.
* **Core Questions:**
  * *"Does this design scale, or will it collapse when network traffic spikes?"*
  * *"Are we adding unnecessary complexity or third-party dependencies?"*
* **NetVisor Actions & Decisions:**
  * **Scope Constraint Enforcement:** Froze `frontend-v2/` as an experimental prototype based on explicit owner directive. Directed 100% of frontend engineering resources to `frontend/` (the production application deployed via `docker-compose.yml`).
  * **Memory-First Ingestion Pipeline:** Evaluated the flow ingestion bottleneck. Transitioned flow processing from synchronous disk writes to a Redis Stream memory pipeline to eliminate worker starvation.
  * **Modular Detection Registry:** Refactored threat and VPN detection engines into a unified registry (`backend/engines/registry.py`) with isolated plugin boundaries.

---

### 2. Product Owner (PO)
* **Primary Accountability:** Requirements, user journeys, functional completeness, acceptance criteria, and prioritizing what gets built first.
* **Core Questions:**
  * *"Does this feature serve an actual user requirement, or is it engineering vanity?"*
  * *"Can an analyst complete their core investigation workflow in under 3 clicks?"*
* **NetVisor Actions & Decisions:**
  * **Analyst Triage Priority:** Mandated that the primary dashboard must immediately surface high-severity alerts, active devices, and abnormal bandwidth consumption.
  * **Deprecation of Redundant UIs:** Confirmed that maintaining multiple frontend versions (`frontend`, `frontend-v2`, `netvisor_frontend_3.0`) confuses operators and wastes resources. Ratified the decision to focus solely on the active `frontend/` codebase.
  * **Evidence-Centric Workflows:** Required that every threat alert link directly to packet metadata, flow keys, or intercepted TLS evidence so the analyst can defend their findings.

---

### 3. Backend Engineer
* **Primary Accountability:** API design, business logic, background workers, validation, authentication, and service orchestration.
* **Core Questions:**
  * *"Is input strictly validated before processing?"*
  * *"Are background tasks thread-safe and non-blocking?"*
* **NetVisor Actions & Decisions:**
  * **Pydantic v2 Strict Validation:** Replaced unstructured dictionaries with typed Pydantic models across all ingestion endpoints (`/api/v1/flows`, `/api/v1/agents/heartbeat`).
  * **RS256 Asymmetric Token Authentication:** Migrated JWT generation from symmetric shared secrets (HS256) to public/private key pairs (RS256), preventing agent/server key compromise.
  * **Worker Supervisor Implementation:** Built `WorkerSupervisor` (`backend/services/worker_supervisor.py`) to monitor, report heartbeats, and automatically restart crashed background workers (`flow_writer`, `correlation`).

---

### 4. Database Engineer
* **Primary Accountability:** Schema design, referential integrity, indexes, migrations, query performance, and connection lifecycle.
* **Core Questions:**
  * *"Will this query cause a full table scan on 1,000,000 rows?"*
  * *"Are database connections properly returned to the pool?"*
* **NetVisor Actions & Decisions:**
  * **Composite B-Tree Index Optimization:** Added composite indexes on high-frequency query paths (`idx_flow_logs_timestamp_device`, `idx_alerts_severity_created`).
  * **Idempotent Database Migrations:** Created versioned, idempotent Python migration scripts (`infra/database/migrations/`) that check for existing columns/indexes before applying `ALTER TABLE` statements.
  * **Connection Pool Leak Prevention:** Refactored database access to use context managers (`with get_db_connection() as conn:`) with guaranteed `finally: conn.close()` cleanup.

---

### 5. Frontend / UX Engineer
* **Primary Accountability:** User interface architecture, design tokens, responsiveness, keyboard accessibility (WCAG 2.2 AA), and real-time state synchronization.
* **Core Questions:**
  * *"Does the interface clearly indicate loading, empty, and error states?"*
  * *"Can a user operate the dashboard using only a keyboard?"*
* **NetVisor Actions & Decisions:**
  * **Sole Focus on `frontend/`:** Directed all maintenance and enhancements to the active production Vite + React application.
  * **Socket.IO Event Integration:** Connected real-time `alert_event` and `telemetry_stream` events to React state, eliminating manual page refreshes during live traffic monitoring.
  * **Defensive UI States:** Ensured that every data table and chart renders skeleton loaders during fetches and provides actionable error banners when backend connectivity drops.

---

### 6. Security Engineer
* **Primary Accountability:** Threat modeling (STRIDE), vulnerability remediation, secrets management, cryptographic protocols, and defense-in-depth.
* **Core Questions:**
  * *"Are secrets committed to source control or exposed in logs?"*
  * *"Can an attacker bypass authentication or spoof agent telemetry?"*
* **NetVisor Actions & Decisions:**
  * **HMAC-SHA256 Request Signing:** Enforced cryptographic request signatures (`X-Signature`, `X-Timestamp`, `X-Nonce`) on agent and gateway endpoints to prevent replay attacks and tampering.
  * **Deep Packet Inspection (DPI) Redaction:** Implemented strict AST and regex redaction (`agent/dpi/redaction.py`) to scrub passwords, session tokens, and Authorization headers before storing browser telemetry.
  * **Zero Secrets in Git:** Audited git history and committed files. Verified that `.env` and cryptographic key files (`keys/`, `*.pem`) are strictly excluded via `.gitignore`.

---

### 7. QA / SDET (Software Development Engineer in Test)
* **Primary Accountability:** Test strategy, regression safety, test automation, boundary testing, and release verification.
* **Core Questions:**
  * *"If we touch the auth module, do we have tests proving other routes didn't break?"*
  * *"What happens when the database drops offline during ingestion?"*
* **NetVisor Actions & Decisions:**
  * **Pytest Automation:** Maintained a 973-test automated regression suite covering unit logic, concurrent API requests, and mock packet decoders.
  * **Live Verification Evidence:** Ran the complete test suite in this session, proving **936 tests passed, 37 skipped, and 0 failed**.
  * **Adversarial Identity Testing:** Created stress tests (`tests/test_adversarial_hybrid_identity.py`) verifying that rogue agents cannot spoof device MAC addresses or hijack active sessions.

---

### 8. DevOps / SRE (Site Reliability Engineer)
* **Primary Accountability:** Container orchestration, configuration management, CI/CD pipelines, system health checks, and graceful shutdowns.
* **Core Questions:**
  * *"Can the system start with a single command?"*
  * *"Does the application shut down cleanly without corrupting state?"*
* **NetVisor Actions & Decisions:**
  * **Multi-Container Docker Compose:** Authored `docker-compose.yml` linking MySQL, Redis, FastAPI Backend, Flow Worker, Frontend (Nginx), and ClickHouse on an isolated bridge network.
  * **Graceful Lifespan Hooks:** Engineered process cleanup routines in `run_server.py` that dump table state to `db_dump/` and flush active worker buffers before SIGTERM exits.
  * **Production Health Probing:** Built multi-tier health endpoints (`/ping`, `/api/v1/health/ready`, `/api/v1/health/status`) to support Docker and Kubernetes liveness/readiness probes.

---

### 9. Code Reviewer
* **Primary Accountability:** Enforcing code standards, readability, single responsibility principle, preventing dead code, and reviewing PRs with adversarial rigor.
* **Core Questions:**
  * *"Is this function doing more than one thing?"*
  * *"Are exceptions being caught and swallowed silently?"*
* **NetVisor Actions & Decisions:**
  * **Dead Code Identification:** Audited 1,262 definitions, identifying unwired helper functions (e.g. `_detect_local_mac`, `_verify_port_listening`) and documenting their status in `dead_code_report.md`.
  * **Rejection of Mock Substitutes:** Enforced that production routes must return real database data rather than static JSON stubs.
  * **Strict Typing & Linting:** Enforced Pydantic type hints across API request handlers to fail fast on invalid payloads.

---

### 10. Technical Writer
* **Primary Accountability:** User-facing documentation, architecture diagrams, runbooks, Architectural Decision Records (ADRs), and interview defense notes.
* **Core Questions:**
  * *"Can a new engineer clone the repo and get it running in 10 minutes?"*
  * *"Can the owner explain and defend every major architectural trade-off?"*
* **NetVisor Actions & Decisions:**
  * **Project Logbook Maintenance:** Continuously documented daily engineering progress and evidence in `docs/project-logbook.md`.
  * **Architectural Decision Records (ADRs):** Recorded trade-offs (e.g. RS256 vs HS256, Redis memory streams vs MySQL row locks) in structured ADR format.
  * **Defense Preparation:** Formulated plain-language explanations for complex topics (e.g. DPI proxy mechanics, JA4 hashing, hybrid device identity).

---

## 3. Team Conference: Architectural Debate & Resolution

Before making substantial changes, the team holds an evidence-based conference to resolve disagreements:

| Topic | Disagreement | Resolution & Decision |
| :--- | :--- | :--- |
| **Frontend Strategy** | Frontend Lead wanted to finish porting routes into `frontend-v2`. Tech Lead noted that `frontend/` is already 100% functional and deployed in Docker. | **Decision:** Follow owner directive. Freeze `frontend-v2`. Invest 100% of effort into polishing and maintaining `frontend/`. |
| **Flow Ingestion Storage** | Backend Engineer proposed inserting every flow log directly into MySQL. Database Engineer objected due to row-lock contention and write amplification. | **Decision:** Buffer incoming flows in Redis streams; flush in micro-batches via the dedicated background `flow_writer` worker. |
| **Agent Authentication** | Backend Engineer wanted simple Bearer API keys. Security Engineer rejected this due to replay attack risk on unencrypted networks. | **Decision:** Enforce HMAC-SHA256 request signing with dynamic nonces and timestamps (`X-Signature`, `X-Nonce`, `X-Timestamp`). |
| **Packet Parsing Performance** | Developer proposed using Scapy for all packet decoding. DevOps profiled Scapy on Windows and found it introduces a 15x CPU bottleneck. | **Decision:** Use `dpkt` and native `struct` unpacking for hot-path packet parsing; keep Scapy only as a fallback. |

---

## 4. The Engineering Workflow: How the Team Executes

When tackling any task, the team follows a 6-step cycle:

```
  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
  │ 1. Discover ├────►│  2. Propose  ├────►│  3. Review  │
  │  & Measure  │     │  & Design    │     │  (Debate)   │
  └─────────────┘     └──────────────┘     └──────┬──────┘
                                                  │
  ┌─────────────┐     ┌──────────────┐            │
  │ 6. Commit   │◄────┤  5. Verify   │◄───────────┘
  │  & Document │     │   (Tests)    │     4. Implement
  └─────────────┘     └──────────────┘
```

1. **Discover & Measure:** Never change code without opening it first. Profile bottlenecks and reproduce bugs before writing a fix.
2. **Propose & Design:** State options, trade-offs, and estimated effort (S/M/L).
3. **Review & Debate:** Challenge weak assumptions. Prefer boring, proven technologies over trendy libraries.
4. **Implement Minimally:** Make focused, reviewable edits. Keep the application runnable after every step.
5. **Verify with Real Output:** Run automated tests and health checks. Never say "done" without real command output.
6. **Commit & Document:** Write a Conventional Commit (`feat:`, `fix:`, `refactor:`), push to remote, and record findings in `docs/project-logbook.md`.

---

## 5. Plain-Language Engineering Glossary

* **Idempotency:** An operation that produces the same result no matter how many times it is run (e.g. running database migrations repeatedly without duplicating tables).
* **Ingestion Backpressure:** When incoming data arrives faster than the system can write it. Solved by queuing in memory (Redis) and rejecting or throttling excess requests gracefully (HTTP 429).
* **mTLS (Mutual TLS):** Both client and server present cryptographic certificates to verify each other's identity before exchanging data.
* **JA4 Fingerprint:** A compact hash of TLS ClientHello parameters that identifies the client software/malware family regardless of IP address changes.
* **AST Redaction:** Parsing code or structured data into an Abstract Syntax Tree to systematically find and scrub passwords or tokens without corrupting syntax.
* **WireGuard 148B / 92B Heuristics:** Identifying WireGuard VPN tunnels by detecting fixed-size initiation (148 bytes) and response (92 bytes) handshake packets.
