# NetVisor Project Logbook

## Purpose

This logbook records the day-wise evolution of NetVisor as an academic major project. It is written as an engineering diary rather than a phase checklist: what was built, what problem appeared, what was learned, and how the system changed.

The history was reconstructed from:

- Archived source snapshots in `C:\Users\prem\NetworkZip`
- Recovered historical files in `C:\Users\prem\Network\old files`
- Git commit history
- Current source code and technical documentation
- Manual test sessions and screenshots recorded during development

Some older entries are reconstructed from file modification dates and archive contents. Those entries are marked as reconstructed where the exact development note was not available.

Security note: old snapshots contain local configuration files and credentials. This logbook intentionally excludes all secret values.

## Project Summary

NetVisor is a self-hosted cyber-security workspace for monitoring devices, network activity, application usage, browser inspection evidence, VPN indicators, and threats.

The current architecture separates visibility into two paths:

- **Managed endpoint agent:** richer telemetry and opt-in browser DPI evidence for systems where the agent is installed.
- **Gateway sensor:** metadata-only visibility for BYOD and hotspot-connected devices without collecting private payloads.
- **Backend and worker services:** authenticated ingestion, processing, storage, alert evaluation, and API delivery.
- **React analyst console:** understandable dashboards for devices, applications, browser evidence, threats, logs, VPN indicators, and operational health.

## Evolution at a Glance

| Period | Main Outcome |
| --- | --- |
| October-November 2025 | Built the first Flask authentication prototype, requirements documents, activity pages, and scanner experiments. |
| December 2025-January 2026 | Added ML and VPN-analysis tooling, local packet-capture testing, interface debugging, and early frontend-agent-server separation. |
| February 2026 | Restored the project into Git, improved security controls, modularized the application, and added pooled batch collection. |
| March-April 2026 | Introduced the modern FastAPI, React, agent, gateway, shared-runtime architecture with DPI and gateway privacy boundaries. |
| May 2026 | Hardened enrollment and ingestion, tested DPI and Windows hotspot gateway collection, and redesigned telemetry pages for readability. |
| June 2026 | Modularized the security detection engines registry, hardened concurrency safety, and built a decoupled real-time event-driven ingestion pipeline with Socket.IO dashboard broadcasts. |
| July 2026 | Hardened mTLS revocation checks, implemented transparent browser intercepting and sensitive data redaction, secured Windows Service execution, and optimized ingestion throughput with partitioned locks. |
| August 2026 | Modernized the Web Inspection dashboard, resolved critical SQL Injection, connection leak, and JWT algorithm confusion vulnerabilities, compiled the service manager, and documented architecture flows and justifications. |

---

## Architecture Evolution

| Version | Stack / Components | Key Focus |
| :--- | :--- | :--- |
| **Version 1** | Flask + MySQL | Basic user auth and prototype network table views. |
| **Version 2** | Flask + Zeek | Live network visibility via passive Zeek log ingestion. |
| **Version 3** | Frontend + Agent + Server | Component decoupling into separate directories. |
| **Version 4** | FastAPI + React | API performance upgrades and interactive analyst dashboard. |
| **Version 5** | Agent + Gateway + Backend | Differentiated managed agent vs metadata-only gateway collection. |
| **Version 6** | Modular Engine Platform | Unified detection engines registry with concurrency controls. |
| **Version 7** | Hardened Production System | SQL Injection whitelisting, mTLS non-blocking checks, and RS256 authentication. |

---

# PHASE 1 – FOUNDATION (Oct 2025 – Nov 2025)

> **Goal:** Build a basic network monitoring prototype.
> 
> **Key Achievements:**
> - Flask authentication
> - MySQL integration
> - Activity dashboard
> - Initial scanner
> 
> **Key Learning:** *A security platform requires more than user management.*

---

## 2025-10-22 - Initial Working Prototype

**Work completed**

- Created the earliest recovered Python prototype.
- Implemented user registration and login using Flask.
- Added password hashing and role-based redirection.
- Added an early registration page.

**Problem or learning**

- The first version was an authentication prototype, not yet a network-security platform.
- Local database handling and application secrets were still embedded directly in the code.

**Evidence**

- Recovered `NTUSER.DAT` and `NTUSER.py` files modified on 2025-10-22.
- Archived `Network Analyser.py` and `ne.py` prototypes.

## 2025-10-29 - First Formal Documentation

**Work completed**

- Prepared the first working report for the Network Analyzer tool.
- Created the first NetVisor Software Requirements Specification document.

**Problem or learning**

- The project needed a clearer definition beyond a basic login system.
- Documentation began shaping the project into a security-monitoring workspace.

**Evidence**

- Recovered `Network_Analyzer_Tool_Working_Report.docx`.
- Recovered `NetVisor_SRS_Document.docx`.

## 2025-10-30 - Requirements Refinement

**Work completed**

- Updated the NetVisor SRS document.

**Problem or learning**

- The project scope was evolving and needed repeated clarification before implementation expanded.

**Evidence**

- Recovered `NetVisor_SRS.docx`.

## 2025-11-17 - Activity Dashboard Experiments

**Work completed**

- Added early activity-page HTML and JavaScript files.
- Began experimenting with dashboard-style data presentation.

**Problem or learning**

- Raw monitoring data is difficult to understand without structured UI views.

**Evidence**

- Recovered `activity.html`, `activity.js`, and related template files.

## 2025-11-18 - First NetVisor Package

**Work completed**

- Created early packaged NetVisor archives.
- Started moving from isolated prototype files toward a shareable project folder.

**Problem or learning**

- Packaging exposed the need for cleaner separation between source files, generated files, and environment-specific configuration.

**Evidence**

- Recovered early `NetVisor.zip` and related archive files.

## 2025-11-19 - Database and Login Iterations

**Work completed**

- Iterated repeatedly on the Flask application.
- Tested MySQL-backed login and registration.
- Expanded the application beyond the earliest SQLite-style prototype.

**Problem or learning**

- Authentication, route naming, and database connectivity required multiple fixes.
- Older snapshots still contained hardcoded local credentials, which later motivated configuration hardening.

**Evidence**

- Multiple recovered `app.py` versions.
- Archived `ne.py` MySQL prototype.

## 2025-11-20 - Packaging and Bug Fixes

**Work completed**

- Created updated runnable and fixed project archives.
- Continued stabilizing the Flask application.

**Problem or learning**

- Frequent archive copies made recovery useful but also made project structure harder to manage.

**Evidence**

- Recovered fixed and runnable zip archives modified around 2025-11-20.

## 2025-11-23 - Activity Data Tracking

**Work completed**

- Added activity data exports and continued dashboard experiments.

**Problem or learning**

- Network activity needed aggregation before it could become useful to an analyst.

**Evidence**

- Recovered activity-related files and CSV artifacts.

## 2025-11-24 - Packaged Ready Version

**Work completed**

- Prepared another ready-to-run project package.

**Problem or learning**

- The project was functional enough to package, but still monolithic and difficult to maintain.

**Evidence**

- Recovered packaged project archives from late November 2025.

## 2025-11-25 - Scanner Modularization

**Work completed**

- Added scanner, configuration, and run-entry files.
- Began separating collection logic from web application logic.

**Problem or learning**

- A network monitoring tool cannot scale cleanly if packet collection, database writes, and UI routes all remain inside one file.

**Evidence**

- Recovered `scanner.py`, `config.py`, and `run.py`.

## 2025-11-26 - Early Modular NetVisor Layout

**Work completed**

- Introduced a more structured NetVisor project directory.
- Continued splitting code into reusable modules.

**Problem or learning**

- The project needed stable module boundaries before threat detection and UI work could grow safely.

**Evidence**

- Recovered `NetVisor` project folders and modular source files.

## 2025-11-27 - Flask SOC Workspace Expansion

**Work completed**

- Expanded the project into a more complete Flask-based SOC workspace.
- Added modular blueprints, database services, logging helpers, input sanitization, Docker-related files, and CI files.
- Added Zeek log ingestion for connection, DNS, and HTTP activity.
- Added early VPN detection using common ports and protocol indicators.

**Problem or learning**

- Simple port-only VPN detection creates false positives and needs richer evidence.
- Monolithic polling and database operations needed more careful performance handling.

**Evidence**

- `n3.zip`.
- Recovered modular Flask package.
- Inspected historical `app.py` implementation using Zeek log tailing.

## 2025-11-29 - Snapshot and Cleanup Work

**Work completed**

- Created another stable archive snapshot.
- Continued consolidating project files.

**Problem or learning**

- Repeated snapshots were useful for backup, but a proper Git-based workflow was becoming necessary.

**Evidence**

- `Network4.zip`.

---

### Phase 1 Reflection

**What Went Well:**
- Established initial Flask route blueprints, user session management, and basic database interaction.
- Designed early network activity layout using static HTML/JS tables.

**Challenges:**
- The prototype was monolithic, making it hard to decouple networking from core UI logic.
- Hardcoded local credentials in early file snapshots highlighted a need for secure configuration management.

**Next Phase Goals:**
- Explore packet capture programmatic engines (Scapy) and initial VPN/ML detection models.
- Modularize the repository into separate component folders.

---

# PHASE 2 – NETWORK VISIBILITY (Dec 2025 – Jan 2026)

> **Goal:** Understand network traffic and VPN detection.
> 
> **Key Achievements:**
> - Packet capture experiments
> - VPN detection research
> - ML evaluation
> - Interface debugging
> 
> **Key Learning:** *Network visibility is challenging due to adapter diversity.*

---

## 2025-12-01 - Project Report Updates

**Work completed**

- Updated written reports describing the system.

**Problem or learning**

- Documentation needed to follow the code as the project shifted from a simple analyzer into a broader monitoring platform.

**Evidence**

- Recovered report documents.

## 2025-12-03 - Source and Report Archival

**Work completed**

- Archived code and report materials together.

**Problem or learning**

- Archival was still manual and included mixed source, reports, and generated files.

**Evidence**

- `Network.7z` and recovered report archives.

## 2025-12-24 - ML and VPN Analysis Tooling

**Work completed**

- Added ML-related tooling and a VPN model artifact.
- Added extraction, training, and sessionization utilities.
- Improved modularity around scanner and ML logic.

**Problem or learning**

- VPN detection needed to combine signatures, sessions, and heuristics rather than relying only on ports.
- Model quality depends on representative traffic and careful false-positive tuning.

**Evidence**

- `Networkdr.zip`.
- Archived tools such as extraction, training, and sessionization scripts.

## 2026-01-03 - Blueprint Documentation

**Work completed**

- Created updated architecture and blueprint documentation.

**Problem or learning**

- The project had grown enough that design documents were necessary to coordinate implementation.

**Evidence**

- Recovered blueprint report and archive files.

## 2026-01-10 - Packaged Application Snapshot

**Work completed**

- Created another packaged version of the network monitoring application.

**Problem or learning**

- Packaging consistency and environment setup remained important operational concerns.

**Evidence**

- `Nnnetwork.zip`.

## 2026-01-17 - Interface Debugging and Local Database Testing

**Work completed**

- Added interface-debugging utilities.
- Tested local database and local application copies.
- Continued experimenting with template and static assets.

**Problem or learning**

- Network interface selection is environment-specific, especially on Windows systems with Wi-Fi, hotspot, Bluetooth, and virtual adapters.

**Evidence**

- Recovered `debug_ifaces.py`, `database.db`, templates, and static assets.

## 2026-01-21 - Local Packet Capture Verification

**Work completed**

- Generated a local capture log for traffic inspection.

**Problem or learning**

- Captured packet data needed filtering and aggregation before it could be presented clearly.

**Evidence**

- Recovered `local_capture_log.csv`.

## 2026-01-31 - Frontend, Agent, and Server Separation

**Work completed**

- Introduced separate `frontend`, `agent`, and `server` areas.
- Moved further away from a single-file prototype.

**Problem or learning**

- Separating components made development cleaner but introduced integration and startup-order challenges.

**Evidence**

- Recovered `frontend`, `dashboard`, `agent`, and `server` folders.

---

### Phase 2 Reflection

**What Went Well:**
- Programmatic capture scripts successfully analyzed local DNS and TCP handshake sequences.
- Decoupled code logic into separate `agent`, `server`, and `frontend` folders.

**Challenges:**
- Windows network adapter diversity caused frequent capture failures due to improper Npcap interface strings.
- Signature-only VPN detection generated high false positives.

**Next Phase Goals:**
- Migrate the backend to FastAPI and frontend to React for performance and maintainability.
- Move the codebase to Git for proper version tracking.

---

# PHASE 3 – ARCHITECTURE MODERNIZATION (Feb – Mar 2026)

> **Goal:** Transform the prototype into a scalable platform.
> 
> **Key Achievements:**
> - Git migration
> - FastAPI migration
> - React frontend
> - Agent-server separation
> 
> **Key Learning:** *Scalability requires modular architecture.*

---

## 2026-02-06 - Dashboard Iteration

**Work completed**

- Continued dashboard layout experiments.

**Problem or learning**

- The UI needed to communicate security meaning, not only expose tables.

**Evidence**

- Recovered dashboard HTML files.

## 2026-02-10 - Dashboard Refinement

**Work completed**

- Updated dashboard layouts and activity presentation.

**Problem or learning**

- Analyst readability remained a recurring requirement.

**Evidence**

- Recovered template and frontend files.

## 2026-02-11 - Frontend JavaScript Iteration

**Work completed**

- Updated JavaScript used by the activity interface.

**Problem or learning**

- Frequent direct frontend changes showed the need for a more maintainable React application.

**Evidence**

- Recovered JavaScript files.

## 2026-02-12 - Activity Interface Refinement

**Work completed**

- Continued activity-page frontend fixes.

**Problem or learning**

- Raw activity streams remained too noisy for normal users.

**Evidence**

- Recovered activity HTML and JavaScript snapshots.

## 2026-02-18 - Git Restoration and Security Baseline

**Work completed**

- Restored the SOC platform into Git.
- Added unit tests for vendor resolution.
- Replaced blocking sleep with asynchronous sleep in a settings API.
- Added admin authorization to sensitive endpoints.
- Removed dead code.
- Improved registration accessibility.

**Problem or learning**

- Git history, tests, and authorization controls were necessary to make changes safer.

**Evidence**

- Git commits from 2026-02-18.

## 2026-02-19 - Modular Refactor and Infrastructure Audit

**Work completed**

- Performed a major modular architecture refactor.
- Hardened connection pooling, mandatory secrets, and session security.
- Fixed import regressions and route mismatches.
- Cleaned binary caches and documented the project.

**Problem or learning**

- Large structural changes introduced route and import regressions that required end-to-end verification.

**Evidence**

- Git commits from 2026-02-19.
- `Network_X.zip`.

## 2026-02-22 - Database Pooling and Batch Collection

**Work completed**

- Improved database connection pooling.
- Added batch log collection.
- Improved logging, API security, session handling, and admin authorization.

**Problem or learning**

- Per-record ingestion is too expensive under sustained network traffic.

**Evidence**

- Git commits from 2026-02-22.
- `Network2.0.zip`.

## 2026-02-25 - Secret and Repository Cleanup

**Work completed**

- Cleaned tracked environment and snapshot files.

**Problem or learning**

- Secrets and machine-specific state must not be stored in source control.

**Evidence**

- Git history from 2026-02-25.

## 2026-02-26 - Archive Snapshot

**Work completed**

- Created a larger project archive after infrastructure changes.

**Problem or learning**

- Archive growth showed why generated state and dependencies should stay outside the source tree.

**Evidence**

- `Networkl.zip`.

## 2026-02-28 - Git Backup Snapshot

**Work completed**

- Preserved a Git backup snapshot.

**Problem or learning**

- Version control became the primary source of truth, while archives remained recovery points.

**Evidence**

- Recovered `.git.zip`.
- `Networkprev.zip`.

## 2026-03-03 - Pre-Restructure Checkpoint

**Work completed**

- Created a checkpoint before another major restructure.

**Problem or learning**

- The project was preparing to split collection responsibilities more clearly.

**Evidence**

- Git commit `pre-restructure`.

## 2026-03-04 - Full Project Snapshot

**Work completed**

- Created a large archive before the next architecture transition.

**Problem or learning**

- The snapshot size showed that runtime artifacts and dependencies still needed cleanup.

**Evidence**

- `Network222.zip`.

## 2026-03-09 - Environment Template

**Work completed**

- Added an environment example file.

**Problem or learning**

- Deployment requires explicit configuration without leaking real local secrets.

**Evidence**

- Recovered `.env.example`.

## 2026-03-15 - Backup Before Architecture Expansion

**Work completed**

- Preserved a large project backup.

**Evidence**

- `Network.zip`.

## 2026-03-19 - Additional Snapshot

**Work completed**

- Preserved another project snapshot during ongoing refactoring.

**Evidence**

- `net22.zip`.

## 2026-03-21 - SNI Storage Support

**Work completed**

- Added a database migration for Server Name Indication metadata in flow logs.

**Problem or learning**

- Domain-level metadata improves application classification without storing private packet payloads.

**Evidence**

- `20260321_add_flow_logs_sni.sql`.
- `Networkx3.zip`.

## 2026-03-22 - Multi-Component Architecture

**Work completed**

- Introduced the modern multi-component architecture.
- Added dedicated `app`, `frontend`, `agent`, `gateway`, and shared runtime areas.
- Added managed endpoint collection and metadata-only gateway collection paths.
- Added web inspection support and related database migration.

**Problem or learning**

- Managed devices and BYOD devices require different visibility boundaries.
- The gateway should provide network metadata without inheriting DPI payload inspection.

**Evidence**

- Git commit introducing the new architecture.
- `20260322_web_inspection.sql`.

## 2026-03-23 - Merge Stabilization

**Work completed**

- Resolved merge conflicts and stabilized the architecture transition.

**Problem or learning**

- Large cross-component changes require integration checks after conflict resolution.

**Evidence**

- Git merge and stabilization commits from 2026-03-23.

## 2026-03-24 - DPI Visibility and UI Performance

**Work completed**

- Improved managed endpoint DPI visibility.
- Improved device and application telemetry pages.
- Added performance optimizations and UI polish.

**Problem or learning**

- Capturing packet evidence is only half the work. It must be grouped and explained so the user can understand it.

**Evidence**

- Git commit `Phase 3: DPI visibility, performance optimizations, and UI polish`.

## 2026-03-26 - Security Hardening Migration

**Work completed**

- Added the first security-hardening database migration.

**Problem or learning**

- Production preparation requires schema-level support for stronger authentication and operational controls.

**Evidence**

- `20260326_security_hardening_phase1.sql`.

---

### Phase 3 Reflection

**What Went Well:**
- Successfully initialized Git repository and established safety baselines (authorization guards, connection pools).
- Completed FastAPI backend cutover and React frontend development.

**Challenges:**
- Splitting the system introduced circular dependency risks and integration issues on initial startup.
- Raw browser inspection log volumes created analytical clutter.

**Next Phase Goals:**
- Harden flow log ingestion and deduplicate redundant security alerts.
- Develop privacy-preserving gateway sensor capture paths.

---

# PHASE 4 – ENTERPRISE FEATURES (Apr – May 2026)

> **Goal:** Add security hardening and operational features.
> 
> **Key Achievements:**
> - Gateway architecture
> - DPI visibility
> - Enrollment system
> - Security migrations
> 
> **Key Learning:** *Privacy and visibility must be balanced.*

---

## 2026-04-16 - Gateway Security Migration

**Work completed**

- Added gateway-specific security schema support.

**Problem or learning**

- Gateway enrollment and sensor authentication need their own lifecycle, separate from endpoint-agent identity.

**Evidence**

- `20260416_gateway_security_phase1.sql`.

## 2026-04-17 - Runtime Schema Upgrade

**Work completed**

- Added runtime schema improvements for the next hardening stage.

**Evidence**

- `20260417_runtime_schema_phase2.sql`.

## 2026-04-18 - Flow Ingestion Hardening

**Work completed**

- Added flow-ingestion schema changes and additional hardening.

**Problem or learning**

- Ingestion needs buffering, deduplication, retry behavior, and controlled database pressure.

**Evidence**

- `20260418_flow_ingest_phase3.sql`.
- `20260419_flow_ingest_hardening_phase4.sql`.

## 2026-05-01 - Deployment and Enrollment Maturity

**Work completed**

- Improved repository hygiene and documentation.
- Added environment bootstrap documentation.
- Restored explicit lab-only LAN transport override.
- Improved sensor enrollment flow.

**Problem or learning**

- Development overrides must remain clearly separated from production defaults.

**Evidence**

- Git commits from 2026-05-01.

## 2026-05-02 - Search, Alert Deduplication, and ML Metadata

**Work completed**

- Optimized ingest baselines and alert processing.
- Hardened flow search and alert deduplication.
- Added ML-related metadata improvements.
- Added a flow-log search benchmark.

**Problem or learning**

- Search queries must remain index-friendly as telemetry grows.
- Repeated alerts need deduplication to avoid analyst fatigue and database pressure.

**Evidence**

- Git commits from 2026-05-02.
- `20260502_flow_search_alert_dedupe_indexes.sql`.

## 2026-05-03 - Telemetry Views, CI, and Scapy Compatibility

**Work completed**

- Polished device and application telemetry views.
- Improved CI dependencies and diagnostics.
- Fixed DNS answer parsing for newer Scapy behavior.
- Isolated deployment-bundle unit tests from frontend builds.

**Problem or learning**

- Dependency upgrades can break packet parsing behavior even when application code has not changed.

**Evidence**

- Git commits from 2026-05-03.

## 2026-05-05 - Role-Based Deployment Bundles

**Work completed**

- Produced separate documentation, agent, and gateway archives.

**Problem or learning**

- Server, agent, and gateway roles should be deployable independently.

**Evidence**

- Recovered `docs.zip`, `agent.zip`, `gateway.zip`, and `gateway.7z`.

## 2026-05-16 - Agent Hardening and Preflight Checks

**Work completed**

- Added agent hardening, preflight checks, health reporting, buffering code, enrollment controls, observability, and DPI governance improvements.
- Improved UI themes and operational visibility.

**Problem or learning**

- Code-level hardening is not complete until reconnect, offline buffering, and second-host deployment behavior are verified in real environments.

**Evidence**

- Git hardening commit from 2026-05-16.
- Current preflight and shared collector code.

## 2026-05-19 - Live DPI Browser Inspection Test

**Work completed**

- Tested managed endpoint browser inspection live.
- Observed Google Search, YouTube, ChatGPT, Google API, and other browser evidence.
- Verified that browser-derived evidence reached the device workspace.

**Problem found**

- The raw activity view was noisy because internal browser requests appeared alongside meaningful pages.
- A frontend rendering failure displayed the React recovery screen with a reboot-workspace action.
- This test motivated evidence grouping and a more understandable application-level view.

**Evidence**

- Manual test screenshots and server output from 2026-05-19.

## 2026-05-20 - Flow Truth Schema Upgrade

**Work completed**

- Added a flow-truth schema migration.

**Problem or learning**

- Application views should be derived from reliable flow records rather than UI guesses.

**Evidence**

- `20260520_flow_truth_phase4.sql`.

## 2026-05-27 - Real Agent Reliability Test

**Work completed**

- Ran the agent against the local backend.
- Verified registration retry behavior while the backend was unavailable.
- Verified eventual successful agent registration and DPI launcher creation.

**Problem found**

- Device synchronization returned HTTP 500 errors.
- Flow uploads experienced read timeouts, HTTP 429 rate limiting, and connection resets.
- Backend pressure and retry behavior still need production-level verification.

**Evidence**

- Manual `run_agent.py` logs from 2026-05-27.

## 2026-05-28 - Windows Hotspot Gateway Test

**Work completed**

- Tested the gateway using Windows Mobile Hotspot.
- Identified the hotspot subnet as `192.168.137.0/24`.
- Detected a connected OPPO phone at `192.168.137.4`.
- Corrected Windows Npcap adapter selection to use the `\Device\NPF_{...}` capture path.

**Problem found**

- The first selected adapter format caused an adapter-open error.
- After adapter selection was fixed, repeated backend upload connection resets remained visible.

**Evidence**

- Manual `run_gateway.py`, `ipconfig`, ARP output, and hotspot screenshots from 2026-05-28.

## 2026-05-29 - Gateway Detection and UI Readability

**Work completed**

- Improved gateway device discovery for hotspot-connected devices.
- Improved metadata-only application detection using domain and flow classification.
- Kept gateway visibility separate from endpoint DPI.
- Redesigned application coverage and application-detail pages for clearer interpretation.
- Added plain-language summaries, usage meaning, detection source, freshness, and suggested next actions.
- Verified frontend lint and production build successfully.

**Problem found**

- Gateway data can still appear more slowly than agent data.
- Backend reset and timeout behavior still needs hardening under repeated flow uploads.

**Evidence**

- Manual gateway and UI screenshots from 2026-05-29.
- Current React application pages and styles.

---

### Phase 4 Reflection

**What Went Well:**
- Built the metadata-only gateway sensor with secure LAN-transport overrides.
- Implemented robust admin-approved enrollment routines for agents.

**Challenges:**
- Large-scale telemetry queries triggered database slowdowns on older schemas.
- Scapy packet parsing behavior changed after updating system dependencies.

**Next Phase Goals:**
- Transform traditional detection services into a modular, registry-driven engine platform.
- Resolve VPN false positives caused by Google QUIC traffic.

---

# PHASE 5 – ENGINE PLATFORM (Jun 2026)

> **Goal:** Replace legacy detection logic with modular engines.
> 
> **Key Achievements:**
> - Device Engine
> - Threat Engine
> - VPN Engine
> - Registry Architecture
> - Risk Correlation
> 
> **Key Learning:** *Modular engines improve maintainability and testing.*

---

## 2026-06-01 - Historical Recovery and Logbook Reconstruction

**Work completed**

- Recovered 129 historical project-related Recycle Bin items non-destructively into `C:\Users\prem\Network\old files`.
- Preserved each recovered item in a separate numbered folder to avoid overwriting files with identical names.
- Created `_recovered_items_manifest.csv`.
- Reviewed source snapshots, archives, Git history, technical documents, and live-test notes.
- Created this academic engineering logbook.

**Problem or learning**

- The earliest recovered prototype artifacts date to 2025-10-22, although the main NetVisor development effort became clearly visible during November 2025.
- Historical folders include sensitive configuration and should remain local and excluded from Git.

**Evidence**

- `C:\Users\prem\Network\old files\_recovered_items_manifest.csv`.
- `C:\Users\prem\NetworkZip`.

---

## Current Implementation Status

### Implemented

- Managed endpoint agent with telemetry collection and opt-in browser DPI inspection.
- Metadata-only gateway for BYOD and hotspot-connected devices.
- FastAPI backend, worker processes, MySQL schema migrations, authenticated collection routes, and operational health endpoints.
- React analyst console for devices, applications, web inspection, threats, traffic, logs, VPN indicators, appearance, and settings.
- Application-level evidence grouping for clearer browser activity review.
- Device and application classification using flow metadata, domains, SNI, and DPI-derived evidence where appropriate.
- Agent and gateway enrollment, preflight checks, security hardening, deployment documentation, CI checks, and role-based bundle generation.
- Code-level buffering, retry, search optimization, alert deduplication, and flow-ingestion hardening support.

---

### June 2026 Summary

During June, the project transitioned from a traditional service-oriented detection model to a modular engine-based architecture. Device classification, threat detection, VPN detection, and risk correlation were migrated into independent engines, significantly improving maintainability, testability, and scalability.

---

## 2026-06-13 - Engine Foundations, Device & Threat Modularization

**Work completed**

- Implemented standard engine contracts (`Severity`, `Finding`, `EngineResult`, `BaseEngine`) under `shared/engine/` to decouple engine implementations from FastAPI routes.
- Migrated device classification to a dedicated, priority-driven `DevicePipeline` (`app/engines/device/pipeline.py`) incorporating mDNS service type advertisements, SSDP UPnP headers, OUI vendor lookups, DHCP Option 55 parameter lists, and conditional active probing.
- Created `SlidingWindowStore` under `app/engines/threat/state.py` to prune expired telemetry buckets.
- Implemented modular `PortScanDetector` to alert on 10 unique ports scanned within 10 seconds.
- Created `EngineRegistry` in `app/engines/registry.py` to handle dynamic registration, constructor injection of engine configs, and selective context execution.
- Rewrote the NDR correlation layer (`RiskEngine`), implementing exponential scoring decay, duplicate correlation alert suppression, and compounded host risk calculations.

**Problem found**

- Legacy active prober was blocking socket timeouts, slowing ingestion when encountering offline devices.
- Direct dictionary key access crashed when processing custom mocked list objects in testing.

**Solution or learning**

- Implemented safe float/int parsing and a generic `get_flow_field` wrapper to support both object attribute and dictionary key lookups.
- Bound active prober execution to occur only if device type is unknown and confidence is low (< 0.50).

**Evidence**

- Created unit tests in `tests/test_device_engine_parities.py` and `tests/test_threat_engine_parities.py` verifying 100% exact matches or enhancements over legacy behavior.

---

## 2026-06-16 - Fuzz Testing, Structured AI & Application JA4 Modernization

**Work completed**

- Added negative testing fixtures (`slow_port_scan.json`, `random_intervals.json`, `cdn_dns_queries.json`, `normal_large_upload.json`, `normal_vpn_usage.json`) and boundary conditions.
- Hardened Threat Engine detectors (brute force, beaconing, exfiltration) with robust try-except conversion blocks.
- Upgraded the AI Engine to return structured playbooks and MITRE mappings, using template playbooks.
- Modernized the Application Engine using **JA4 client TLS fingerprints** to classify tools like Curl, Python Requests, Go HTTP Client, Tor Browser, and Cobalt Strike C2 payloads.
- Integrated live ASN metadata lookup in `ApplicationService` to retrieve autonomous system names and numbers.

**Problem found**

- Fuzz tests with empty dictionaries, null fields, and out-of-bound integers caused unhandled ValueErrors and type crashes in the threat heuristics pipeline.

**Solution or learning**

- Implemented type-safe fallbacks (e.g. defaulting malformed ports to `0` and malformed byte counts to `0`) across all detectors to ensure engines fail gracefully.

**Evidence**

- Created `tests/test_engine_resilience.py` running fuzz checks across all registered registry engines. Verified zero failures.

---

## 2026-06-19 - Concurrency Hardening & VPN Engine Pipeline

**Work completed**

- Implemented thread safety using re-entrant locks (`RLock`) across all shared mutable stores, including `SlidingWindowStore`, `DNSTunnelingDetector`, `SuppressionStore`, and `ApplicationService`.
- Created Scapy-based programmatic PCAP generator `tests/helpers/pcap_generator.py` to write raw test captures.
- Modernized the VPN Engine, introducing a modular `VPNPipeline` orchestrating `ASNReputationDetector`, `TLS_Cert_Detector`, `OpenVPNSignatureDetector`, and `WireGuardHeuristicDetector` (verifying payload sizes `148`/`92`/`32` with bidirectional constraints).

**Problem found**

- Heavy concurrent ingest loads caused random `RuntimeError: dictionary changed size during iteration` crashes in state pruning loops.
- WireGuard heuristics triggered false alarms on standard unidirectional UDP flows.

**Solution or learning**

- Locked all pruning loops and return copies of stores using `RLock`.
- Enforced a strict sorted bidirectional IP/port pair tracking mechanism for WireGuard flows.

**Evidence**

- Created concurrency tests `test_concurrent_engine_execution` and `test_parallel_risk_correlation` in `tests/test_engine_resilience.py`.
- Verified WireGuard and OpenVPN PCAP captures propagate alerts correctly via `tests/test_pcap_pipeline.py`.

---

## 2026-06-20 - Ingestion Worker Cutover & Real PCAP Telemetry Validation

**Work completed**

- Refactored `_persist_batch_on_connection` in `FlowService` to natively run `registry.analyze_selective` and write alerts backward-compatibly to `alerts` and `device_risks`.
- Removed retired database queries (legacy device baselines and cache reads).
- Evaluated the ingest pipeline against real (non-synthetic) network traffic PCAP captures for WireGuard, OpenVPN, Tor exit nodes, and benign web browsing.

**Problem found**

- `SanitizedFlow` is a python dataclass, not a Pydantic model. Standard `.model_dump()` crashed.
- Circular dependency issues arose during FastAPI system startup when importing the registry.

**Solution or learning**

- Converted flows to dictionary contexts via `dataclasses.asdict()`.
- Implemented the registry as a lazy property inside `FlowService` to defer imports.

**Evidence**

- Verified score parity inside `tests/test_flowservice_registry_parity.py` and validated real datasets in `tests/test_real_traffic_evaluation.py`. All **437 tests** passed.

---

## 2026-06-21 - Live Verification, QUIC False Positive Tuning & Legacy Retirement (Today)

**Work completed**

- Resolved a critical dashboard VPN feed display bug where the VPN Page was empty because `vpn_score` and `vpn_provider` were missing from the DB breakdown.
- Fixed a false-positive OpenVPN opcode signature collision with standard Google QUIC (UDP 443) traffic.
- Permanently retired and deleted all legacy service files (`risk_engine.py`, `flow_analyzer.py`, `dns_analyzer.py`, `baseline_engine.py`, legacy tests, and adapters).

**Problem found**

- QUIC short headers (first byte `0x40` to `0x7F`) when right-shifted by 3 yielded `8` or `9`, which matched the OpenVPN UDP control frame opcode parser.
- The dashboard and system log endpoints filter VPN alerts using `breakdown.vpn_score > 0.3`. Since this key was omitted by the modular registry, alerts did not display.

**Solution or learning**

- Excluded shifted UDP opcode checks on ports 443/8443 if the payload starts with a QUIC short header byte (`0x40 <= first_byte <= 0x7F`).
- Injected `vpn_score`, `vpn_provider`, and `vpn_type` into the breakdown dictionary in `flow_service.py` to restore dashboard display.

**Evidence**

- Verified live dashboard display of WireGuard and OpenVPN.
- All remaining **427 tests** in the test suite pass cleanly with zero errors.

---

## 2026-06-25 - Real-time Telemetry, Queue Decoupling & Socket.IO Dashboard Integration

**Work completed**

- Created the thread-safe `LiveTelemetryStore` to maintain rolling 60s bandwidth, active devices, risk levels, and recent alerts, primed from MySQL historical tables on startup.
- Implemented `EventDispatcher` and `flow_ingestion_queue` (in-process event bus) to decouple HTTP flow ingestion from database persistence and threat processing, handling workers (Metrics, Threat, DB Writer, Audit) concurrently.
- Integrated `EventDispatcher` and `BroadcastScheduler` into the ASGI lifespan in `app/main.py` to start and stop workers cleanly.
- Implemented `BroadcastScheduler` to poll metrics from the live telemetry store and broadcast dashboard updates via Socket.IO to room `org:<org_id>` every 500ms.
- Refactored agent and gateway ingestion API routes to immediately enqueue incoming batches and return HTTP 202 Accepted.
- Refactored the dashboard `/overview` API endpoint to return cached live store counters (no-SQL hot path).
- Modified `DashboardPage.jsx` on the React frontend to replace the 15-second interval HTTP polling with real-time Socket.IO event listeners for `dashboard_update`.
- Updated `shared/collector/flow_manager.py` to support explicit lifecycle event types (`FLOW_NEW`, `FLOW_UPDATE`, and `FLOW_END`).
- Updated `FlowBase` and `FlowSummary` Pydantic models with `event_type` metadata.

**Problem found**

- Pytest collection errors occurred due to `@pytest.mark.asyncio` decorator mismatch with the anyio plugin configured in the codebase.
- Shared queue state from other test scenarios polluted the global `flow_ingestion_queue`, causing worker mock assertion failures in `test_event_dispatcher_queuing`.

**Solution or learning**

- Updated the test mark to `@pytest.mark.anyio` and added logic in `test_event_dispatcher_queuing` to drain the global `flow_ingestion_queue` before executing test flows.
- Mocked `time.time` using monkeypatch to test deterministic `FlowManager` state transitions via `_expire_flows()`.

**Evidence**

- Created and successfully passed unit tests in [tests/test_live_telemetry.py](file:///c:/Users/prem/Network/tests/test_live_telemetry.py) covering the telemetric store, event queue dispatcher routing, and flow manager event transitions.
- All **438 tests** in the test suite passed cleanly.

---

### Phase 5 Reflection

**What Went Well:**
- Decoupled detection into discrete engines (Device, Threat, VPN, Risk, AI) under a central `EngineRegistry`.
- Eliminated legacy code redundancy, verified engine resilience via fuzzing, and optimized database write-paths.
- Successfully resolved the OpenVPN opcode collision against Google QUIC traffic.

**Challenges:**
- Managing concurrency locks (`RLock`) on shared stores was critical to prevent race conditions during heavy ingestion.
- Dashboard integration required retrofitting specific database keys to maintain backward compatibility.

**Next Goals:**
- Continue refining ML heuristics and roll out agent platform to production systems.

---

## Major Engineering Challenges Solved

### 1. VPN False Positives (OpenVPN vs. QUIC)
- **Problem:** Google QUIC traffic over UDP port 443 triggered false alarms in the OpenVPN opcode signature parser because QUIC short headers right-shifted by 3 yielded bytes `8` or `9`, matching the OpenVPN control frames.
- **Solution:** Added protocol-aware checks to exclude packet evaluations on ports 443/8443 if the payload matches a QUIC short header byte range (`0x40 <= first_byte <= 0x7F`).

### 2. Windows Adapter Selection
- **Problem:** Npcap on Windows devices lists multiple virtual, Bluetooth, and inactive network adapters, causing application crashes on startup when opening invalid capture strings.
- **Solution:** Normalized interface selection, checking for active loopback or WLAN configurations and validating capture paths via `\Device\NPF_{...}` before launching listeners.

### 3. Circular Imports on Startup
- **Problem:** Dynamic registry configurations and service instantiation caused circular import dependencies during FastAPI initialization.
- **Solution:** Defer engine registry imports by referencing the registry as a lazy property inside the data service layer (`FlowService`).

### 4. Concurrent Processing Crashes
- **Problem:** High-volume traffic ingestion caused concurrent write/read race conditions on shared stores, yielding `RuntimeError: dictionary changed size during iteration`.
- **Solution:** Wrapped all shared memory lookups, sliding-window storage, and suppression pipelines in re-entrant locks (`RLock`) to ensure thread-safe operations.

### 5. Dashboard Readability
- **Problem:** Raw network session streams cluttered the console, causing analyst fatigue and UI lag.
- **Solution:** Introduced application-level evidence grouping and formatted data logs to group individual web sessions under high-level parent assets.

---

## Visual Development Timeline

Below is a curated series of screenshots capturing the project's user interface evolution:

- **Figure 1: Early Flask Login Page**  
  *Initial Flask authentication layout featuring secure password validation and role redirection.*
- **Figure 2: First Activity Dashboard**  
  *Early HTML/JS design displaying raw IP traffic and basic table layouts.*
- **Figure 3: FastAPI Migration & React Console**  
  *Modern modular layout showing the transitioned React console and interactive grid dashboard.*
- **Figure 4: Gateway Device Detection**  
  *The updated device console showcasing metadata-only discovery of hotspot-connected BYOD assets.*
- **Figure 5: Modern React Analyst Console**  
  *The completed high-fidelity analyst workstation showing live status telemetry, active threat alerts, and correlated risk scores.*

---

## Conclusion

NetVisor started as a simple Flask authentication prototype on 22 October 2025 and evolved into a modular, high-fidelity cyber-security workspace consisting of:
- **FastAPI backend:** Serves as the ingestion and orchestration engine, handling telemetry, alerts, and operational status.
- **React analyst console:** A modern dashboard offering unified workspace visualization across network nodes.
- **Managed endpoint agent:** Provides deep device details and granular DPI browser inspection capabilities.
- **Gateway sensor:** Collects metadata-only network flows from BYOD and hotspot-connected assets, maintaining user privacy.
- **Modular detection engines:** Decouples device, threat, VPN, and AI operations into a registry-driven plug-and-play architecture.
- **Risk correlation framework:** Correlates multiple independent indicators into host risk scores using exponential decay.

This project provided deep, hands-on experience in networking, systems security, backend scalability, modern frontend architectures, and software engineering best practices.

---

## 2026-07-07 - Ingestion Pipeline Alignment & Security Hardening

**Work completed**

- Refactored `flow_writer_worker` Redis Stream consumer in `flow_service.py` to deserialize dictionary payloads into Pydantic `FlowBase` objects using `FLOW_BATCH_ADAPTER.validate_python`.
- Consolidated the persistence layer: removed redundant database writer (`_db_writer_worker`) and threat checker (`_threat_worker`) from `EventDispatcher`. The dispatcher now only manages in-memory live metrics (`_metrics_worker`) and auditing.
- Integrated alert updates and Prometheus metrics into the single `flow_writer_worker` persistence path, safely getting `lastrowid` in case of mocked DB cursors.
- Standardized agent ingestion: routed `/api/v1/agents/batch` directly through `flow_service.buffer_flows()`.
- Gated `ChaosMiddleware` under a new configurable `CHAOS_ENABLED` settings flag.

**Problem found**

- Redis messages loaded as dictionaries caused `getattr` sanitization checks to return `None`, silently dropping all stream telemetry.
- Overlapping persistence loops in `EventDispatcher` created db transaction conflicts and write races.
- Lack of security gating allowed any client to request simulated DB failure via headers.

**Solution or learning**

- Enforce a single write path in background workers. Let the dispatcher handle only real-time in-memory counters to decouple telemetry reads and writes.
- Enforce early parsing of telemetry payloads into verified schemas (`FlowBase`).

**Evidence**

- Ran `pytest` testing suite. All 446 unit and integration tests passed cleanly.

---

## 2026-07-11 - DPI Integration, Windows Service Registry Hardening, and Self-Healing CA

**Work completed**

- **UI & Schema Alignment:** Updated `web_schema.py` and `web_inspection_service.py` to map and expose status parameters (`browser_launcher_deprecated`, `trust_scope`, `trust_store_match`, `key_protection`) to the frontend.
- **Frontend UI Setup:** Updated `DpiSetupGuide.jsx` to display a "Local Capture Mode Active" banner when transparent browser traffic interception is active.
- **Windows Service Registry Hardening:** Updated the C# service manager `service_controller.cs` to dynamically parse Python home from `pyvenv.cfg` and inject environment variables (`SystemRoot`, `PATH`, `PYTHONPATH`) into the registry, preventing background service startup timeouts.
- **Self-Healing Certificates:** Implemented DPAPI context-aware self-healing logic in `ensure_ca_files()` inside `cert_manager.py` to automatically regenerate CA certificates when running contexts change (e.g. from user account to `LocalSystem`).
- **Transparent Local Browser Interception:** Configured transparent interception mode for Chrome, Edge, and Firefox at the OS level via `NETVISOR_DPI_CAPTURE_MODE=local_browsers`.
- **Sensitive Data Redaction:** Added sensitive credentials and authorization headers redaction in `redaction.py` and `mitm_addon.py`. Enforces hashing/redacting of cookies, authorization tokens, Fernet tokens, JWTs, and sensitive query keys.
- **Production-Grade Security Hardening:** Refactored rate limiting to use Redis-backed sliding window logs with an in-memory fallback, implemented spoofing-resistant IP resolution via `resolve_source_ip` using a `TRUSTED_PROXIES` whitelist, enabled secure-only cookies in production environments, enforced strict JWT claims verification (`iss`, `aud`, `iat`, `jti`), injected HTTP security headers (HSTS, CSP, etc.), and redacted tracebacks/errors before logging.

**Problem found**

- Virtual/inactive Windows network adapters caused SCM start timeouts (`%%1053`).
- DPAPI-encrypted private keys conflicted between user account context and `LocalSystem` service context, throwing `FileNotFoundError` or decryption errors.
- Unconditional trust of `X-Forwarded-For` and in-memory rate limiting allowed IP spoofing and clustered rate-limit bypass.

**Solution or learning**

- Parsing the Python home path dynamically and passing it to the SCM registry preserves SCM environment context.
- Self-healing certificates automatically handle user-to-system security context transitions.
- Source IPs must only be resolved from headers when the direct peer is a trusted proxy.

**Evidence**

- Background Windows service successfully runs under `LocalSystem`.
- Over 700+ browser events successfully intercepted and written to `web_events` table.
- Passed local rate limiting and security headers validations. Commits `41372df018`, `858ff060ec`, and `ea7d2c1e8f` in Git.

---

## 2026-07-12 - RemixIcon Local Bundling & Logo Config

**Work completed**

- **Local Asset Provisioning:** Bundled the RemixIcon stylesheet and font files locally within the frontend build structure instead of loading them from public CDN endpoints.
- **Antigravity Logo Config:** Added custom logo visual settings for branding consistency in air-gapped analyst workstations.

**Problem found**

- Deploying NetVisor in offline, proxied, or air-gapped corporate environments caused missing icons and styling glitches due to blocked external CDN requests.

**Solution or learning**

- Bundling static assets locally guarantees application visual parity and UI completeness across all network contexts.

**Evidence**

- Verified rendering of RemixIcons offline. Commit `d7e5394282f` in Git.

---

## 2026-07-21 - Performance & Concurrency Hardening (Partitioned Locks & Ingestion Pool)

**Work completed**

- **Partitioned Concurrency Locks:** Refactored `live_telemetry_store.py` and `audit_service.py` to use partitioned locks indexed by organization ID (`defaultdict(threading.Lock)`). This removes the bottleneck of a single global lock during multi-tenant updates.
- **Dedicated DB Executor:** Added a `ThreadPoolExecutor` (`self._db_executor = ThreadPoolExecutor(max_workers=4)`) in `FlowService` to offload blocking MySQL writes and Redis Stream calls from the FastAPI event loop.
- **Deadlock Resilience:** Implemented a retry wrapper for MySQL deadlock error code `1213` in `_sync_persist_batch` with backoff logic.
- **Bulk Ingestion:** Optimized query patterns using batch inserts and `FOR UPDATE SKIP LOCKED`.

**Problem found**

- Concurrent multi-tenant ingestion spikes led to global lock contention, resulting in high event loop lag.
- Overlapping subnet updates from multiple agents caused MySQL InnoDB transaction overlaps and deadlocks, rolling back ingestion tasks.

**Solution or learning**

- Tenant-based lock partitioning prevents global lock bottlenecks. Dedicated DB threads preserve FastAPI asyncio thread loop responsiveness.

**Evidence**

- Sustained concurrent ingestion tests completed without deadlock failures or event loop blocks. Commit `164356ab62` in Git.

---

## 2026-08-02 - Web Inspection Layout & UI Null-Safety

**Work completed**

- **Tabbed Layout:** Redesigned the Web Inspection DPI dashboard on the React frontend using a tabbed structure (Active Telemetry, URL Log, Payload Snippets, Setup Guide).
- **Device Null-Safety:** Added defensive rendering guards on devices views to handle missing/empty properties safely.

**Problem found**

- The DPI dashboard was cluttered and difficult to navigate. In addition, devices without complete baseline telemetry caused React page crashes due to null properties.

**Solution or learning**

- Segmenting complex telemetry grids into tabs improves analyst workflow efficiency. All UI components rendering external data must have fallback defaults.

**Evidence**

- Verified React app compilation and runtime safety. Commit `1f966b5863` / `d55a6fb469` in Git.

---

## 2026-08-11 - Project Restructuring & Phase 1 Security Fixes

**Work completed**

- **Project Restructuring:** Cleaned up code layout and moved historical configuration artifacts to standardized directories.
- **SQL Injection Remediation:** Parameterized dynamic table counts, CSV exports, and database resets in `system_service.py` and `flow_service.py`, using strict whitelists of allowed table and filter column names.
- **mTLS Connection Leak Fix:** Implemented cache-based serial revocation lookups (5-minute TTL) inside `mtls_middleware.py` and executed the query asynchronously in a thread pool via `anyio.to_thread.run_sync()`.
- **JWT Authentication Migration:** Replaced symmetric `HS256` token signing with asymmetric `RS256` in `security.py`, adding PEM key loaders and validating `iss`, `aud`, `iat`, and `jti` claims.
- **Service Manager CLI:** Added the compiled `netvisor_manager.exe` (built from `service_controller.cs`) to facilitate agent management on Windows test nodes.

**Problem found**

- Security audit identified SQL injection paths in maintenance tools, DB connection starvation in mTLS middleware under concurrent requests, and algorithm confusion vulnerability in authentication tokens.

**Solution or learning**

- Whitelisting column/table names is necessary for dynamic SQL queries. Asymmetric keys prevent token forging even if application secrets are exposed.

**Evidence**

- Successfully executed security stress tests; all unit and integration tests passed cleanly. Commit `c4b005e7bb` and `fbf077375b` in Git.

---

## 2026-08-13 - Flow Architecture Diagrams & Tech Stack Justification

**Work completed**

- **Architecture Documentation:** Authored a comprehensive flow diagram in `docs/project_flow_diagram.md` illustrating data routing from agents/gateways, processing via the async event dispatcher and modular engines, and Socket.IO broadcast rooms.
- **Technology Stack Justification:** Prepared the `docs/reports/technology-stack-report.md` detailing backend/frontend libraries and justifying the use of programmatic Python modules (Scapy, mitmproxy) for packet capture and DPI over standalone heavy tools like Wireshark.

**Problem found**

- Evaluators required clear architecture specifications and a technical justification for chosen capture methodologies rather than manual Wireshark packet capture.

**Solution or learning**

- Programmatic capturing and custom parsing allow real-time multitenant analytics, alerts correlation, and automation which manual tools cannot provide.

**Evidence**

- Generated `docs/project_flow_diagram.md` and `docs/reports/technology-stack-report.md`.

---

## 2026-08-16 - Logbook Update & Project Synthesis

**Work completed**

- **Logbook Synchronization:** Consolidated and updated the project logbook with all past design developments, performance updates, layout refactorings, security remediations, and documentation sprints from July and August 2026.
- **Project Documentation Review:** Conducted a comprehensive audit of current source configurations and walkthrough files to align development logs.

**Problem found**

- The academic project logbook had fallen out of sync with actual engineering progress since early July 2026.

**Solution or learning**

- Maintain documentation incrementally to match actual repository commit history.

**Evidence**

- Verified changes inside `docs/project-logbook.md`.

---

## 2026-08-20 - NetVisor Android Mobile App & Full Web Parity

**Work completed**

- **Mobile Application Architecture:** Initialized and structured the native Android application (`Android_Application`) using modern Android Jetpack Compose, Material 3, Coroutines, StateFlow, Kotlinx Serialization, and Retrofit/OkHttp.
- **Cyberpunk UI & Branding:** Built custom glassmorphic UI components (`GlassCard`, `GlassSurface`, `GlassButton`, `StatusBadge`, `FloatingBottomNavBar`) and branded the application as "NetVisor" with custom vector shield launcher icons (`ic_launcher_background.xml`, `ic_launcher_foreground.xml`, `ic_netvisor_logo.xml`).
- **Compose Blur Fix:** Diagnosed and resolved a render-shader bug where Compose `Modifier.blur(20.dp)` on parent containers caused complete illegibility on Android 12+ (API 31+). Replaced with high-contrast translucent cyber gradients and glowing cyan borders.
- **Pre-filled Default Authentication:** Configured `LoginScreen.kt` with default demo credentials (`admin` / `NetVisor!DemoAccess99`) and interactive 1-tap switcher chips for `Admin` and `Operator` accounts.
- **Full Web Platform Parity:**
  - `HomeScreen.kt` / `HomeViewModel.kt`: Live operational health status, active threat metrics, 24h traffic volume, and real-time security activity stream.
  - `NetworkScreen.kt` / `NetworkViewModel.kt` & `DeviceDetailsScreen.kt`: Searchable device inventory with online indicators, OS badges, and deep risk-score factor inspection.
  - `ThreatsScreen.kt` / `ThreatsViewModel.kt`: Live incident alerts with severity filtering (`Critical`, `High`, `Medium`, `Low`).
  - `DpiScreen.kt` / `DpiViewModel.kt`: Deep Packet Inspection decoder status and real-time inspectable HTTP/TLS web flows with risk classification.
  - `AppsScreen.kt` / `AppsViewModel.kt`: Application category tagging (Streaming, Social, Web, Work), byte volumes, and flow counts.
  - `VpnScreen.kt` / `VpnViewModel.kt`: Heuristic detection of encrypted VPN/Proxy tunnels (WireGuard, OpenVPN, IPsec) and endpoint IPs.
  - `AgentsScreen.kt` / `AgentsViewModel.kt`: Fleet monitoring of enrolled collector agents, versions, OS families, queue depths, and heartbeat status.
  - `LogsScreen.kt` / `LogsViewModel.kt`: Real-time network flow logs (`src_ip:port -> dst_ip:port`), protocol labels, and IP search.
  - `SettingsScreen.kt` / `SettingsViewModel.kt`: Operator profile & role, dynamic backend URL management, health monitoring, and instant security scan trigger.
- **Session, CSRF & Network Hardening:**
  - Added `network_security_config.xml` configured in `AndroidManifest.xml` with `<base-config cleartextTrafficPermitted="true">` to enable local LAN/Wi-Fi HTTP cleartext communication on Android 9–15.
  - Rebuilt `CookieJar` in `NetVisorApiFactory.kt` to preserve `netvisor_session` and `csrftoken` across all requests, eliminating post-login 401 Unauthorized errors.
  - Added automated `X-XSRF-TOKEN` / `X-CSRF-Token` header injection for all mutating POST/PUT/DELETE requests.
  - Directed real-time WebSocket traffic in `NetVisorWebSocket.kt` to Socket.IO (`/socket.io/?EIO=4&transport=websocket`) with authenticated session cookie headers.
- **Build Verification:** Successfully built debug APK with Gradle `./gradlew.bat assembleDebug` (`BUILD SUCCESSFUL`).

**Problem found**

- Initial login attempts on Android physical devices failed due to Android OS cleartext restrictions and Windows Firewall blocking inbound port 8000.
- Subsequent authenticated requests failed with 401 Unauthorized because `Cookie.parse` dropped session cookies due to domain-path mismatches.
- Mutation endpoints returned 403 Forbidden because CSRF tokens were missing from HTTP headers.

**Solution or learning**

- In modern Android versions, `usesCleartextTraffic="true"` must be paired with an explicit `network_security_config.xml`.
- A resilient `CookieJar` must store session cookies in memory and dynamically attach them matching the target request host.
- Background WebSocket connections must target the Socket.IO ASGI transport endpoint rather than raw `/ws`.

**Evidence**

- Generated `app-debug.apk` at `C:\Users\prem\Network\Android_Application\app\build\outputs\apk\debug\app-debug.apk`.
- Confirmed server log showing `POST /api/v1/auth/login 200 OK` from mobile client `10.18.86.193`.

---

## 2026-08-22 - Documentation & Logbook Synchronization (Today)

**Work completed**

- **Logbook Update:** Formally documented the NetVisor Android native mobile application development, full web parity implementation, and network/security fixes in `docs/project-logbook.md`.
- **System Verification:** Verified end-to-end alignment between backend services, React web frontend, and Jetpack Compose mobile client.

**Evidence**

- Updated `docs/project-logbook.md` and `walkthrough.md`.

---

## Template for Future Daily Entries

```text
## YYYY-MM-DD - Short Title

**Work completed**

- What was implemented or changed.

**Problem found**

- What failed, looked unclear, or required investigation.

**Solution or learning**

- What fixed the issue or what should be done next.

**Evidence**

- Commit, screenshot, command output, test, or file reference.
```
