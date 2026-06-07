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
| June 2026 | Recovered historical source snapshots and reconstructed this evidence-based academic logbook. |

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

### Pending Verification and Hardening

- Verify gateway upload retry and backoff behavior under backend connection resets.
- Reduce gateway-to-UI delay while preventing backend overload.
- Verify offline buffering and replay across backend restarts.
- Validate server, agent, and gateway deployment on separate machines.
- Tune VPN and threat detection false positives with repeatable traffic tests.
- Run final end-to-end acceptance tests for all documented threat scenarios.
- Continue readability improvements for remaining console pages.
- Confirm Docker cold-start behavior, database readiness, backup retention, and restore procedures in a clean deployment.

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
