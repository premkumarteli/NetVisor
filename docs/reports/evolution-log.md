# 📊 NetVisor Project Evolution Log Book

Welcome to the project evolution log book for **NetVisor**! This document records the timeline, milestones, and daily development history of our security operations platform.

---

## 🚀 Key Milestones
| Milestone | Timeline | Description |
| :--- | :--- | :--- |
| **1. Wireshark Prototyping** | Nov 2025 | First exploration of network packets, PCAP analysis, and scapy capture prototyping. |
| **2. SOC Platform Birth** | Feb 18, 2026 | Initial codebase commit restoring the SOC platform with Fluent Intelligence. |
| **3. Enterprise Hardening** | Feb 19, 2026 | Secured backend routes, standardized connection pooling, and verified ingestion. |
| **4. Architectural Split** | Mar 22, 2026 | Separated monolithic services into dedicated `app`, `frontend`, `agent`, and `gateway` modules. |
| **5. Visual & DPI Polish** | Mar 24, 2026 | Enhanced UI with sleek background animations, grid layering, and high DPI visibility. |
| **6. CI Pipeline & Telemetry** | May 1-3, 2026 | Built admin enrollment flows, isolated deploy builds, and optimized ingestion benchmarks. |
| **7. Modular Engines** | June 2026 | Transitioned to unified EngineRegistry, decoupled real-time flow ingestion event loop, and resolved QUIC collisions. |
| **8. Production Hardening** | July-Aug 2026 | Implemented transparent browser intercepting and sensitive redaction, secured Windows SCM execution, partitioned concurrency locks, and fixed SQL Injection & JWT vulnerabilities. |

---

## 📅 Historical Log Book

### 🕵️ November 2025: Genesis & Wireshark Prototyping
*   **Initial Packet Analysis:**
    *   Began by capturing network packets using **Wireshark** to analyze headers, DNS queries, and TCP handshake patterns.
    *   Mapped standard flow properties and studied how to structure network capture metadata.
    *   Transitioned from manual Wireshark inspection to programmatic scripting with `scapy` and `libpcap` wrappers to automate packet sniffing.

### 🔌 February 2026: SOC Platform Birth & Hardening
*   **Feb 18, 2026 (Initial Commit):**
    *   *Restored SOC Platform with Fluent Intelligence*: Initialized SQLite database architecture and core agent routines.
    *   Enhanced accessibility in registration pages and added a secure SHA256 login fallback.
*   **Feb 19, 2026 (Enterprise Hardening & Stabilization):**
    *   Standardized routing protocols and verified the data ingestion pipeline.
    *   Audit and fix of template route names to prevent `Internal Server Error` occurrences.
    *   Hardened project security: introduced connection pooling, secured sessions, and mandated secret key usage.
    *   Created primary project documentation (`README.md`).
*   **Feb 22–25, 2026 (Hygiene & Logging):**
    *   Added database connection pooling and batch logging mechanisms.
    *   Cleaned up local environments (`.env` and `.env.example`).

### 📐 March 2026: Architectural Refactoring & UI Aesthetics
*   **Mar 22, 2026 (Multi-Component Architecture):**
    *   Split the codebase into discrete microservices:
        *   `app` - Core server and coordinator.
        *   `frontend` - User interface dashboard.
        *   `agent` - Local network capture daemon.
        *   `gateway` - Ingest listener and secure packet pipeline.
*   **Mar 23, 2026 (Integration):**
    *   Merged conflicting configurations and integrated the NetvisorX module.
*   **Mar 24, 2026 (UI Polish):**
    *   Styled the user interface using custom HSL palettes and modern animations.
    *   Implemented particle net background animations and scanline overlays.
    *   Added background grid support and fine-tuned layers for high-DPI visibility.

### 🛡️ May 2026: Admin Controls, Ingestion, & CI Hardening
*   **May 1, 2026 (Enrollment & Hygiene):**
    *   Implemented admin-approved agent enrollment flow for secure onboarding.
    *   Restored custom LAN transport overrides and added bootstrap setup scripts.
*   **May 2, 2026 (Analytics Hardening):**
    *   Added flow log search performance benchmarks.
    *   Optimized ingestion baseline, alert handling structures, and ML metadata tracking.
*   **May 3, 2026 (CI & Telemetry Verification):**
    *   Polished device telemetry and application analytics views.

### June 2026: Gateway Hardening & Modular Engine Migration
*   **June 6-7, 2026 (Gateway Hardening):**
    *   Added gateway hardening snapshots so startup health reports now expose missing bootstrap keys, missing TLS pins, unenrolled state, and capture-interface issues.
    *   Made gateway startup fail fast when the runtime is not safe for production, rather than continuing with a weak or ambiguous deployment posture.
    *   Required capture-interface configuration for production gateway operation and surfaced the active capture target in startup output.
    *   Strengthened gateway transport reporting so health checks and deployment checks can distinguish readiness from mere process liveness.
    *   Added regression coverage for unenrolled and missing-interface gateway startup failures.
*   **June 13, 2026 (Migration Kickoff & Engine Foundations):**
    *   *Phases 1–3*: Created the core engine contracts (`Severity`, `Finding`, `EngineResult`) and built compatibility wrappers.
    *   *Phase 4 (Device Engine)*: Rewrote OUI, Hostname, and passive fingerprinting (DHCP option 55, mDNS, SSDP) into `DevicePipeline`. Retired legacy device wrapper.
    *   *Phase 5 (Threat Engine)*: Implemented `SlidingWindowStore` and modular port scanning.
    *   *Phases 6–7*: Built dynamic registry configuration (`EngineConfig`) and central `EngineRegistry`.
    *   *Phase 8 (Risk Engine)*: Rewrote risk calculation to perform correlation, duplicate suppression, and exponential score decay.
*   **June 16, 2026 (Test Hardening & Application Modernization):**
    *   *Phases 8.5 & 10.5*: Added negative test cases, fuzz testing, and stress-tested risk history limits. Hardened threat detectors against malformed values.
    *   *Phase 9*: Upgraded `AIEngine` to yield structured playbooks and ATT&CK mappings.
    *   *Phase 10*: Modernized `ApplicationEngine` using **JA4 client TLS signatures** and ASN reputation enrichment.
*   **June 19, 2026 (Concurrency Hardening & VPN Modernization):**
    *   *Phase 11A*: hardened thread safety with `RLock` across all sliding window stores and suppression tables. Built the programmatic Scapy PCAP validation helper (`pcap_generator.py`).
    *   *Phase 11B (VPN Engine)*: Implemented modular `VPNPipeline` containing OpenVPN opcode checks and WireGuard UDP bidirectional handshake packet size validation (`148`/`92`/`32`).
*   **June 20, 2026 (Production Ingestion Cutover):**
    *   *Phase 12A*: Migrated production `FlowService` to natively run the selective `EngineRegistry` and map scores, severities, and AI summaries backward-compatibly. Added real traffic evaluation PCAP ingestion tests.
*   **June 21, 2026 (Live Verification & Legacy Retirement - Today):**
    *   *Fixes*: Solved dashboard VPN feed missing keys (`vpn_score`, `vpn_provider`) and the QUIC vs OpenVPN UDP opcode collision in `analysis.py`.
    *   *Phase 12B (Legacy Retirement)*: Permanently deleted all retired legacy engines, legacy wrappers, and legacy test files. Verified that all **427 tests pass cleanly** with 0 regressions.

### 🔒 July 2026: Ingestion Alignment & Security Hardening
*   **July 7, 2026 (Ingestion Worker Cutover):**
    *   Refactored `flow_writer_worker` Redis Stream consumer to deserialize dictionary payloads into Pydantic `FlowBase` objects.
    *   Consolidated persistence layers: routed all MySQL and ClickHouse writes exclusively through the `flow_writer_worker` path.
    *   Added configurable `ChaosMiddleware` gating under a settings flag.
*   **July 11, 2026 (DPI Integration & Windows Service Registry Hardening):**
    *   Mapped and exposed status parameters (`browser_launcher_deprecated`, `trust_scope`, `trust_store_match`, `key_protection`) to the React frontend.
    *   Implemented `service_controller.cs` environment initialization to resolve SCM start timeouts.
    *   Added self-healing certificate logic to handle decryption context changes.
    *   Configured transparent local browser interception for Chrome, Edge, and Firefox via `NETVISOR_DPI_CAPTURE_MODE=local_browsers`.
    *   Implemented sensitive credential and authorization header redactions within payload snippets, URLs, and headers.
    *   Integrated Redis-backed rate limiting, spoof-resistant IP resolving with `TRUSTED_PROXIES` validation, secure-only cookies, strict JWT claims verification, and global exception log redaction.
*   **July 12, 2026 (UI Icon Portability):**
    *   Bundled RemixIcon assets locally in the frontend workspace to support offline deployment environments.
*   **July 21, 2026 (High-Load Performance Optimizations):**
    *   Partitioned concurrency locks by organization ID to remove global lock contention bottlenecks.
    *   Offloaded blocking MySQL writes and Redis Stream tasks to a dedicated `ThreadPoolExecutor` to keep the FastAPI event loop responsive.
    *   Added MySQL transaction deadlock (`1213`) recovery/retry mechanics.

### 📈 August 2026: UI Modernization, Vulnerability Mitigation & Documentation
*   **Aug 2, 2026 (DPI UI Polish):**
    *   Modernized the Web Inspection DPI analyst view with a tabbed layout.
    *   Introduced rendering safeguards to handle null/uninitialized device properties safely.
*   **Aug 11, 2026 (Project Refactoring & Security Sprint):**
    *   Restructured project file layout to align backend, frontend, agent, and gateway components.
    *   Fixed SQL Injection vectors in `system_service.py` and `flow_service.py` via whitelists and parameterization.
    *   Resolved mTLS connection leaks in middleware via asynchronous execution and cached revocation status.
    *   Migrated access tokens to asymmetric `RS256` keys and enforced strict claim verification.
    *   Added compiled `netvisor_manager.exe` tool to support agent service management on target Windows nodes.
*   **Aug 13, 2026 (Technical Documentation):**
    *   Authored the comprehensive NetVisor flow diagram (`project_flow_diagram.md`) tracing data from collection to real-time Socket.IO broadcasts.
    *   Prepared the technology stack report (`technology-stack-report.md`) detailing language metrics and justifying Python-based packet analysis over manual Wireshark.
*   **Aug 16, 2026 (Logbook Synchronization - Today):**
    *   Consolidated the main project logbook (`project-logbook.md`) and evolution logbook with all past work up to today.

---

## ✍️ How to Log Future Updates
To keep this log book current, append any new changes to the bottom of the log or insert a new date under the current month. Include:
1.  **Date** of the update.
2.  **Key Goals** accomplished.
3.  **Specific Changes** made to files/modules.
4.  **Verification** results.
