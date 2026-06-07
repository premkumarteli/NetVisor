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
    *   Isolated deploy bundle unit tests from the frontend build sequence.
    *   Set up automated test database provisioning for backend testing.
    *   Fixed DNS answer parsing regressions in Scapy.
*   **May 16–18, 2026 (Hygiene & Maintenance):**
    *   Hardened agent deployment code and prepared codebase for production deployment.

---

## ✍️ How to Log Future Updates
To keep this log book current, append any new changes to the bottom of the log or insert a new date under the current month. Include:
1.  **Date** of the update.
2.  **Key Goals** accomplished.
3.  **Specific Changes** made to files/modules.
4.  **Verification** results.
