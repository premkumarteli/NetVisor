# NetVisor Engineering Memory Document

**Document Version:** 1.0  
**Date:** August 30, 2026  
**Status:** Living Engineering Reference  
**Target Codebase:** NetVisor Platform (v7.0 Modular Infrastructure)  

---

## Executive Overview

This document records the architectural history, rationale, trade-offs, deferred features, technical debt, security boundaries, and critical developer guidelines for NetVisor. It serves as the authoritative context document for future maintainers and core engineers working on the platform.

---

## 1. Major Architectural Decisions

### 1.1 Cutover from Flask to FastAPI (Phase 3, March 2026)
* **Decision:** Migrated the entire backend server from a synchronous Flask WSGI application to an asynchronous FastAPI (ASGI) application running on Uvicorn.
* **Impact:** Enabled native Python `async/await` handling across HTTP REST endpoints and Socket.IO WebSocket streams.

### 1.2 Differentiated Managed Endpoint Agent vs. Privacy-Preserving Gateway Sensor (Phase 3/4, March–April 2026)
* **Decision:** Split network data collection into two distinct architectural components:
  1. **Managed Endpoint Agent (`agent/`):** Installed on company-owned assets for deep OS process mapping, interface monitoring, and opt-in TLS/HTTP Deep Packet Inspection (DPI).
  2. **Metadata-Only Gateway Sensor (`gateway/`):** Deployed on perimeter routers/hotspots for passive BYOD device discovery, extracting Layer 3/4 headers and SNI/DNS metadata while enforcing a strict zero-payload storage policy.

### 1.3 Opt-In TLS DPI via mitmproxy Addon & System CA Management (March 2026)
* **Decision:** Built HTTPS payload inspection around an embedded inline `mitmproxy` engine ([agent/dpi/mitm_addon.py](file:///c:/Users/prem/Network/agent/dpi/mitm_addon.py)) and automated root CA installation ([agent/dpi/cert_manager.py](file:///c:/Users/prem/Network/agent/dpi/cert_manager.py)).

### 1.4 Asymmetric RS256 JWT Authentication & mTLS Internal CA (May–July 2026)
* **Decision:** Standardized analyst console authentication on RS256 asymmetric JWT key pairs and agent/gateway transport authentication on Mutual TLS (mTLS) X.509 client certificates issued by an internal NetVisor CA ([backend/services/ca.py](file:///c:/Users/prem/Network/backend/services/ca.py)).

### 1.5 Dual Storage Database Architecture (MySQL 8.0 + ClickHouse) (July 2026)
* **Decision:** Adopted a hybrid database strategy:
  * **MySQL 8.0:** Manages relational domain entities (users, organizations, devices, agents, alerts, audit trails).
  * **ClickHouse:** Columnar engine (`infra/clickhouse/schema.sql`) for high-throughput time-series raw flow log ingestion and analytical querying.

### 1.6 Decoupled Event-Driven Ingestion Pipeline (June 2026)
* **Decision:** Separated HTTP REST ingestion endpoints from database persistence and real-time UI notifications using an asynchronous memory store (`LiveTelemetryStore`), event dispatcher (`EventDispatcher`), correlation worker (`CorrelationWorker`), and Socket.IO broadcast scheduler (`broadcast_scheduler`).

### 1.7 Anti-Tamper Cryptographic Audit Log Chaining (July 2026)
* **Decision:** Implemented block-like hash chaining (`hash = SHA256(prev_hash + current_log_payload)`) in [backend/services/audit_chain_service.py](file:///c:/Users/prem/Network/backend/services/audit_chain_service.py) to guarantee immutability for administrative audit records.

---

## 2. Rationale: Why Decisions Were Made

| Decision | Primary Engineering Rationale |
| :--- | :--- |
| **FastAPI Cutover** | Flask WSGI blocked worker threads under concurrent telemetry ingest. FastAPI handles thousands of concurrent socket connections asynchronously without thread pool exhaustion. |
| **Agent / Gateway Split** | Enterprise compliance permits full process-to-flow monitoring on company hardware, but privacy regulations prohibit payload inspection on guest Wi-Fi and employee BYOD devices. |
| **mitmproxy Base** | Writing a custom TLS 1.3 decryption proxy from scratch is dangerous and error-prone. mitmproxy provides a battle-tested, standard-compliant interceptor core. |
| **mTLS + RS256** | Static API keys embedded in client binaries can be extracted or intercepted. mTLS enforces cryptographic host identity bound to local OS storage (DPAPI). |
| **ClickHouse Storage** | High-frequency flow logging overwhelmed MySQL disk I/O and table locks during traffic spikes. ClickHouse handles 100,000+ inserts/sec with 10x columnar compression. |
| **Decoupled Ingestion** | Executing threat correlation rules and database writes synchronously inside HTTP request handlers caused client upload timeouts during network bursts. |

---

## 3. Alternatives Considered

### 3.1 gRPC vs. REST/mTLS for Agent Transport
* **Evaluated:** Protocol Buffers over gRPC (`proto/` schema files exist in repo).
* **Choice:** REST/HTTPS over mTLS.
* **Reasoning:** REST over standard HTTPS port 443 traverses corporate proxies, firewalls, and middleboxes seamlessly without custom gRPC HTTP/2 framing blockages.

### 3.2 Zeek/Suricata Integration vs. Custom Python Packet Engine
* **Evaluated:** Ingesting passive log output from Zeek network sensors (evaluated in Nov 2025 prototype).
* **Choice:** Custom Python packet engine (`packet_engine/`) using DPKT and Scapy.
* **Reasoning:** Zeek requires complex native Linux daemon dependencies that could not be packaged cleanly as a lightweight Windows agent/gateway service.

### 3.3 ORM (SQLAlchemy) vs. Raw Parameterized SQL Connection Pool
* **Evaluated:** Heavy Object-Relational Mapping via SQLAlchemy.
* **Choice:** Custom thread-safe MySQL connection pool (`backend/db/session.py`) executing raw parameterized SQL queries.
* **Reasoning:** Maximize batch insertion performance and eliminate ORM object hydration latency during bulk telemetry writes.

---

## 4. Features Intentionally Postponed

1. **Linux eBPF/XDP Kernel Gateway Sensor:** High-performance C-kernel packet capture postponed to v7.5 due to cross-compilation complexity across heterogeneous Linux kernels.
2. **Native Multi-Factor Authentication (MFA/TOTP):** Analyst TOTP login postponed to v7.2; current authentication relies on single-factor RS256 JWT credentials.
3. **Automated Incident Remediation Playbooks:** Automated firewall rule injection upon alert detection postponed to v8.0 to prevent accidental lockout during early pilot deployments.
4. **Android Offline Telemetry Sync:** Mobile offline SQLite queue sync postponed; current Android app requires active backend connectivity.

---

## 5. Features Removed

* **Zeek Process Spawner:** Removed Zeek log tailing subprocess modules from Version 2.
* **Monolithic Flask Templates:** Deleted all static HTML/Jinja templates (`activity.html`, `app.py`) following Phase 3 React migration.
* **Root-Level Requirements Wrappers:** Deleted 7 redundant root requirements text files (`requirements-server.txt`, etc.) in August 2026 to enforce single-source dependency management in `requirements/`.
* **Port-Only Signature VPN Detector:** Deprecated static port tagging (e.g., assuming port 1194 is always OpenVPN) due to 40%+ false positive rates; replaced by ML feature extraction.

---

## 6. Current Roadmap

```
+-----------------------------------------------------------------------------------+
|                                 NetVisor Roadmap                                  |
+-----------------------------------------------------------------------------------+
  v7.1 (Q3 2026)    --> Complete 100% Native ClickHouse Ingestion Routing
  v7.2 (Q4 2026)    --> Implement RFC 6238 TOTP Multi-Factor Authentication
  v7.5 (Q1 2027)    --> Deploy Linux eBPF/XDP C-Kernel Gateway Sensor Package
  v8.0 (Q2 2027)    --> Automated Remediation Playbooks & Enterprise SIEM Connectors
```

---

## 7. Known Technical Debt

1. **Raw SQL Query Coupling:** Business logic services in `backend/services/` contain hardcoded SQL strings requiring manual column whitelisting for dynamic sorting.
2. **Residual `HS256` Fallback Path:** Auth middleware retains `HS256` key verification logic if `RS256` certificate files cannot be loaded on startup.
3. **Gateway Python GIL Ceiling:** Single-process Python socket capture in `gateway/main.py` hits a single-core performance ceiling at ~1 Gbps.
4. **Dual Component Imports:** Residual V1 component aliases coexist in `frontend/src/` alongside pure V2 glassmorphism design components.

---

## 8. Known Bugs

1. **QUIC UDP Fallback Lag:** On specific Windows 11 host configurations, blocking UDP port 443 via Windows Firewall causes Chrome to attempt 5 retries before falling back to HTTPS, causing a 2-second initial page load delay.
2. **mTLS Revocation Cache Stale Window:** The Certificate Revocation List (CRL) cache in `backend/services/ca.py` maintains a 5-minute TTL during which a revoked agent cert may temporarily authenticate before cache invalidation.

---

## 9. Components Considered Unstable

* **Active IP Prober ([backend/engines/device/active_prober.py](file:///c:/Users/prem/Network/backend/engines/device/active_prober.py)):** High-speed subnet ARP/ICMP scanning can trigger port-security alarms on managed enterprise switches or get flagged by local IDS sensors.
* **mitmproxy Media Stream Inspection:** Intercepting high-bandwidth 4K video streams through mitmproxy inline addon can cause temporary memory growth on low-RAM endpoint hardware.

---

## 10. Areas Where Codebase Differs from Original Plan

* **Monolithic Executable -> Decoupled Deployment Roles:** The original plan envisioned a single binary; the final platform separates `server`, `agent`, and `gateway` builds.
* **Passive Sniffing -> Active MITM Interception:** Original specifications planned for 100% passive sniffing. Active TLS decryption was added when encryption analysis revealed that 85%+ of modern web traffic obscures plain-text URL paths.

---

## 11. Assumptions Made During Development

1. Managed host systems run 64-bit Windows 10/11 or modern Linux distributions with Administrator/root privileges.
2. Perimeter routers allow outbound mTLS connections over port 8443 or standard HTTPS port 443.
3. Internal network subnets follow standard RFC 1918 private IPv4 allocation (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

---

## 12. Security Assumptions

* The server's internal Certificate Authority private key (`ca.key`) stored in `keys/` is protected by strict file permission ACLs.
* Local endpoint users cannot manipulate Windows DPAPI registry keys without SYSTEM-level rights.
* Network gateway hardware is physically secure against local memory bus extraction attacks.

---

## 13. Scaling Assumptions

* **MySQL 8.0:** Handles up to 10,000 active devices, 500 enrolled agents, and asset state updates.
* **ClickHouse:** Handles time-series retention exceeding 100,000,000 raw network flow records.
* **Socket.IO Realtime Core:** Handles up to 1,000 concurrent analyst dashboard WebSocket sessions per server instance.

---

## 14. Critical Developer Rules: What NEVER to Change Without Review

> [!CAUTION]
> The following 5 core mechanisms represent critical security and operational boundaries. **DO NOT modify these files without explicit review from the lead security architect.**

1. **mTLS Certificate Revocation & Verification Chain ([backend/services/ca.py](file:///c:/Users/prem/Network/backend/services/ca.py)):**  
   *Never* alter certificate chain validation or disable CRL revocation checking; doing so risks accepting unauthorized or spoofed agent telemetry.
2. **Sensitive Data Redaction Pipeline ([agent/dpi/redaction.py](file:///c:/Users/prem/Network/agent/dpi/redaction.py)):**  
   *Never* remove or weaken PII/JWT/password regex redaction patterns; doing so will cause unencrypted user credentials to leak into the database.
3. **Dynamic SQL Column Whitelisting ([backend/services/](file:///c:/Users/prem/Network/backend/services/)):**  
   *Never* pass raw user-supplied sorting strings directly into SQL queries; always enforce strict column whitelisting to prevent SQL Injection.
4. **JWT Algorithm Validation ([backend/core/security.py](file:///c:/Users/prem/Network/backend/core/security.py)):**  
   *Never* pass loose `algorithms=["RS256", "HS256"]` arrays to `jwt.decode()` without explicit header key verification; doing so re-opens JWT algorithm confusion vulnerabilities.
5. **Anti-Tamper Audit Log Hash Chaining ([backend/services/audit_chain_service.py](file:///c:/Users/prem/Network/backend/services/audit_chain_service.py)):**  
   *Never* alter the `SHA256(prev_hash + current_log)` formula; doing so breaks validation across historical audit logs.
