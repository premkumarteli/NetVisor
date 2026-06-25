# 📊 NetVisor Technology Stack Report

This report provides a comprehensive breakdown of the technologies, frameworks, libraries, protocols, and security features implemented across the NetVisor SOC platform. All findings are verified by source code, configuration files, and deployment scripts located within the repository.

---

### 1. Executive Summary

*   **Project Type:** Distributed Security Operations Center (SOC) and Endpoint Monitoring Platform.
*   **Primary Purpose:** Network traffic monitoring, endpoint telemetry collection, deep packet inspection (DPI), threat detection, cryptographic logging, machine learning-based flow anomaly detection, and automated device profiling.
*   **High-Level Architecture:** Distributed Collector-Server architecture comprising:
    1.  **FastAPI Backend Coordinator:** Aggregates flow telemetry, manages configurations, executes detection engines, and orchestrates client updates.
    2.  **React Frontend Dashboard:** Real-time visualization of threats, active devices, bandwidth consumption, and log feeds.
    3.  **Endpoint Telemetry Agent:** Python daemon sniffing raw packet headers and running a browser MITM proxy for granular web inspection.
    4.  **BYOD Gateway Collector:** Sniffs local segments in promiscuous mode to passively discover unmanaged endpoints.
    5.  **Reverse Proxy (Caddy/Nginx):** Edge termination of mTLS certificates and static asset provisioning.
    6.  **Persistent Storage (MySQL):** Relational schema storage for flows, alerts, sessions, and client identities.
*   **Technology Stack Overview:** React 18, Vite 6, TailwindCSS 4, Chart.js, FastAPI, Socket.IO, Scapy, Linux Raw Sockets, `mitmproxy`, Scikit-learn (IsolationForest), MySQL 8.0, Caddy, Docker & Docker Compose.

---

### 2. Programming Languages

The repository consists of Python, JavaScript (ES6), React JSX, styling sheets, SQL migrations, and pipeline configurations. Based on line count analysis of active source files (excluding virtual environments, `node_modules`, builds, and package locks):

*   **JSON / Configuration Data (~72.38%):** Used for dependency locks, lint configurations, and runtime settings.
*   **JavaScript (~16.79% - 158 files, 97,876 lines):** Implements utility helper suites, context state providers, and client hooks.
*   **Python (~6.65% - 279 files, 38,762 lines):** Powers the backend FastAPI framework, telemetry agent, network gateway, analytical engines, and database migrations.
*   **CSS (~2.07% - 50 files, 12,066 lines):** Defines custom stylesheets, animations, and typography.
*   **React JSX (~1.47% - 59 files, 8,541 lines):** Forms the page structure, modals, and graphical components.
*   **HTML (~0.42% - 39 files, 2,457 lines):** Single Page Application entrypoints and templates.
*   **SQL (~0.12% - 14 files, 713 lines):** Relational schema definition and initial seeds.
*   **YAML / CI/CD (~0.10% - 4 files, 590 lines):** GitHub Actions workflows and compose structures.

---

### 3. Frontend Stack

*   **Core UI Framework:** **React** (v18.3.1) and **React-DOM** (v18.3.1).
    *   *Evidence:* [package.json](file:///c:/Users/prem/Network/frontend/package.json#L18-L20)
*   **Build Tools & Bundlers:** **Vite** (v6.0.5) using `@vitejs/plugin-react` (v4.3.4).
    *   *Evidence:* [package.json](file:///c:/Users/prem/Network/frontend/package.json#L28) and [vite.config.js](file:///c:/Users/prem/Network/frontend/vite.config.js)
*   **Routing:** **React Router DOM** (v7.13.0). Implements lazy loading (`lazy`, `Suspense`) and route protection (`ProtectedRoute`).
    *   *Evidence:* [App.jsx](file:///c:/Users/prem/Network/frontend/src/App.jsx#L2-L40)
*   **State Management:** React Context API.
    *   `AuthProvider` for session management: [AuthContext.jsx](file:///c:/Users/prem/Network/frontend/src/context/AuthContext.jsx)
    *   `ImmersionProvider` for theme rendering states: [ImmersionProvider.jsx](file:///c:/Users/prem/Network/frontend/src/immersion/engine/ImmersionProvider.jsx)
*   **UI Libraries & Animations:** **Framer Motion** (v12.38.0) for micro-animations and route transitions, **Lucide React** (v1.16.0) for vector iconography.
    *   *Evidence:* [package.json](file:///c:/Users/prem/Network/frontend/package.json#L16-L17)
*   **Styling & CSS Processing:** **TailwindCSS** (v4.2.2) via `@tailwindcss/vite` and **PostCSS** (v8.5.8) with **Autoprefixer** (v10.4.27).
    *   *Evidence:* [package.json](file:///c:/Users/prem/Network/frontend/package.json#L13) and [index.css](file:///c:/Users/prem/Network/frontend/src/index.css) (custom utility classes).
*   **Charts & Visualizations:** **Chart.js** (v4.4.7) wrapper **React-Chartjs-2** (v5.3.0) for rendering bandwidth histograms, active flow rates, and alerts.
    *   *Evidence:* [package.json](file:///c:/Users/prem/Network/frontend/package.json#L15)
*   **WebSocket Client:** **Socket.io-client** (v4.8.1) for handling backend-driven notifications and live telemetry.
    *   *Evidence:* [socket.js](file:///c:/Users/prem/Network/frontend/src/socket.js)

---

### 4. Backend Stack

*   **Web & API Framework:** **FastAPI** (ASGI wrapper over Starlette).
    *   *Evidence:* [main.py](file:///c:/Users/prem/Network/app/main.py#L142) and [router.py](file:///c:/Users/prem/Network/app/api/router.py)
*   **Application Server:** **Uvicorn** (utilizes ASGI protocol).
    *   *Evidence:* [requirements-server.txt](file:///c:/Users/prem/Network/requirements-server.txt#L4)
*   **WebSocket Engine:** **Python-SocketIO** (v5.x) ASGI wrapper (`socketio.ASGIApp`).
    *   *Evidence:* [main.py](file:///c:/Users/prem/Network/app/main.py#L93-L94) and [realtime.py](file:///c:/Users/prem/Network/app/realtime.py)
*   **Authentication & Signing:**
    *   **JWT Access Tokens:** Implemented with `python-jose[cryptography]` utilizing `HS256`.
        *   *Evidence:* [security.py](file:///c:/Users/prem/Network/app/core/security.py#L7-L18)
    *   **API Requests Signature Verification:** HMAC-SHA256 signature verification for agent-to-backend communication.
        *   *Evidence:* [agent_auth.py](file:///c:/Users/prem/Network/shared/security/agent_auth.py#L56-L95)
*   **Authorization:** Role-Based Access Control (RBAC) (definitions like `viewer`, `org_admin`, `super_admin`).
    *   *Evidence:* [roles.js](file:///c:/Users/prem/Network/frontend/src/utils/roles.js) and routes checks in [agents.py](file:///c:/Users/prem/Network/app/api/agents.py)
*   **Security Middlewares:**
    *   `TransportSecurityMiddleware` (Enforces HTTPS/HSTS): [transport_security.py](file:///c:/Users/prem/Network/app/middleware/transport_security.py)
    *   `MTLSMiddleware` (Performs mTLS cert validation): [mtls_middleware.py](file:///c:/Users/prem/Network/app/middleware/mtls_middleware.py)
    *   `CSRFProtectionMiddleware` (Double-Submit cookie verification): [csrf_protection.py](file:///c:/Users/prem/Network/app/middleware/csrf_protection.py)
*   **Background Jobs:**
    *   **Embedded Mode:** Async loop task in FastAPI startup lifecycle.
        *   *Evidence:* [main.py](file:///c:/Users/prem/Network/app/main.py#L121) calling `flow_service.flow_writer_worker()`
    *   **External Mode:** Dedicated container executing `run_flow_worker.py`.
        *   *Evidence:* [docker-compose.yml](file:///c:/Users/prem/Network/docker-compose.yml#L106-L140)

---

### 5. Database Layer

*   **Primary Engine:** **MySQL 8.0** (running in container `netvisor-db`).
    *   *Evidence:* [docker-compose.yml](file:///c:/Users/prem/Network/docker-compose.yml#L3-L23)
*   **Connection Driver & Pooler:** **mysql-connector-python** using `pooling.MySQLConnectionPool` for thread-safe operations.
    *   *Evidence:* [session.py](file:///c:/Users/prem/Network/app/db/session.py#L334-L380)
*   **ORM / Query Builders:** **None**. The platform runs direct SQL statements prepared and executed on raw DB connections for maximum efficiency.
    *   *Evidence:* [session.py](file:///c:/Users/prem/Network/app/db/session.py#L421-L450)
*   **Migration Framework:** Custom modular Python migration files.
    *   *Evidence:* [apply_20260417_runtime_schema_phase2.py](file:///c:/Users/prem/Network/infra/database/migrations/apply_20260417_runtime_schema_phase2.py) and apply steps in [docker-compose.yml](file:///c:/Users/prem/Network/docker-compose.yml#L38-L46)
*   **Caching Engine:** local memory dictionaries implementing custom TTL (time-to-live) expiration.
    *   *Evidence:* `DomainHintCache` in [traffic_metadata.py](file:///c:/Users/prem/Network/shared/collector/traffic_metadata.py#L92-L131) and ASN cache in [vpn_detector.py](file:///c:/Users/prem/Network/app/services/vpn_detector.py#L174-L246)

---

### 6. Networking Technologies

*   **Scapy Packet Sniffing:** Implemented. Snoops packets synchronously/asynchronously and dispatches callbacks.
    *   *Evidence:* `ScapyCaptureBackend` in [capture.py](file:///c:/Users/prem/Network/shared/collector/capture.py#L191-L237)
*   **Linux Raw Sockets:** Implemented. Drops Scapy overhead on Linux machines using native raw socket bindings.
    *   *Evidence:* `LinuxRawSocketCaptureBackend` in [capture.py](file:///c:/Users/prem/Network/shared/collector/capture.py#L239-L307) using `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))`
*   **PCAP Processing:** Partially Implemented / Planned. Logs indicate Wireshark and pcap integration, but active collectors sniffing live interfaces.
*   **Npcap / WinPcap:** Partially Implemented / Planned. Local code recognizes and categorizes Npcap error signatures, but relies on drivers being pre-installed on the host.
    *   *Evidence:* [capture.py](file:///c:/Users/prem/Network/shared/collector/capture.py#L94)
*   **Deep Packet Inspection (DPI):** Implemented.
    *   **TLS SNI Parser:** Extracts hostnames by inspecting ClientHello handshakes starting with `0x16 0x03`.
        *   *Evidence:* `_extract_tls_sni` in [traffic_metadata.py](file:///c:/Users/prem/Network/shared/collector/traffic_metadata.py#L154-L218)
    *   **HTTP Host Parser:** Decodes payload headers to retrieve `Host` indicators.
        *   *Evidence:* `_extract_http_host` in [traffic_metadata.py](file:///c:/Users/prem/Network/shared/collector/traffic_metadata.py#L220-L250)
    *   **Dynamic Browser Proxy:** Integrates `mitmproxy` as a client-side proxy to intercept page content, titles, and parameters.
        *   *Evidence:* [mitm_addon.py](file:///c:/Users/prem/Network/agent/dpi/mitm_addon.py) and [proxy_manager.py](file:///c:/Users/prem/Network/agent/dpi/proxy_manager.py)
*   **Flow Analysis & Management:** Implemented. Aggregates sniffed packets into session metrics (byte count, durations, average sizes).
    *   *Evidence:* `FlowManager` and `FlowState` in [flow_manager.py](file:///c:/Users/prem/Network/shared/collector/flow_manager.py)
*   **Protocol Analysis:** Implemented. Classifies traffic protocol layers (TCP, UDP, ICMP, ARP) and matches port signatures (DNS, DHCP, HTTP, HTTPS, SSH, TLS, SSDP, mDNS, etc.).
    *   *Evidence:* `_classify_application` in [analysis.py](file:///c:/Users/prem/Network/shared/collector/analysis.py#L208-L346)

---

### 7. Security Technologies

*   **JWT Implementation:** `python-jose` for encoding/decoding auth cookies.
    *   *Evidence:* [security.py](file:///c:/Users/prem/Network/app/core/security.py#L7-L18)
*   **mTLS Client/Server Validation:**
    *   **Edge Termination:** Terminated by **Caddy** which passes validation metrics upstream.
        *   *Evidence:* [Caddyfile](file:///c:/Users/prem/Network/infra/deployment/server/Caddyfile#L16-L28)
    *   **Server Verification:** Backend middleware parses header assertions and enforces validation policies.
        *   *Evidence:* [mtls_middleware.py](file:///c:/Users/prem/Network/app/middleware/mtls_middleware.py)
    *   **Client Generation:** Local generation of ECDSA keypairs (SECP256R1) and signing requests (CSR).
        *   *Evidence:* [mtls.py](file:///c:/Users/prem/Network/agent/security/mtls.py#L98-L130)
*   **Encryption & Hashing Libraries:**
    *   **Passlib & Bcrypt:** Hashing and validation of administrative credentials.
        *   *Evidence:* [security.py](file:///c:/Users/prem/Network/app/core/security.py#L20-L28)
    *   **Cryptography:** ECDSA, X509 serialization, CSR, and Ed25519 signatures.
        *   *Evidence:* [integrity.py](file:///c:/Users/prem/Network/agent/security/integrity.py#L10-L11)
*   **Secrets Storage (DPAPI):** Secure local persistence of registration credentials on Windows nodes using Windows Data Protection API (DPAPI).
    *   *Evidence:* [dpapi.py](file:///c:/Users/prem/Network/agent/security/dpapi.py) using `ctypes.windll.crypt32`
*   **Cryptographic Audit Log Chaining:** Entries are linked into a hash chain using SHA-256 (`entry_hash` and `chain_hash`) to guarantee history immutability.
    *   *Evidence:* [audit_chain_service.py](file:///c:/Users/prem/Network/app/services/audit_chain_service.py)
*   **Code Integrity Checks:** Cryptographic verification of the agent package contents using Ed25519-signed JSON manifests.
    *   *Evidence:* [integrity.py](file:///c:/Users/prem/Network/agent/security/integrity.py)

---

### 8. Cybersecurity Features

*   **Threat Detection Engine:** Orchestrates specialized detection units:
    *   **C2 Beaconing:** `BeaconingDetector` computes the coefficient of variation (CoV) on connection intervals to pinpoint automated periodic beacons.
        *   *Evidence:* [beaconing.py](file:///c:/Users/prem/Network/app/engines/threat/beaconing.py)
    *   **DNS Tunneling:** `DNSTunnelingDetector` measures subdomain Shannon Entropy and tracks query spikes using a bloom filter.
        *   *Evidence:* [dns_tunneling.py](file:///c:/Users/prem/Network/app/engines/threat/dns_tunneling.py)
    *   **Brute Force:** `BruteForceDetector` monitors failed connection events on critical target ports.
        *   *Evidence:* [brute_force.py](file:///c:/Users/prem/Network/app/engines/threat/brute_force.py)
    *   **Port Scanning:** `PortScanDetector` checks for connection attempts targeting unique destination ports.
        *   *Evidence:* [port_scan.py](file:///c:/Users/prem/Network/app/engines/threat/port_scan.py)
    *   **Data Exfiltration:** `ExfiltrationDetector` alerts when data uploads surpass custom boundaries.
        *   *Evidence:* [exfiltration.py](file:///c:/Users/prem/Network/app/engines/threat/exfiltration.py)
*   **Device Fingerprinting Pipeline:** Modular scoring framework that classifies nodes using:
    1.  Vendor OUI Lookup: [oui_detector.py](file:///c:/Users/prem/Network/app/engines/device/oui_detector.py)
    2.  Hostname Cleaning & Pattern Matching: [hostname_detector.py](file:///c:/Users/prem/Network/app/engines/device/hostname_detector.py)
    3.  DHCP Fingerprints (OS family identification): [dhcp_detector.py](file:///c:/Users/prem/Network/app/engines/device/dhcp_detector.py)
    4.  mDNS Service Scanning: [mdns_detector.py](file:///c:/Users/prem/Network/app/engines/device/mdns_detector.py)
    5.  SSDP friendly name parses: [ssdp_detector.py](file:///c:/Users/prem/Network/app/engines/device/ssdp_detector.py)
    6.  Active Port Probing (last resort fallback): [active_prober.py](file:///c:/Users/prem/Network/app/engines/device/active_prober.py)
*   **Risk Engine & Threat Correlation:** Evaluates rules against MITRE ATT&CK concepts (e.g. T1110, T1071, T1048), decaying contribution scores via half-life formulas and suppressing alerts.
    *   *Evidence:* [engine.py](file:///c:/Users/prem/Network/app/engines/risk/engine.py) and [correlation.py](file:///c:/Users/prem/Network/app/engines/risk/correlation.py)
*   **Threat Intelligence Service:** Checks base domains against lists of malicious URLs, flags risky TLDs (e.g., `.zip`, `.monster`), and triggers on executable mime types.
    *   *Evidence:* [threat_intelligence_service.py](file:///c:/Users/prem/Network/app/services/threat_intelligence_service.py)
*   **VPN Endpoint Detector:** Integrates real-time Tor exit node scrapers, checks known VPN provider lists (NordVPN, SurfShark), evaluates hosting ranges, and identifies standard VPN tunnel ports.
    *   *Evidence:* [vpn_detector.py](file:///c:/Users/prem/Network/app/services/vpn_detector.py)

---

### 9. AI / Machine Learning

*   **Core Library:** **Scikit-learn** (v1.2+) and **NumPy**.
    *   *Evidence:* [requirements-server.txt](file:///c:/Users/prem/Network/requirements-server.txt#L14-L15)
*   **ML Model:** **Isolation Forest** (`sklearn.ensemble.IsolationForest`) for unsupervised flow anomaly detection.
    *   *Evidence:* [model.py](file:///c:/Users/prem/Network/app/ml/model.py#L30)
*   **Features Engine:** Extracts six telemetry metrics: `packet_count`, `byte_count`, `duration`, `average_packet_size`, `src_port`, and `dst_port`.
    *   *Evidence:* [features.py](file:///c:/Users/prem/Network/app/ml/features.py)
*   **Serialization:** Fits and dumps model configurations to disk via **Joblib**.
    *   *Evidence:* [model.py](file:///c:/Users/prem/Network/app/ml/model.py#L37-L44)

---

### 10. Infrastructure & DevOps

*   **Containerization Engine:** **Docker** and **Docker Compose** (V3 bridge networking).
    *   *Evidence:* [docker-compose.yml](file:///c:/Users/prem/Network/docker-compose.yml)
*   **Multi-Stage Build Targets:**
    *   FastAPI backend (slim Python 3.11 build): [Dockerfile.backend](file:///c:/Users/prem/Network/infra/docker/Dockerfile.backend)
    *   React frontend SPA compiler (Node compilation + Nginx stage): [Dockerfile.frontend](file:///c:/Users/prem/Network/infra/docker/Dockerfile.frontend)
    *   Sniffing Agent and Gateway: [Dockerfile.agent](file:///c:/Users/prem/Network/Dockerfile.agent) and [Dockerfile.gateway](file:///c:/Users/prem/Network/Dockerfile.gateway)
*   **Web Servers & Reverse Proxies:**
    *   **Nginx:** Serves static frontend bundles.
        *   *Evidence:* [nginx.conf](file:///c:/Users/prem/Network/infra/docker/nginx.conf)
    *   **Caddy:** Handles client certificate validation and request forwarding.
        *   *Evidence:* [Caddyfile](file:///c:/Users/prem/Network/infra/deployment/server/Caddyfile)

---

### 11. CI/CD Pipeline

*   **Automation Platform:** **GitHub Actions**.
*   **Workflow file:** [.github/workflows/ci.yml](file:///c:/Users/prem/Network/.github/workflows/ci.yml)
*   **Workflow Steps & Objectives:**
    1.  *Repository Hygiene:* Ensures forbidden folders (`node_modules`, `dist`, `__pycache__`) are untracked.
    2.  *Environment Provisioning:* Runs Ubuntu Runner, loads Python 3.13, Node 20, and spawns a MySQL 8.0 server container.
    3.  *Dependency Installation:* Sets up Python pip requirements and runs `npm ci` inside the frontend directory.
    4.  *Database Bootstrapping:* Provisions the test database schema using `init_ci_database.py`.
    5.  *Frontend Linter & Compiling:* Validates styles with ESLint and builds deploy-ready code using Vite.
    6.  *Backend Test Execution:* Executes pytest suites (`run_pytest_ci.py`).
    7.  *Probing & Security Regressions:* Runs integration test assertions for route authentication, DB session pooling, and secure transport policies.
    8.  *Asset Packaging:* Bundles server, agent, and gateway roles into deploy zip files via `build_deploy_bundles.py`.

---

### 12. Monitoring & Observability

*   **Prometheus Metrics:** The `/api/v1/health/metrics.prom` route generates application counters, gauges, and histograms.
    *   *Evidence:* [health.py](file:///c:/Users/prem/Network/app/api/health.py#L137-L150) and [metrics_service.py](file:///c:/Users/prem/Network/app/services/metrics_service.py)
*   **System Performance Observability:** Monitored via `psutil` inside agents and servers.
    *   *Evidence:* [requirements-server.txt](file:///c:/Users/prem/Network/requirements-server.txt#L13)
*   **Application Alerting:** Security violations are saved to the `alerts` database table and immediately pushed to active frontend layouts using WebSockets.
    *   *Evidence:* [alert_service.py](file:///c:/Users/prem/Network/app/services/alert_service.py)

---

### 13. APIs & External Integrations

*   **REST API Router:** FastAPI APIRouter structure under `/api/v1`.
    *   *Evidence:* [router.py](file:///c:/Users/prem/Network/app/api/router.py)
*   **WebSockets:** ASGI wrapper streaming telemetry updates to client browsers.
    *   *Evidence:* [main.py](file:///c:/Users/prem/Network/app/main.py#L233)
*   **Threat Intel Scraper:** Scrapes the Tor Project feed at `check.torproject.org`.
    *   *Evidence:* [vpn_detector.py](file:///c:/Users/prem/Network/app/services/vpn_detector.py#L337-L349)
*   **GeoIP Resolver:** ASN/ISP lookups query `ip-api.com`.
    *   *Evidence:* [vpn_detector.py](file:///c:/Users/prem/Network/app/services/vpn_detector.py#L268-L289)

---

### 14. Dependency Analysis

All Python and Node packages are organized into functional domains:

*   **Core:** `fastapi`, `uvicorn`, `requests`, `python-dotenv`, `pydantic`, `pydantic-settings`, `python-multipart`, `psutil`, `react`, `react-dom`, `react-router-dom`, `axios`, `vite`.
*   **Security:** `bcrypt`, `cryptography`, `python-jose`, `PyJWT`, `passlib` (unused), `itsdangerous` (unused).
*   **Networking:** `scapy`, `mitmproxy`, `tldextract`.
*   **Database:** `mysql-connector-python`.
*   **Frontend Visuals:** `framer-motion`, `lucide-react`, `socket.io-client`, `chart.js`, `react-chartjs-2`.
*   **AI/ML:** `scikit-learn`, `numpy`, `joblib`.
*   **DevOps / CI/CD:** `postcss`, `autoprefixer`, `tailwindcss`, `@tailwindcss/vite`, `eslint`, `globals`.

---

### 15. Architecture Diagram

```
                                +-------------------+
                                |   Web Browser     |
                                | (React Dashboard) |
                                +---------+---------+
                                          |
                        HTTPS (REST) /    |
                        WebSockets (WS)   |
                                          v
                                +---------+---------+
                                |    Edge Proxy     |
                                |     (Caddy)       |
                                +---------+---------+
                                          | (Internal Proxy)
                                          v
                                +---------+---------+
                                |  FastAPI Backend  |
                                |  (REST/WebSockets)|
                                +----+----+----+----+
                                     |    |    |
             +-----------------------+    |    +-----------------------+
             |                            |                            |
             v                            v                            v
    +--------+--------+          +--------+--------+          +--------+--------+
    |  MySQL Database |          |  Anomaly Engine |          |  Threat Engine  |
    | (network_sec)   |          | (IsolationForest)|          | (Beacon, Tunnel)|
    +--------+--------+          +-----------------+          +-----------------+
             ^
             | Ingestion Pipeline
             +-----------------------------------------+
                                                       |
                                                       | (HTTPS API)
                                                       |
                                            +----------+----------+
                                            |   Telemetry Agent /  |
                                            |   BYOD Gateway       |
                                            +----------+----------+
                                                       |
                                                       | (Packet Capture)
                                                       v
                                            +----------+----------+
                                            | Local Network / NIC |
                                            +---------------------+
```

---

### 16. Technology Inventory Table

| Technology | Category | Version | Used? | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **FastAPI** | Backend Framework | v0.100+ | Yes | [main.py](file:///c:/Users/prem/Network/app/main.py#L142) |
| **React** | Frontend Library | v18.3.1 | Yes | [package.json](file:///c:/Users/prem/Network/frontend/package.json#L18) |
| **Scapy** | Network Packet Sniffing | v2.5.0+ | Yes | [capture.py](file:///c:/Users/prem/Network/shared/collector/capture.py#L18) |
| **MySQL** | Persistent Database | v8.0 | Yes | [docker-compose.yml](file:///c:/Users/prem/Network/docker-compose.yml#L4) |
| **Mitmproxy** | SSL/TLS Interception | v9.0+ | Yes | [mitm_addon.py](file:///c:/Users/prem/Network/agent/dpi/mitm_addon.py) |
| **Scikit-learn** | Machine Learning Anomaly | v1.2+ | Yes | [model.py](file:///c:/Users/prem/Network/app/ml/model.py#L3) |
| **Caddy** | Reverse Proxy / mTLS | v2.x | Yes | [Caddyfile](file:///c:/Users/prem/Network/infra/deployment/server/Caddyfile) |
| **Nginx** | Frontend Web Server | alpine | Yes | [Dockerfile.frontend](file:///c:/Users/prem/Network/infra/docker/Dockerfile.frontend#L20) |
| **TailwindCSS** | Frontend Styling | v4.2.2 | Yes | [package.json](file:///c:/Users/prem/Network/frontend/package.json#L36) |
| **Framer Motion** | UI Transitions | v12.38.0 | Yes | [package.json](file:///c:/Users/prem/Network/frontend/package.json#L16) |
| **Socket.io** | Bidirectional WS | v4.8.x | Yes | [main.py](file:///c:/Users/prem/Network/app/main.py#L233) |
| **cryptography** | Cryptography Library | v40.0+ | Yes | [mtls.py](file:///c:/Users/prem/Network/agent/security/mtls.py#L17) |
| **bcrypt** | Password Encryption | v4.0+ | Yes | [security.py](file:///c:/Users/prem/Network/app/core/security.py#L4) |
| **passlib** | Password Management | v1.7.4 | No | Listed in `requirements.txt`, unused in code (using bcrypt direct). |
| **itsdangerous** | Token Utilities | v2.1.2 | No | Listed in `requirements.txt`, unused. |
| **mac-vendor-lookup** | OUI Resolving | v0.1.x | No | Listed in `requirements.txt`, replaced by local static mapping in constants.py. |

---

### 17. Feature-to-Technology Mapping

| Feature | Technologies Used |
| :--- | :--- |
| **User Authentication** | JWT (`python-jose`), Cookies, Bcrypt, FastAPI, CSRF Middleware, MySQL |
| **Collector Authentication** | HMAC-SHA256 request signatures, Nonces, MySQL |
| **Packet Capture** | Scapy sniffing, Linux Raw Sockets (`AF_PACKET`) |
| **DPI Interception** | TLS SNI decoder, HTTP Host parser, `mitmproxy` interceptor, browser launch hooks |
| **Threat Detection** | Python metrics (intervals, entropy calculations, bloom filters, counters) |
| **Flow Anomaly Detection** | Unsupervised Isolation Forest model (`scikit-learn`), NumPy, Joblib |
| **Device Fingerprinting** | Hostname regexes, OUI prefixes, DHCP options, mDNS parser, SSDP, active sockets |
| **Security Auditing** | SHA256 log chaining (`entry_hash`, `chain_hash`) |
| **Dashboard Display** | React, TailwindCSS, Framer Motion, Chart.js, Socket.IO WebSockets |

---

### 18. Unused Technologies

1.  `passlib[bcrypt]`: Declared in [requirements.txt](file:///c:/Users/prem/Network/requirements.txt#L21) but replaced by native [bcrypt](file:///c:/Users/prem/Network/app/core/security.py#L20-L28) function calls.
2.  `itsdangerous`: Declared in [requirements.txt](file:///c:/Users/prem/Network/requirements.txt#L10) but never imported.
3.  `mac-vendor-lookup`: Declared in [requirements.txt](file:///c:/Users/prem/Network/requirements.txt#L23) but replaced by local mapping inside [oui_detector.py](file:///c:/Users/prem/Network/app/engines/device/oui_detector.py).

---

### 19. Planned vs Implemented

*   **Raw Packet Capture:** **Fully Implemented**. Captures live flows via Scapy or Linux Raw Sockets.
*   **Deep Packet Inspection:** **Fully Implemented**. Extracts SNI/HTTP headers and dynamically intercepts browser endpoints using `mitmproxy`.
*   **Threat Engine (Beaconing, Tunneling, Scans):** **Fully Implemented**. Analyzes live metrics against thresholds.
*   **ML Anomaly Detection:** **Fully Implemented**. Fits and queries an Isolation Forest model.
*   **Cryptographic Log Chaining:** **Fully Implemented**. Asserts audit trail validity via a hash chain.
*   **Code Integrity Checking:** **Fully Implemented**. Signatures verified against manifest hashes.
*   **Windows OS-Level sniffer driver (Npcap/WinPcap installer):** **Planned Only**. The collector logs warning categories but expects pre-installed drivers.

---

### 20. Final Stack Summary

*   **Programming Languages:** Python, JavaScript (ES6), React JSX, SQL, HTML, CSS.
*   **Frontend Stack:** React, Vite, React Router, TailwindCSS, Framer Motion, Chart.js, Socket.io-client.
*   **Backend Stack:** FastAPI, Uvicorn, Python-SocketIO, Python-Jose, Cryptography, Bcrypt.
*   **Database Stack:** MySQL 8.0, connection pooler.
*   **Networking Stack:** Scapy, Linux Raw Sockets (`socket.AF_PACKET`), Mitmproxy.
*   **Cybersecurity Stack:** Threat Engine (beaconing, brute force, exfiltration, DNS tunneling, scans), Device Fingerprinting (OUI, hostname, DHCP, mDNS, SSDP, prober), Risk correlation (T1110, T1071, T1048), VPN detector (Tor, ASNs, ports), Audit chaining, Code integrity checker.
*   **AI/ML Stack:** Scikit-learn (Isolation Forest), NumPy, Joblib.
*   **DevOps / Infrastructure:** Docker, Docker Compose, Caddy, Nginx, GitHub Actions CI.
