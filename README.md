<div align="center">

# NetVisor

### Enterprise-grade Network Visibility, Endpoint Telemetry & Security Monitoring Platform

A modular, self-hosted platform for monitoring managed endpoints and providing metadata-only visibility for BYOD environments.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?logo=mysql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Copyright](https://img.shields.io/badge/Copyright-All%20Rights%20Reserved-red)

</div>

---

# Overview

Traditional network monitoring solutions are often expensive, difficult to customize, or require organizations to send telemetry to third-party services.

**NetVisor** is a modular, self-hosted network visibility platform that enables centralized monitoring of managed endpoints while maintaining metadata-only visibility for BYOD (Bring Your Own Device) environments.

The platform integrates endpoint telemetry, gateway-based metadata collection, and a web-based analyst dashboard to provide administrators with actionable insights into network activity, endpoint health, and system operations from a single interface.

---

# Key Features

## Endpoint Monitoring

- Endpoint telemetry collection
- Device health monitoring
- Managed endpoint inventory
- Agent-based data collection

## Network Visibility

- Metadata-only BYOD monitoring
- Gateway-based traffic collection
- Device discovery
- Network activity visibility

## Security Operations

- Security event logging
- Centralized analyst dashboard
- Health monitoring
- Audit-friendly architecture

## Platform

- RESTful API
- Docker deployment
- Modular architecture
- Cross-platform support
- Automated testing
- GitHub Actions CI/CD

---

# System Architecture

```text
                    +----------------------+
                    |  Managed Endpoints   |
                    +----------+-----------+
                               |
                               | Endpoint Agent
                               |
                    +----------v-----------+
                    |     NetVisor API     |
                    +----------+-----------+
                               |
            +------------------+------------------+
            |                                     |
+-----------v-----------+             +-----------v-----------+
|      Gateway          |             |       MySQL           |
| Metadata Collection   |             | Configuration & Data  |
+-----------+-----------+             +-----------+-----------+
            |                                     |
            +------------------+------------------+
                               |
                    +----------v-----------+
                    |   React Dashboard    |
                    |  Analyst Workspace   |
                    +----------------------+
```

---

# Repository Structure

```text
NetVisor
│
├── backend/              FastAPI Server, Auth, Detection Engines & Telemetry APIs
├── agent/                Host Endpoint Telemetry Collector & TLS Inspection Proxy
├── gateway/              BYOD Network Metadata & Sensor Gateway
├── packet_engine/        Zero-Copy Packet Sniffer, DPKT Fast Parser & PCAP Engine
├── collector/            Legacy v1 Traffic Observation & Flow Extraction Library
├── engine/               Base Detection Engine Contracts & Finding Schemas
├── intel/                Domain Intelligence, ASN Feeds & App Classifiers
├── security/             Mutual TLS (mTLS), HMAC-SHA256 Signing & Key Management
├── proto/                Protobuf Definitions & Serialized Message Schemas
├── frontend/             Production React 18 / Tailwind Dashboard (Docker-deployed)
├── frontend-v2/          Next-Gen React 18 / Tailwind Dashboard (xyflow graph views)
├── Android_Application/  Android Endpoint Telemetry Client
├── infra/                Docker, Nginx, MySQL Schemas & Automated Database Migrations
├── docs/                 Architecture Specifications, Runbooks & Project Logbook
├── scripts/              Operational, Ingestion & Benchmark Utilities
├── tests/                Comprehensive Automated Test Suite (Unit, Integration, E2E)
└── benchmarks/           Performance, PCAP & Throughput Benchmarking Suites
```

---

# Technology Stack

| Layer | Technologies |
|-------|--------------|
| Backend & APIs | Python 3.11+, FastAPI, Uvicorn, AnyIO |
| Packet Inspection | DPKT (zero-copy memoryview), Scapy, WinPcap/Npcap, Mitmproxy |
| Frontends | React 18, Vite, Tailwind CSS v4, Lucide Icons, Chart.js, XYFlow |
| Datastores | MySQL 8.0 (metadata & transactions), ClickHouse (analytics), Redis 7+ (streams & cache) |
| Security & Identity | mTLS (X.509/CA), HMAC-SHA256, JWT (RS256/HS256), JA4 TLS Fingerprints |
| Infrastructure | Docker, Docker Compose, Nginx, GitHub Actions |
| Mobile Client | Android SDK (Java/Kotlin) |

---

# Getting Started

## Clone Repository

```bash
git clone https://github.com/premkumarteli/NetVisor.git
cd NetVisor
```

## Initialize Environment

```bash
python scripts/init_env.py
```

Configure your `.env` file.

## Initialize Database

```bash
mysql -u root -p < infra/database/init.sql
```

## Start Backend

```bash
python run_server.py
```

## Start Endpoint Agent

```bash
python run_agent.py
```

## Start Gateway

```bash
python run_gateway.py
```

## Start Frontend

```bash
cd frontend
npm install
npm run dev
```

---

# Documentation

Project documentation is available inside the **docs/** directory.

- Quick Start Guide
- Installation Guide
- Architecture Specification
- Deployment Guide
- Security Operations Guide
- API Documentation

---

# Screenshots

NetVisor features modern real-time operational interfaces built on React 18, Tailwind CSS, and Chart.js:

- **Executive Overview Dashboard**: High-level telemetry summaries, active device counts, aggregate bandwidth, and real-time fleet health metrics.
- **Topology & Packet Flow Graph**: Dynamic animated spoke flow charts powered by `@xyflow/react` in `frontend-v2`, mapping host-to-gateway interactions.
- **Asset Inventory & Risk Matrix**: Continuous host profiling detailing vendor MAC lookups, persistent UUIDs, operating system heuristics, and calculated threat scores.
- **Security Alert & Detection Console**: Instant incident triage with automated classification for C2 beaconing, port scans, and TLS anomalies.

---

# Roadmap

- [x] Backend API & Multi-Tenant Partitioning
- [x] Host Endpoint Telemetry Agent & MITM TLS Inspection
- [x] Gateway BYOD Traffic Collector & Hotspot Monitoring
- [x] Zero-Copy DPKT Fast Packet Parser
- [x] React Administrative Dashboard (Vite, Tailwind, Charts)
- [x] Next-Gen Flow Graph Visualization (`frontend-v2` with XYFlow)
- [x] Automated Database Migrations & Version Tracking
- [x] Threat Intelligence Integration (Tor, Dynamic ASN, Malware/C2 IP Feeds)
- [x] Advanced Detection Engine (Port Scanning, DNS Tunneling, WireGuard Heuristics)
- [x] Mutual TLS (mTLS) Certificate Revocation & Rotation
- [x] Docker Multi-Container Orchestration (`docker-compose.yml`)
- [x] Comprehensive Automated Test Suite (970+ Tests)
- [ ] Direct ClickHouse Analytical Query Routing (Deprecating write-only dual sink)
- [ ] Official Consolidation of `frontend-v2` into Docker Production Pipeline
- [ ] SIEM & Syslog Forwarder Integration
- [ ] Cloud Native Kubernetes (Helm / K8s) Deployment

---

# Development

### Backend

```bash
python run_server.py
```

### Agent

```bash
python run_agent.py
```

### Gateway

```bash
python run_gateway.py
```

### Frontend

```bash
cd frontend
npm run dev
```

---

# Testing

Run backend tests

```bash
pytest
```

Run frontend checks

```bash
npm run lint
npm run build
```

---

# Contributing

Contributions, bug reports, and feature requests are welcome.

Please open an issue before submitting major changes.

---

# Copyright

**© 2026 Premkumar Teli. All Rights Reserved.**

This repository is provided for **viewing and evaluation purposes only**.

No part of this project may be copied, modified, redistributed, republished, reverse engineered, or used in any commercial or non-commercial project without prior written permission from the author.

If you wish to use any portion of this project, please contact the author to obtain written permission.

---

# Author

## Premkumar Teli

**Information Science & Engineering Student**

Backend Development • AI • Cybersecurity

- **GitHub:** https://github.com/premkumarteli
- **LinkedIn:** https://www.linkedin.com/in/premkumar-teli-s9

---

<div align="center">

### ⭐ Thank you for visiting NetVisor!

</div>
