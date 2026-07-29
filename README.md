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
├── app/                  Backend API & Services
├── agent/                Endpoint Agent
├── gateway/              BYOD Gateway
├── frontend/             React Dashboard
├── shared/               Shared Libraries
├── infra/                Infrastructure
├── docs/                 Documentation
├── scripts/              Utility Scripts
├── tests/                Automated Tests
├── benchmarks/           Performance Benchmarks
└── .github/              GitHub Actions
```

---

# Technology Stack

| Layer | Technologies |
|-------|--------------|
| Backend | Python, FastAPI |
| Frontend | React, JavaScript, Tailwind CSS |
| Database | MySQL, Redis |
| Infrastructure | Docker, GitHub Actions |
| Deployment | Linux, Windows |

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

> Replace these placeholders with actual screenshots.

## Dashboard

![Dashboard](docs/images/dashboard.png)

## Devices

![Devices](docs/images/devices.png)

## Alerts

![Alerts](docs/images/alerts.png)

## Network Overview

![Network Overview](docs/images/network-overview.png)

---

# Roadmap

- [x] Backend API
- [x] Endpoint Agent
- [x] Gateway Monitoring
- [x] React Dashboard
- [x] Docker Support
- [x] Automated Testing
- [ ] Threat Intelligence Integration
- [ ] Advanced Detection Engine
- [ ] SIEM Integration
- [ ] Cloud Deployment
- [ ] Multi-Tenant Support

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
