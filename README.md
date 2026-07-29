<div align="center">

# NetVisor

### Enterprise-grade Network Visibility, Endpoint Telemetry & Security Monitoring Platform

A modular, self-hosted platform for monitoring managed endpoints and providing metadata-only visibility for BYOD environments.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=black)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?logo=mysql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

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
- Health checks
- Audit-friendly architecture

## Platform

- RESTful API
- Docker deployment
- Modular architecture
- Cross-platform support
- Automated testing
- CI/CD pipeline

---

# System Architecture

```text
                    +----------------------+
                    |  Managed Endpoints   |
                    +----------+-----------+
                               |
                               | Agent
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
├── app/                  Backend API & Business Logic
├── agent/                Endpoint Monitoring Agent
├── gateway/              BYOD Gateway Service
├── frontend/             React Dashboard
├── shared/               Shared Libraries
├── infra/                Infrastructure & Deployment
├── docs/                 Project Documentation
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

## Clone the Repository

```bash
git clone https://github.com/premkumarteli/NetVisor.git
cd NetVisor
```

## Initialize Environment

```bash
python scripts/init_env.py
```

Update your `.env` configuration with your local settings.

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

# Project Documentation

Documentation is available in the `docs/` directory.

- Quick Start Guide
- Environment Setup
- Architecture Specification
- Deployment Guide
- Security Operations
- Runbook

---

# Screenshots

> Replace these placeholders with actual screenshots.

| Dashboard | Devices |
|-----------|---------|
| *(Screenshot)* | *(Screenshot)* |

| Alerts | Network Overview |
|--------|------------------|
| *(Screenshot)* | *(Screenshot)* |

---

# Roadmap

- [x] Backend API
- [x] Endpoint Agent
- [x] Gateway Service
- [x] React Dashboard
- [x] Docker Support
- [x] CI/CD Pipeline
- [ ] Threat Intelligence Integration
- [ ] Advanced Detection Engine
- [ ] SIEM Integration
- [ ] Cloud Deployment
- [ ] Multi-tenant Support

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

Run backend tests:

```bash
pytest
```

Run frontend checks:

```bash
npm run lint
npm run build
```

---

# Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

# Disclaimer

NetVisor is intended for educational, research, and authorized administrative environments. Ensure you have appropriate authorization before monitoring any network or endpoint.

---

# License

This project is licensed under the **MIT License**.

---

# Author

**Premkumar Teli**

Information Science & Engineering Student  
Backend Development • AI • Cybersecurity

- GitHub: https://github.com/premkumarteli
- LinkedIn: https://www.linkedin.com/in/premkumar-teli-s9

---

<div align="center">

### ⭐ If you find this project useful, consider giving it a star!

</div>
