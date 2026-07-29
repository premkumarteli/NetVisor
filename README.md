<div align="center">

# NetVisor

### Intelligent Network Visibility & Security Monitoring Platform

A self-hosted security workspace for managed endpoints and metadata-only BYOD visibility.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688)
![React](https://img.shields.io/badge/React-Frontend-61DAFB)
![MySQL](https://img.shields.io/badge/MySQL-Database-blue)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

---

# Overview

NetVisor is a modular, self-hosted network visibility and security monitoring platform designed to provide centralized monitoring of managed endpoints while maintaining metadata-only visibility for BYOD (Bring Your Own Device) environments.

The platform combines endpoint telemetry, gateway-based network metadata collection, and a web-based analyst dashboard to help administrators monitor devices, investigate security events, and analyze network activity from a single interface.

---

# Key Features

- Real-time endpoint telemetry
- Metadata-only BYOD monitoring
- Centralized analyst dashboard
- Network traffic monitoring
- Endpoint agent management
- Gateway-based network collection
- Device inventory management
- Health monitoring
- Security event logging
- REST API
- Docker deployment support
- Modular architecture

---

# System Architecture

```text
                +----------------+
                |   Endpoints    |
                | (Managed PCs)  |
                +-------+--------+
                        |
                        | Agent
                        |
                +-------v--------+
                |   NetVisor     |
                |     API        |
                +-------+--------+
                        |
       +----------------+----------------+
       |                                 |
+------v------+                 +--------v-------+
|   Gateway   |                 |    MySQL DB    |
| BYOD Traffic|                 | Configuration  |
+------+------+\                +--------+-------+
       |                                 |
       +---------------+-----------------+
                       |
                +------v------+
                | React UI    |
                | Dashboard   |
                +-------------+
```

---

# Repository Structure

```
NetVisor
│
├── app/               Backend API & Services
├── agent/             Endpoint Agent
├── gateway/           BYOD Gateway
├── frontend/          React Dashboard
├── shared/            Shared Libraries
├── infra/             Infrastructure & Deployment
├── docs/              Documentation
├── scripts/           Utility Scripts
├── tests/             Automated Tests
└── benchmarks/        Performance Benchmarks
```

---

# Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- Redis
- MySQL

### Frontend

- React
- JavaScript
- Tailwind CSS

### Infrastructure

- Docker
- GitHub Actions
- Linux
- Windows

---

# Quick Start

Clone the repository

```bash
git clone https://github.com/premkumarteli/NetVisor.git
cd NetVisor
```

Initialize the environment

```bash
python scripts/init_env.py
```

Configure your `.env`

Initialize the database

```bash
mysql -u root -p < infra/database/init.sql
```

Run the backend

```bash
python run_server.py
```

Run the endpoint agent

```bash
python run_agent.py
```

Run the gateway

```bash
python run_gateway.py
```

Start the frontend

```bash
cd frontend
npm install
npm run dev
```

---

# Documentation

- Quick Start
- Architecture Specification
- Deployment Guide
- Security Operations
- Runbook
- API Documentation

Documentation is available inside the `docs/` directory.

---

# Screenshots

> Add screenshots here.

Dashboard

Device Monitoring

Alerts

Network Overview

Traffic Analysis

---

# Project Status

Current Status

- Active Development

Upcoming Features

- Threat Intelligence Integration
- Advanced Detection Engine
- SIEM Integration
- Improved Analytics
- Cloud Deployment

---

# Development Workflow

```bash
# Backend

python run_server.py

# Agent

python run_agent.py

# Gateway

python run_gateway.py

# Frontend

cd frontend
npm run dev
```

---

# Testing

Run all tests

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

# License

This project is licensed under the MIT License.

---

# Author

**Premkumar Teli**

Information Science Engineering Student

Backend Development • AI • Cybersecurity

LinkedIn:
https://www.linkedin.com/in/premkumar-teli-s9

GitHub:
https://github.com/premkumarteli

---

## If you find this project useful, consider giving it a ⭐.
