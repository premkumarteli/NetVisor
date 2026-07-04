# NetVisor Benchmark Specification

This document defines the baseline hardware environment, workload characteristics, and execution criteria for NetVisor system verification and saturation testing.

## 1. Target Hardware & OS Baseline

Benchmarks must be executed under a standardized environment to ensure comparative validity:
- **Processor**: AMD Ryzen 5 or Intel Core i5 (minimum 6 physical cores, 12 threads @ 3.5GHz base).
- **Memory**: 16 GB DDR4/DDR5 RAM allocated to system container/process space.
- **Storage**: PCIe NVMe SSD (minimum sustained sequential write speed of 1500 MB/s).
- **Operating System**: Ubuntu 22.04 LTS or Windows 11 Enterprise (virtualization via WSL2 allowed).
- **Network Interface**: Virtual loopback interface (`lo`) for local microservice traffic, supporting up to 10 Gbps loopback throughput.

## 2. Test Workloads & Capture Sets

The replay harness uses a mix of standard network capture files parsed into serialized Protobuf flow records:
1. **CIC-IDS2017**: Standard intrusion detection dataset containing diverse benign and common network attacks (DDoS, Brute Force, XSS, etc.).
2. **CTU-13**: Botnet traffic captures containing peer-to-peer and command-and-control bot activity mixed with normal background traffic.
3. **MAWI**: Highly aggregated traffic captures from the trans-Pacific link between Japan and the US, providing realistic large-scale backbone flow characteristics.
4. **Synthetic/Enterprise PCAP**: Local telemetry containing multi-tenant SMB structures, standard DNS queries, HTTP/HTTPS web sessions, and mTLS handshakes.

## 3. Performance Metrics & SLOs

Under the target workload, the system must satisfy the following service level objectives (SLOs):

| Metric | Target Value | Hard Maximum Constraint |
|---|---|---|
| **Flow Throughput** | $\ge 10,000$ flows/second | Sustained for 15 minutes |
| **P95 API Ingestion Latency** | $\le 10$ ms | $\le 50$ ms |
| **Correlation Queue Lag** | $\le 50$ flows | $\le 200$ flows |
| **CPU Utilization (Server)** | $\le 50\%$ (of 6 cores) | $\le 80\%$ |
| **RAM Utilization (Server)** | $\le 2.0$ GB | $\le 4.0$ GB |
| **Database Insertion Latency** | $\le 5$ ms | $\le 15$ ms |

## 4. Run Conditions

- **Warm-Up Period**: 60 seconds (system initialization, database connection pool warm-up, Python/Go/Rust VM/runtime compilation warm-up).
- **Measurement Window**: 15 minutes (sustained 10,000 flows/sec).
- **Cool-Down Period**: 30 seconds (queue drain, file handles flush).

## 5. Standardized Reproducible Runtime Configuration

To ensure consistent and directly comparable results across execution runs, the following standard configuration must be applied:

### FastAPI / Uvicorn Server Environment
- **Process Worker Count**: `1` (forces single-core bottleneck analysis for throughput).
- **Logging Level**: `INFO` (minimizes local terminal I/O latency while preserving operational audits).
- **mTLS Validation**: `disabled` (bypassed locally to benchmark raw network parsing throughput).
- **Chaos Testing Middleware**: Registered (`NETVISOR_CHAOS_TESTING=1`), but no chaos headers (`X-Chaos-*`) passed during execution.

### Database (MySQL) Configuration
- **Connection Pool Size**: `10` active connections.
- **Autocommit Status**: `False` (all ingest batches inserted via transactions to avoid disk write bottlenecks).
- **Batching Parameters**: `500` flows per request payload.
- **Bootstrap DB State**: Truncate/delete all rows in `flow_ingest_batches` and `flow_logs` prior to start to prevent backlog backpressure (HTTP 429).

