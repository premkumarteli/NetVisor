# Walkthrough - Milestone 1 Refinement Completion

We have successfully refined all **Milestone 1** exit criteria and completed the requested implementation refactoring according to the VP of Engineering's guidelines.

---

## Refinement Outcomes

### 1. True Latency Percentile Computations
- **Prototypes:** Refactored the Python and Rust prototypes to store individual traversal duration samples and compute true sorted P50, P95, and P99 percentiles instead of averages.
- **Workload Generator:** Updated the collector to compile high-resolution float arrays of response latencies and calculate true percentiles via `numpy.percentile`.

### 2. High-Fidelity OS Process Tree Measurements (Observability Metrics Fixed)
- **Rust Integration:** Replaced the memory placeholder in `main.rs` with OS-native queries. On Windows, we use `GetProcessMemoryInfo` from the `windows-sys` crate. On Linux, we parse `/proc/self/statm`.
- **Server Process Tree Summing:** Refactored `ResourceMonitor` to recursively find all descendant processes of the Uvicorn wrapper and sum their RSS memory. This resolved the "3.3 MB" monitor-only footprint, reporting a true baseline of **~123 MB**.
- **Stateful CPU Percent Cache:** Implemented a stateful cache of `psutil.Process` instances inside `ResourceMonitor` to prevent the first-call `0.0%` value error. This correctly captures actual server CPU load under workload (averaging **46.3%** under ingestion).

### 3. Removed Simulated Go Benchmarks
- Removed all simulated Go results from the comparison reports. Only live, empirically measured data for Python and Rust is compared.

### 4. Deferral of Rust Selection
- Updated the benchmark results to state: *"Rust remains the leading candidate pending end-to-end workload validation. A final production runtime selection will be deferred until the complete telemetry integration and end-to-end workload has been benchmarked."*

### 5. Production-Grade Isolated Chaos Engineering
- **Context-Scoped Variables:** Created `app/middleware/chaos_context.py` using Python's thread-safe, asyncio-safe `contextvars`.
- **Safe Middleware:** Refactored `ChaosMiddleware` to populate these context variables strictly for the scope of the request instead of globally monkey-patching module attributes.
- **DB Driver Integration:** Updated `get_db_connection` in `app/db/session.py` to inspect the active context variables thread-safely, raising database connection failures or sleeping to simulate latency.
- **Integration Test:** Created [real_infrastructure_chaos.py](file:///c:/Users/prem/Network/tests/chaos/real_infrastructure_chaos.py). Verified that a request with `X-Chaos-DB-Down: 1` correctly triggers a 503 error, while a concurrent normal request at the exact same moment completes successfully (200 OK) with zero leakage.

### 6. MySQL InnoDB Deadlock Characterization
- Characterized the database bottleneck: concurrent `INSERT ... ON DUPLICATE KEY UPDATE` queries against the unique index keys in the `sessions` and `external_endpoints` tables cause InnoDB transactions to lock-overlap. Threads wait to upgrade Shared (S) locks to Exclusive (X) locks concurrently, creating a circular wait (deadlock) that InnoDB rolls back.

### 7. Versioned Benchmark Specification
- Froze the benchmark parameters as specification version `1.0.0` in [benchmark_spec.md](file:///c:/Users/prem/Network/benchmarks/benchmark_spec.md).

---

## Empirical Verification Results

### 1. Correlation Engine Benchmarks
Compiled and executed the revised prototypes:
```
| Runtime Language | Ingestion Throughput (edges/sec) | P50 Latency (ms) | P95 Latency (ms) | P99 Latency (ms) | Time-Wheel Cleanup (ms) | Memory Footprint (RSS MB) |
|---|---|---|---|---|---|---|
| Python | 121,183.2 | 0.1859 | 0.4465 | 0.9559 | 28.2403 | 131.40 |
| Rust | 197,805.5 | 0.0760 | 0.1593 | 0.2501 | 8.5331 | 93.36 |
```

### 2. Workload Ingestion Results
Executed a clean run of the modular synthetic generator (`10,000 flows/sec` workload):
- **Duration:** 10.30 seconds
- **Total Flows Sent:** 100,000
- **Throughput:** 9,704.91 flows/second
- **P50 Latency:** 12.39 ms
- **P95 Latency:** 105.81 ms
- **P99 Latency:** 165.73 ms
- **Errors:** 0
- **Server CPU**: 46.3% (summed tree average)
- **Server Memory**: 123.1 MB (summed tree average)
- **Time-Series Log:** Exported to `benchmarks/performance_time_series.csv`.
- **ASCII Charts:** Generated line plots in `benchmarks/performance_results.md` representing CPU, RAM, and DB queue depth progression.

---

# Milestone 2 — Day 1: Bug Fixes & Pipeline Scaffolding

**Date:** 2026-06-27

## Program Status Update

Milestone 1 was formally **accepted** by the VP of Engineering with an overall score of **9.5/10**. The Architecture Review Board is now dissolved. All future reviews will evaluate running software, not design documents. Milestone 2 (Production Pipeline Integration) is **approved and in progress**.

---

## 1. Critical Bug Fixes

Three blocking errors prevented the server, agent, and gateway from operating together.

### 1.1 Missing `prometheus_client` Module
- **Error:** `ModuleNotFoundError: No module named 'prometheus_client'`
- **Root Cause:** The Prometheus middleware was added in Milestone 1 but the dependency was never added to `requirements-server.txt`.
- **Fix:** Installed `prometheus-client` and added it to both [requirements-server.txt](file:///c:/Users/prem/Network/requirements-server.txt) and [requirements.txt](file:///c:/Users/prem/Network/requirements.txt).

### 1.2 Conflicting `socketio` Package
- **Error:** `AttributeError: module 'socketio' has no attribute 'AsyncServer'`
- **Root Cause:** A bare `socketio` package (v0.2.1) was installed alongside `python-socketio`, shadowing the correct module.
- **Fix:** Uninstalled the conflicting `socketio` package and force-reinstalled `python-socketio`.

### 1.3 Agent & Gateway 400 Errors (Protocol Version Header)
- **Error:** All `/api/v1/collect/*` and `/api/v1/gateway/*` endpoints returned `400 Bad Request` with `"X-Protocol-Version header is required."`
- **Root Cause:** The mTLS middleware in [mtls_middleware.py](file:///c:/Users/prem/Network/app/middleware/mtls_middleware.py) enforces an `X-Protocol-Version` header on all protected paths, but neither the agent nor gateway transport layer was sending it.
- **Fix:** Added `"X-Protocol-Version": "1.0.0"` to the default `headers` dict in the `request()` method of both:
  - [agent/security/transport.py](file:///c:/Users/prem/Network/agent/security/transport.py) (line 275)
  - [gateway/security/transport.py](file:///c:/Users/prem/Network/gateway/security/transport.py) (line 191)
- **Verified:** After applying the fix, the agent successfully completed heartbeats, device sync, and flow uploads:
  ```
  [+] Heartbeat sent. Agent active.
  [+] Discovered devices synchronized.
  [+] Telemetry batch upload successful.
  ```

---

## 2. Milestone 2 Infrastructure Scaffolding

### 2.1 Docker Compose — Redis & ClickHouse Services
Added two new service definitions to [docker-compose.yml](file:///c:/Users/prem/Network/docker-compose.yml):
- **Redis** (`redis:7-alpine`) — message stream for async flow ingestion, port 6379, with health check and persistent volume.
- **ClickHouse** (`clickhouse/clickhouse-server:23.8-alpine`) — columnar analytical database for high-throughput flow log storage, ports 8123/9000, with health check and persistent volume.

### 2.2 Dependencies
- Added `redis` and `clickhouse-connect` to [requirements-server.txt](file:///c:/Users/prem/Network/requirements-server.txt) and [requirements.txt](file:///c:/Users/prem/Network/requirements.txt).
- Installed both packages locally.

### 2.3 Configuration
Added the following settings to [app/core/config.py](file:///c:/Users/prem/Network/app/core/config.py):
| Setting | Default | Env Variable |
|---|---|---|
| `REDIS_HOST` | `localhost` | `NETVISOR_REDIS_HOST` |
| `REDIS_PORT` | `6379` | `NETVISOR_REDIS_PORT` |
| `CLICKHOUSE_HOST` | `localhost` | `NETVISOR_CLICKHOUSE_HOST` |
| `CLICKHOUSE_PORT` | `8123` | `NETVISOR_CLICKHOUSE_PORT` |
| `CLICKHOUSE_USER` | `default` | `NETVISOR_CLICKHOUSE_USER` |
| `CLICKHOUSE_PASSWORD` | *(empty)* | `NETVISOR_CLICKHOUSE_PASSWORD` |
| `CLICKHOUSE_DB` | `default` | `NETVISOR_CLICKHOUSE_DB` |

### 2.4 Database Client Modules
- **[app/db/redis_client.py](file:///c:/Users/prem/Network/app/db/redis_client.py):** Thread-safe Redis connection pool manager with `get_redis_connection()` helper.
- **[app/db/clickhouse_client.py](file:///c:/Users/prem/Network/app/db/clickhouse_client.py):** ClickHouse client pool manager with automatic DDL schema migration on first connection.

### 2.5 ClickHouse Schema
Created [infra/clickhouse/schema.sql](file:///c:/Users/prem/Network/infra/clickhouse/schema.sql) with the `flow_logs` table definition:
- Engine: `MergeTree()`
- Partition: `toYYYYMM(last_seen)` (monthly partitions)
- Order: `(organization_id, last_seen, src_ip)`
- Columns mirror the MySQL `flow_logs` table schema for compatibility.

---

## 3. Files Changed

| File | Action | Description |
|---|---|---|
| `requirements-server.txt` | Modified | Added `prometheus-client`, `redis`, `clickhouse-connect` |
| `requirements.txt` | Modified | Added `prometheus-client`, `redis`, `clickhouse-connect` |
| `docker-compose.yml` | Modified | Added Redis and ClickHouse service definitions + volumes |
| `app/core/config.py` | Modified | Added Redis and ClickHouse configuration fields |
| `agent/security/transport.py` | Modified | Added `X-Protocol-Version: 1.0.0` header |
| `gateway/security/transport.py` | Modified | Added `X-Protocol-Version: 1.0.0` header |
| `app/db/redis_client.py` | **New** | Redis connection pool manager |
| `app/db/clickhouse_client.py` | **New** | ClickHouse client with DDL migrations |
| `infra/clickhouse/schema.sql` | **New** | ClickHouse flow_logs table DDL |

---

## 4. Next Steps

- Implement Redis Streams publishing in `buffer_flows()` (dual-write alongside existing MySQL queue).
- Create `app/services/stream_consumer.py` — Redis Streams consumer worker with XREADGROUP, batch XACK, XCLAIM for recovery, and dead-letter routing.
- Add ClickHouse bulk insert logic to the stream consumer worker.
- Add Prometheus metrics for stream length, consumer lag, and ClickHouse insert throughput.
- Run end-to-end verification with the full pipeline under sustained workload.


## Milestone 2 — Day 2: Telemetry Ingestion Pipeline Realignment & Security Hardening

**Date:** 2026-07-07

## 1. Summary of Accomplished Work

We have successfully addressed the integration bugs in the Milestone 2 ingestion and persistence architecture, creating a unified, type-safe, and secure pipeline:

### 1.1 Redis Stream Deserialization Type Safety
*   **Problem:** Redis stream messages are read as dictionary payloads, causing the database persistence and sanitization helpers to return `None` (due to expecting object attributes via `getattr`).
*   **Fix:** Refactored the `flow_writer_worker` consumer loop in `app/services/flow_service.py` to deserialize dictionary lists back into valid Pydantic `FlowBase` objects using the pre-existing `FLOW_BATCH_ADAPTER` helper:
    ```python
    flows = list(FLOW_BATCH_ADAPTER.validate_python(json.loads(flows_json or "[]")))
    ```
*   **Outcome:** Redis stream flows now validate and persist correctly, preventing telemetry dropping.

### 1.2 Consolidated Single-Path Database Writing
*   **Problem:** Duplicate writes to `flow_logs` and multiple overlapping threat/alert evaluations occurred between `flow_writer_worker` and `EventDispatcher`, introducing race conditions and blocking ClickHouse ingestion.
*   **Fix:** 
    *   Removed `_threat_worker` and `_db_writer_worker` from `EventDispatcher` in [event_dispatcher.py](file:///c:/Users/prem/Network/app/services/event_dispatcher.py). The dispatcher now acts purely as an in-memory dashboard metric counter updater (`_metrics_worker`) and logger.
    *   Routed all MySQL and ClickHouse writes exclusively through the `flow_writer_worker` path.
    *   Integrated live `LiveTelemetryStore` alert updates and Prometheus `ALERTS_GENERATED` metric incrementation into the single write path.
    *   Updated the tests in `tests/test_live_telemetry.py` to assert against the new simplified model.

### 1.3 Uniform Agent Ingestion
*   **Problem:** The `/api/v1/agents/batch` API endpoint bypassed the Redis and ClickHouse pipeline, enqueuing raw batches directly to `EventDispatcher`'s local queue.
*   **Fix:** Refactored `/api/v1/agents/batch` in [agents.py](file:///c:/Users/prem/Network/app/api/agents.py) to validate payloads into `FlowBase` objects (enforcing secure tenant mapping for `agent_id` and `organization_id`) and delegate directly to `flow_service.buffer_flows()`.

### 1.4 Gated Chaos Middleware
*   **Problem:** `ChaosMiddleware` was active globally on all requests in production environments, making endpoints vulnerable to artificial failure simulation.
*   **Fix:**
    *   Added `CHAOS_ENABLED` flag to `Settings` in [config.py](file:///c:/Users/prem/Network/app/core/config.py).
    *   Conditionally initialized `ChaosMiddleware` in [main.py](file:///c:/Users/prem/Network/app/main.py) only when `settings.CHAOS_ENABLED` is `True`.

### 1.5 Redis Connection Socket Timeout Adjustment
*   **Problem:** The Redis connection pool in [redis_client.py](file:///c:/Users/prem/Network/app/db/redis_client.py) had a short socket timeout of `0.5` seconds. Blocking Redis Stream operations (like `XREADGROUP`) used `block=1000` or `block=2000` (1.0 to 2.0 seconds), causing constant socket timeouts (`Timeout reading from socket`) when no new data was present in the stream.
*   **Fix:** Increased `socket_timeout` to `5.0` seconds in [redis_client.py](file:///c:/Users/prem/Network/app/db/redis_client.py) to accommodate blocking reads.

---

## 2. Verification Outcomes
*   **Unit & Integration Tests:** Ran the test suite via `.venv\Scripts\pytest`. All **446 tests passed successfully** with **0 failures**, confirming that mock databases, mTLS authentication, threat engines, and api routes are fully aligned and correct.


