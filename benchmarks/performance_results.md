# NetVisor Ingestion Performance Results

Generated at: 2026-06-27T15:19:21+00:00
Benchmark Specification Version: `1.0.0`

---

## 1. Executive Summary & Throughput Discrepancy Analysis

During performance validation, we observed two distinct operational regimes reflecting different system database states:

### Regime A: Clean Baseline (Quiet DB)
*   **Throughput Achieved**: **9,704.91 flows/sec** (against a target of 10,000 flows/sec)
*   **P50 Latency**: 12.39 ms
*   **P95 Latency**: 105.81 ms
*   **P99 Latency**: 165.73 ms
*   **System State**: The database and ingestion queue were empty. Flow writing workers processed incoming batches with minimal database lock contention.

### Regime B: Congested Pipeline (DB Backlog & Deadlocks)
*   **Throughput Achieved**: **1,930.32 flows/sec**
*   **P50 Latency**: 3,392.14 ms
*   **P95 Latency**: 4,678.06 ms
*   **P99 Latency**: 4,694.87 ms
*   **System State**: Leftover background worker threads from previous high-throughput runs were writing backlog flow logs, triggering MySQL transaction deadlocks (`InternalError: 1213: Deadlock found when trying to get lock`). This backpressure blocked the FastAPI intake requests, causing API ingestion latency to spike and the client loop to drop throughput.

---

## 2. In-Depth MySQL InnoDB Deadlock Characterization

Through our performance profiling under Regime B, we characterized the root cause of the MySQL deadlock exceptions:

### The Bottleneck: Index Record Lock Upgrades
The ingestion pipeline writes logs to the database using an asynchronous worker queue. During processing, the worker calls two upsert methods:
1.  `session_service.upsert_session`
2.  `external_endpoint_service.observe_endpoint`

Both methods execute `INSERT ... ON DUPLICATE KEY UPDATE` queries against hot indexes:
- The unique primary key `session_id` in the `sessions` table.
- The unique primary key `endpoint_ip` in the `external_endpoints` table.

### The Locking Sequence
Under high ingestion concurrency:
1.  **Shared Locks (S-Locks)**: Multiple concurrent transaction threads attempt to insert/update the exact same `session_id` or `endpoint_ip` (due to the synthetic dataset repeating IPs/ports in cycles). InnoDB acquires Shared Locks (S) on the index records for those keys to verify existence.
2.  **Exclusive Locks (X-Locks) Upgrade**: Thread 1 attempts to upgrade its S-Lock on the record to an Exclusive Lock (X) to execute the `UPDATE` clause. It must wait for Thread 2 to release its S-Lock.
3.  **Circular Block**: Thread 2 simultaneously attempts to upgrade its S-Lock on the same record to an Exclusive Lock (X) to update. It must wait for Thread 1 to release its S-Lock.
4.  **Deadlock Detection**: InnoDB detects the circular locking dependency and terminates one transaction (`InternalError: 1213: Deadlock found when trying to get lock`), forcing it to rollback and retry.

This index record deadlock contention is the primary reason throughput degrades to ~1,900 flows/sec when a backlog accumulates, and confirms why moving to ClickHouse (which lacks transactional locking overhead) for flow logs is the correct architectural decision for Milestone 2.

---

## 3. Standardized Reproducible Benchmark Configuration

Every benchmark report is generated under the following versioned configuration (`v1.0.0`):

| Component | Parameter | Standardized Setting |
|---|---|---|
| **Server** | Port | `8000` |
| | Uvicorn Workers | `1` (single worker baseline) |
| | Logging Level | `INFO` (minimizes terminal I/O latency) |
| | mTLS mode | `disabled` (local network baseline) |
| **Database** | Pool Size | `10` active connections |
| | Autocommit | `False` (all inserts batched via transactions) |
| | Pre-run Cleanup | Truncate `flow_ingest_batches` and `flow_logs` |
| **Workload** | Batch Size | `500` flows per request |
| | Duration | `10` seconds |
| | Target Rate | `10,000` flows/second |
| | Chaos Mode | Enabled in middleware, no headers sent |

---

## 4. Resource Utilization (Regime A Baseline - 9.7k flows/sec)

*   **Average Server CPU (Summed Tree)**: **46.3%**
*   **Average Server Memory (Summed Tree)**: **123.1 MB**

### Server CPU Load Over Time (%)
*Range: 0.0 to 92.6*
```
                         *************************
                         *************************
                         *************************
                         *************************
                         *************************
                         *************************
                         *************************
**************************************************
```

### Server Memory Footprint Over Time (MB)
*Range: 110.6 to 135.6*
```
                         *************************
                         *************************
                         *************************
                         *************************
                         *************************
                         *************************
                         *************************
**************************************************
```

### Database Ingestion Queue Lag Over Time (Batches)
*Range: 0.0 to 1.0*
```
                                                   
                                                   
                                                   
                                                   
                                                   
                                                   
                                                   
**************************************************
```
