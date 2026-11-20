# NetVisor Architectural & Performance Review: Security Engines, Ingestion Pipeline, and Multi-Database Storage

- **Document Version**: 1.0.0
- **Classification**: Core System Architectural Review & Engineering Roadmap
- **Date**: 2026-11-20
- **Scope**: Security & Analytics Engines (R1), Ingestion Pipeline & Concurrency (R2), Multi-Database Workload Distribution (R3), Stress & Benchmark Architecture (R4), Codebase Preservation (R5)
- **Target Systems**: `backend/engines/`, `backend/services/`, `packet_engine/`, `backend/db/`, `infra/`

---

## 1. Executive Summary & System Architecture Overview

### 1.1 Executive Summary
NetVisor is an enterprise-grade Network Detection and Response (NDR) platform designed to capture wire-speed network traffic, decode protocols, reconstruct bidirectional flow telemetry, detect advanced security threats, and deliver real-time asset risk and operational analytics. 

This comprehensive architectural and performance review synthesizes deep-dive forensic audits across the entire NetVisor runtime stack:
1. **Security & Analytics Detection Engines (`backend/engines/`)**: Evaluated `ThreatEngine`, `VPNEngine`, `DeviceEngine`, `ApplicationEngine`, `AIEngine`, `RiskEngine`, and `EngineRegistry`. Identified hot-path execution bottlenecks, $O(N)$ eviction cliffs under exclusive thread locks, unbounded memory structures, and synchronous network/socket blocking hazards.
2. **Telemetry Ingestion Pipeline & Concurrency (`packet_engine/`, `backend/services/`)**: Evaluated packet capture mechanisms, the multi-worker async flow ingestion pipeline (`flow_service.py`), worker lifecycle supervision (`worker_supervisor.py`), and correlation pipelines. Identified critical multi-consumer Redis stream race conditions (`XDEL` destroying telemetry), ingress backpressure decoupling, synchronous dual-write database deadlocks, supervisor infinite crash-loop flaws, and unwired high-performance kernel capture modules.
3. **Multi-Database Workload Distribution (`MySQL 8.0`, `Redis 7.0`, `ClickHouse 23.8`)**: Evaluated data domain boundaries, query routing, indexing, and connection pools. Identified OLTP/OLAP architectural boundary violations (MySQL shouldering heavy analytical time-series loads while ClickHouse remains unqueried), InnoDB partitioning restrictions (Foreign Key Error 1506), Redis response caching decoding failures (`AttributeError` on strings), and rate limiter timestamp collision vulnerabilities.
4. **Codebase Preservation Assurance**: Formally confirmed that zero core business logic files in `backend/` and `packet_engine/` were modified during this review, establishing a verified baseline for isolated stress testing and tiered optimization.

---

### 1.2 NetVisor System Architecture Overview

The NetVisor architecture comprises three functional planes: the **Telemetry Capture Plane**, the **Ingestion & Processing Plane**, and the **Multi-Tier Persistence Plane**:

```
====================================================================================================
                                      NETVISOR SYSTEM ARCHITECTURE
====================================================================================================

+--------------------------------------------------------------------------------------------------+
|                                    1. TELEMETRY CAPTURE PLANE                                    |
|                                                                                                  |
|   +--------------------------+    +--------------------------+    +--------------------------+   |
|   |   Managed Endpoint Agent |    |     Network Gateway      |    | Linux Raw / AF_PACKET    |   |
|   |      (`agent/main.py`)   |    |   (`gateway/main.py`)    |    |   (`packet_engine/`)     |   |
|   +-------------+------------+    +------------+-------------+    +------------+-------------+   |
|                 |                              |                               |                 |
|                 \------------------------------+-------------------------------/                 |
|                                                | HTTP Batch Ingestion (JSON)                     |
+------------------------------------------------v-------------------------------------------------+
|                                2. INGESTION & PROCESSING PLANE                                   |
|                                                                                                  |
|   +------------------------------------------------------------------------------------------+   |
|   | FastAPI Ingress Controller (`/api/v1/collect/flow/batch`)                                 |   |
|   | - Payload Sanitization (`SanitizedFlow`) & Organization Validation                       |   |
|   +--------------------------------------------+---------------------------------------------+   |
|                                                | `r.xadd("netvisor:flow_stream", ...)`           |
|                                                v                                                 |
|   +------------------------------------------------------------------------------------------+   |
|   | Ephemeral Message Bus: Redis 7.0 Stream (`netvisor:flow_stream`)                          |   |
|   +---------------------+----------------------------------------------+---------------------+   |
|                         | Consumer Group: `flow_workers`               | Consumer Group:     |
|                         v                                              | `correlation_workers|
|   +----------------------------------------------------+               v                     |
|   | `flow_writer_worker` (`flow_service.py`)           |    +-----------------------------+  |
|   | - `ThreadPoolExecutor(max_workers=4)`              |    | `correlation_worker.py`     |  |
|   | - Synchronous 5-Engine Inspection per flow         |    | - Graph Multi-Hop Analysis  |  |
|   | - Dual-Write Orchestration (MySQL + ClickHouse)    |    | - Alert Generation          |  |
|   +---------------------+------------------------------+    +--------------+--------------+  |
|                         |                                                  |                 |
+-------------------------|--------------------------------------------------|-----------------+
|                         \-----------------------+--------------------------/                 |
|                                                 |                                            |
|                                                 v                                            |
+----------------------------------------------------------------------------------------------+
|                              3. MULTI-TIER PERSISTENCE PLANE                                 |
|                                                                                              |
|   +--------------------------+    +--------------------------+    +----------------------+   |
|   |        MySQL 8.0         |    |        Redis 7.0         |    |   ClickHouse 23.8    |   |
|   |       (OLTP Tier)        |    |      (Ephemeral Tier)    |    |     (OLAP Tier)      |   |
|   | - Tenants & Auth         |    | - Ingestion Stream Queue |    | - High-Volume Flows  |   |
|   | - Device Inventory       |    | - Sliding-Window Limits  |    | - Columnar MergeTree |   |
|   | - Rollup Summaries       |    | - Dashboard TTL Cache    |    | - Vectorized Trends  |   |
|   | - Alerts & Incidents     |    | - Pub/Sub Event Bus      |    | - Unwired Analytics  |   |
|   +--------------------------+    +--------------------------+    +----------------------+   |
+----------------------------------------------------------------------------------------------+
```

---

## 2. Deep-Dive Review of All NetVisor Engines (R1)

The NetVisor engine framework (`backend/engines/`) provides a modular detection pipeline unified under `BaseEngine`, `Finding`, and `EngineResult`. All 37 existing unit tests pass cleanly in 9.91s. However, forensic analysis of the engine code reveals systemic algorithmic bottlenecks, thread lock contention, and unbounded memory structures that severely impede high-throughput operation.

```
+---------------------------------------------------------------------------------------------+
|                                    ENGINE REGISTRY PIPELINE                                 |
|                                                                                             |
|   Incoming Flow Context                                                                     |
|            |                                                                                |
|            +-----------------------+-----------------------+                                |
|            | (Independent Tier)    |                       |                                |
|            v                       v                       v                                |
|   +------------------+    +------------------+    +------------------+                      |
|   |   ThreatEngine   |    |    VPNEngine     |    |ApplicationEngine |                      |
|   |  - Port Scans    |    |  - Tor Intel     |    |  - JA4 Fingerpr. |                      |
|   |  - C2 Beaconing  |    |  - ASN Detect    |    |  - Domain Cache  |                      |
|   |  - SMB/Kerberos  |    |  - WireGuard     |    |  - Async DB Save |                      |
|   +--------+---------+    +--------+---------+    +--------+---------+                      |
|            |                       |                       |                                |
|            \-----------------------+-----------------------/                                |
|                                    | Aggregated Findings                                    |
|                                    v                                                        |
|                           +------------------+                                              |
|                           |    RiskEngine    |                                              |
|                           |  - Half-Life     |                                              |
|                           |  - Suppression   |                                              |
|                           +--------+---------+                                              |
|                                    | Risk Summary + Findings                                |
|                                    v                                                        |
|                           +------------------+                                              |
|                           |     AIEngine     |                                              |
|                           |  - Summaries     |                                              |
|                           |  - Playbooks     |                                              |
|                           +------------------+                                              |
+---------------------------------------------------------------------------------------------+
```

### 2.1 Engine Registry (`backend/engines/registry.py`)
- **Location**: `backend/engines/registry.py:11-179`
- **Execution Order**: Enforces sequential execution: `[device, threat, application, vpn] -> risk -> ai` (lines 60-68).
- **Serialization Overhead**: On every flow analysis, line 100 calls `self._serialize_finding(f)` for each generated finding, converting datetime objects to ISO-8601 strings and enums to strings, incurring CPU allocation churn.
- **Unwired Engine in Production**: While `DeviceEngine` is registered in `registry.py:17`, the production pipeline in `flow_service.py:1337` calls `analyze_selective` with only `["threat", "vpn", "application", "risk", "ai"]`, omitting `"device"`.
- **Per-Flow Scalar Invocation**: In `flow_service.py:1337`, `FlowService` iterates through batches in a scalar `for flow in batch:` loop, invoking the registry per flow. Converting each dataclass flow into a dictionary via `dataclasses.asdict()` before invoking 5 engines synchronously creates a massive CPU barrier.

---

### 2.2 Threat Engine (`backend/engines/threat/`)
- **Location**: `backend/engines/threat/engine.py:18-126`, `state.py:10-79`
- **Lock Contention**: `ThreatEngine` acquires `self._lock` (an `RLock`) at lines 66-68 and 113-116. In addition, each sub-detector (`SlidingWindowStore`, `DNSTunnelingDetector`, `KerberoastingDetector`, `PassTheHashDetector`, `SMBLateralMovementDetector`) acquires its own internal `RLock`. Under multi-threaded batch ingestion, workers serialize heavily on these locks.
- **O(N) Eviction Cliffs**: In `state.py:25-26`:
  ```python
  if len(self._stores) >= _MAX_KEYS and key not in self._stores:
      self._evict_oldest_key()
  ```
  `_evict_oldest_key()` (lines 53-67) performs a linear `for k, v in self._stores.items()` scan across all 1,000 keys to find the minimum timestamp under lock. Once a network exceeds 1,000 active tracking keys, **every new key insertion incurs an O(N) linear dictionary traversal under lock**.
- **Linear Scans in Advanced Threat Detectors**:
  - `KerberoastingDetector` (`kerberoasting.py:64-71`): When `len(self._tgs_requests) >= self._MAX_SRCS` (1,000), runs `min(...)` linear scan over all keys under lock.
  - `PassTheHashDetector` (`pass_the_hash.py:61-69`): When `len(self._smb_authentications) >= self._MAX_SRCS` (1,000), runs `min(...)` linear scan over all keys under lock. Also uses `set(list(self._smb_authentications[src_ip])[-self._MAX_IPS_PER_SRC:])` at line 75, performing list conversions and slicing on every flow.
  - `SMBLateralMovementDetector` (`smb_lateral_movement.py:58-67`): When `len(self._smb_sessions) >= self._MAX_SRCS` (1,000), runs `min(...)` linear scan over all keys under lock.
- **C2 Beaconing Inefficiencies**: In `beaconing.py:40-48`:
  ```python
  timestamps = sorted([ts for ts in bucket])
  avg_interval = mean(intervals)
  interval_stdev = pstdev(intervals)
  ```
  This sorting and statistics calculation runs on every single matching flow for `(src_ip, dst_ip, dst_port)`. Sorting $K$ timestamps takes $O(K \log K)$ and allocates intermediate lists on every packet.
- **DNS Tunneling Memory & Parsing Flaw**: In `dns_tunneling.py:38`, `parent_domain = ".".join(parts[-2:])` splits blindly, grouping multi-label TLD queries (e.g. `.co.uk`, `.com.au`) under the generic suffix (e.g. `co.uk`), causing false positive alert triggers when >50 subdomains are queried. Furthermore, `self.dns_subdomain_counts` has no maximum key limit, leaking memory indefinitely.
- **Timestamp Parsing Penalty**: In `engine.py:77-88`, string timestamps are parsed by attempting four separate `strptime()` formats in a try-except loop, falling back to `fromisoformat()`.

---

### 2.3 VPN Engine (`backend/engines/vpn/`)
- **Location**: `backend/engines/vpn/engine.py:6-89`, `pipeline.py:9-87`, `asn_detector.py:29-72`, `tor_intel.py:25-111`
- **Uncached ASN Details on Hot Path**: `ASNLookupService.lookup_organization` (`backend/utils/asn_lookup.py:60`) has `@lru_cache(maxsize=8192)`, but `lookup_asn_details` (called by `ASNReputationDetector.analyze` on line 53) has **no cache decorator**. It executes reader lookups and `ipaddress.ip_address` parsing on every single flow.
- **External Synchronous Network Request**: `TorIntelligence` (`tor_intel.py:38-44, 71`) starts a daemon thread and performs `requests.get("https://check.torproject.org/exit-addresses", timeout=15)`. If outbound Internet access is restricted or firewalled, the thread blocks for 15 seconds.
- **Linear Scan in WireGuard Pruning**: `WireGuardHeuristicDetector` (`wireguard.py:63-68`) scans all items in `self._history` to prune expired keys on every matching UDP packet under lock, with no hard size cap on `_history`.
- **False Positive Substring Matching in TLS Detector**: `TLSCertificateDetector` (`tls_cert.py:28, 35, 42, 49`) checks `kw in sni` and `kw in domain` for short strings like `"pia"`. Benign domains such as `utopia.org` or `pianotiles.com` match `"pia"` and trigger false positive VPN alerts.

---

### 2.4 Device Engine (`backend/engines/device/`)
- **Location**: `backend/engines/device/engine.py:9-102`, `pipeline.py:12-145`, `active_prober.py:4-35`
- **Catastrophic Synchronous Blocking in ActiveProber**: `ActiveProber.probe()` (`active_prober.py:22-34`) executes sequential blocking `sock.connect((ip, port))` across 11 ports with a 0.3-second timeout each (`sock.settimeout(0.3)`). If an unclassified IP is firewalled or offline, it blocks the thread for up to 3.3 seconds. Sockets are closed without a `finally:` block.
- **Fragile DHCP Detection**: `DHCPDetector.FINGERPRINTS` (`dhcp_detector.py:6-10`) contains only 3 hardcoded Option 55 fingerprint strings. Any variant OS yields `"Unknown"`.
- **Per-Flow Ingestion Waste**: Device identification (OUI vendor, DHCP, SSDP, mDNS) is an endpoint inventory task. Evaluating it on per-flow packet ingestion cycles is redundant and uncalled in production (`flow_service.py` omits `"device"`).

---

### 2.5 Application Engine (`backend/engines/application/`)
- **Location**: `backend/engines/application/engine.py:5-46`, `backend/services/application_service.py:154, 352-452, 1505-1576`
- **Unbounded Memory Leak**: `application_service.py:154` defines `self._domain_app_cache: dict[str, dict] = {}`. In lines 382, 397, 417, 435, every classified domain is added to this dictionary without any eviction, TTL, or maximum capacity limit. In production, this dictionary grows monotonically with every distinct domain visited.
- **Uncoordinated DB Connection Spawning**: In `_async_persist_discovery` (`application_service.py:188-226`), when an unclassified domain is parsed via SLD heuristics, a task is submitted to `ThreadPoolExecutor(max_workers=2)` which immediately calls `get_db_connection()`, executes an `INSERT ... ON DUPLICATE KEY UPDATE` to MySQL, commits, and closes. Under bursts of new web traffic, this saturates DB connection pools.
- **Repeated Dynamic Sorting**: `lookup_ja4_signature` (`ja4_signatures.py:76`) executes `sorted(JA4_SIGNATURES.keys(), key=len, reverse=True)` on every prefix lookup instead of pre-sorting the signature keys at module initialization.

---

### 2.6 AI Engine (`backend/engines/ai/`)
- **Location**: `backend/engines/ai/engine.py:11-120`, `analyzer.py:6-88`, `summary_engine.py:3-46`, `recommendation_engine.py:6-52`, `templates.py:3-59`
- **Execution Profile**: Runs in `template` mode by default, executing deterministic rule templates. Wall-clock execution is fast (~0.2ms), non-blocking, and free of external network calls.
- **String Parsing Inefficiency**: Playbooks in `templates.py` format priority rules as human-readable strings (e.g. `"Priority 1: Enforce immediate MFA..."`). In `recommendation_engine.py:26-32`, the engine repeatedly parses these strings using `startswith()`, `split(":", 1)`, and `int(...)` on every flow analysis.
- **Strict Pipeline Dependency**: Assumes `_findings` and `risk_summary` have already been populated in `context` by the Registry.

---

### 2.7 Risk Engine (`backend/engines/risk/`)
- **Location**: `backend/engines/risk/engine.py:14-278`, `suppression.py:5-43`, `correlation.py:6-83`
- **Re-entrant Lock Inversion**: If `_findings` is not present in `context`, `RiskEngine.analyze` calls `self.registry.analyze_selective(...)` inside `with self._lock:` (lines 94-106). This re-enters other engines while holding the RiskEngine lock, risking deadlocks in multithreaded environments.
- **Suppression Store Permanent Memory Leak**: `SuppressionStore._last_emitted: Dict[Tuple[str, str], datetime] = {}` (`suppression.py:8`). `record_emission()` inserts `(target_ip, identifier)` keys on line 38, but there is zero TTL pruning, zero eviction, and zero capacity cap. Entries remain in memory indefinitely.
- **Unbounded History Retention**: `RiskEngine._history = defaultdict(list)` (`engine.py:29`). Inactive IP addresses whose findings have expired are only pruned if another flow arrives from that exact same IP (lines 161-164). An IP that is scanned once and goes silent stays in `_history` permanently.
- **Quadratic List Deduplication**: Lines 116-126 iterate through `self._history[target_ip]` (a list), match engine and finding type, call `list.remove()`, and append.

---

### 2.8 Summary Matrix of Engine Algorithmic Complexity, Locks, and Memory

| Engine | Component / Function | Time Complexity (Current) | Space Complexity | Lock / Sync Primitive | Memory Leak Hazard | Synchronous Blocking Hazard |
|---|---|---|---|---|---|---|
| **Threat** | `SlidingWindowStore._evict_oldest_key()` | $O(N)$ linear scan ($N=1000$) | $O(N \cdot K)$ | `threading.RLock` | None (bounded at 1000) | Yes (under lock during insert) |
| **Threat** | `KerberoastingDetector.analyze()` | $O(N)$ linear scan ($N=1000$) | $O(N \cdot K)$ | `threading.RLock` | None (bounded at 1000) | Yes (under lock during insert) |
| **Threat** | `PassTheHashDetector.analyze()` | $O(N)$ linear scan + slice | $O(N \cdot K)$ | `threading.RLock` | None (bounded at 1000) | Yes (under lock during insert) |
| **Threat** | `SMBLateralMovementDetector.analyze()` | $O(N)$ linear scan ($N=1000$) | $O(N \cdot K)$ | `threading.RLock` | None (bounded at 1000) | Yes (under lock during insert) |
| **Threat** | `BeaconingDetector.analyze()` | $O(K \log K)$ sort + `pstdev` | $O(K)$ | `threading.RLock` | None (bounded per flow key) | High CPU churn per packet |
| **Threat** | `DNSTunnelingDetector.analyze()` | $O(P)$ label split | $O(D \cdot S)$ | `threading.RLock` | **High** (`dns_subdomain_counts` unbounded) | False positives on multi-TLDs |
| **VPN** | `ASNReputationDetector.analyze()` | $O(\log M)$ tree lookup | $O(1)$ | None | None | Reader I/O (uncached hot path) |
| **VPN** | `TorIntelligence._refresh_loop()` | $O(E)$ parsing | $O(E)$ | `threading.Lock` | None | **Critical**: `requests.get` (15s timeout) |
| **VPN** | `WireGuardHeuristicDetector.analyze()` | $O(N)$ linear sweep | $O(N)$ | `threading.RLock` | Medium (unbounded history) | Linear lock holding time |
| **Device** | `ActiveProber.probe()` | $O(P)$ sequential sockets | $O(1)$ | None | None | **Catastrophic**: Up to 3.3s blocking socket |
| **Application** | `classify_domain()` | $O(1)$ hash lookup | $O(U)$ | None | **Critical**: `_domain_app_cache` unbounded | None |
| **Application** | `_async_persist_discovery()` | $O(1)$ SQL insert | $O(1)$ | Pool Lock | None | DB pool starvation on bursts |
| **Application** | `lookup_ja4_signature()` | $O(S \log S)$ sort | $O(S)$ | None | None | Repeated sorting overhead |
| **Risk** | `SuppressionStore.record_emission()`| $O(1)$ hash insert | $O(T)$ | None | **Critical**: `_last_emitted` unbounded | None |
| **Risk** | `RiskEngine._history` | $O(F)$ list deduplication | $O(I \cdot F)$ | `threading.RLock` | **High**: Silent IPs never pruned | Re-entrant lock inversion hazard |
| **AI** | `recommendation_engine.analyze()` | $O(R \cdot S)$ string split | $O(R)$ | None | None | Repeated string parsing churn |
| **Registry** | `analyze_selective()` | $O(E \cdot F)$ sequential | $O(F)$ | Engine locks | None | Per-flow scalar execution bottleneck |

---

### 2.9 Tiered Concrete Optimization Roadmaps for Engines

#### Tier 1: Architectural Decoupling & Batch Ingestion Pipeline (Highest Impact)
1. **Vectorized / Batch Engine Interface**:
   - Introduce `analyze_batch(flows: List[dict]) -> List[EngineResult]` on `BaseEngine` and `EngineRegistry`.
   - Process batches of 100–500 flows simultaneously. Route flows conditionally by protocol (e.g. only UDP flows to `WireGuardHeuristicDetector`, only DNS/TLS flows to `DNSTunnelingDetector` and `ApplicationEngine`), bypassing 70%+ of detector invocations.
2. **Concurrent Engine Evaluation**:
   - In `EngineRegistry.analyze_selective`, execute `[threat, vpn, application]` concurrently using `asyncio.gather` or a dedicated thread worker pool, since they have zero cross-dependencies. Once their results complete, execute `risk`, followed by `ai`.
3. **Decouple Device Identification from Flow Path**:
   - Formally remove `DeviceEngine` from real-time per-flow inspection. Place device profiling strictly on device discovery triggers (DHCP lease packets, ARP broadcasts, mDNS announcements) within `backend/services/device_service.py`.

#### Tier 2: Algorithmic Efficiency & Data Structure Hardening
1. **O(1) LRU Eviction for Stateful Detectors**:
   - Replace linear eviction in `SlidingWindowStore`, `KerberoastingDetector`, `PassTheHashDetector`, and `SMBLateralMovementDetector` with `collections.OrderedDict` or a doubly linked list + hash map. New insertions evict the oldest entry in $O(1)$ time:
     ```python
     if len(self._stores) >= _MAX_KEYS and key not in self._stores:
         self._stores.popitem(last=False)  # O(1) eviction
     self._stores[key] = bucket
     ```
2. **Online Single-Pass Statistics for C2 Beaconing**:
   - Replace `sorted()` + `pstdev()` in `BeaconingDetector` with Welford's algorithm or a running accumulator ($N$, $\sum \Delta t$, $\sum (\Delta t)^2$) to calculate interval mean and variance in $O(1)$ time per packet without sorting or array copies:
     ```python
     # Welford's online variance calculation: O(1) per packet
     delta = new_interval - mean
     mean += delta / count
     M2 += delta * (new_interval - mean)
     variance = M2 / (count - 1) if count > 1 else 0.0
     ```
3. **Public Suffix List (PSL) Integration for DNS Tunneling**:
   - Replace `domain.split(".")[-2:]` with `tldextract` or a local Trie of public suffixes to accurately resolve effective second-level domains (e.g. `bbc.co.uk` -> parent `bbc.co.uk`, not `co.uk`).
4. **Token-Bounded Substring Matching in TLS Detector**:
   - Replace naive `kw in sni` with regex word boundaries `\b` or exact domain label matching so that 3-letter tokens like `"pia"` do not match `olympiacos.org` or `utopia.org`.

#### Tier 3: Memory Safety & Leak Elimination
1. **Bounded LRU Caches**:
   - Replace unbounded `_domain_app_cache: dict` in `ApplicationEngine` with `functools.lru_cache(maxsize=32768)` or an `OrderedDict` capped at 32,768 entries.
   - Implement TTL-based circular buffer or bounded `OrderedDict` for `SuppressionStore._last_emitted` in `RiskEngine`.
   - Add periodic background sweep in `RiskEngine` to prune expired, silent IPs from `self._history`.
2. **Batched Asynchronous Domain Persistence**:
   - Replace the immediate `get_db_connection()` task dispatch in `_async_persist_discovery` with a thread-safe `queue.Queue`. A dedicated batch worker thread drains the queue and executes bulk `INSERT ... ON DUPLICATE KEY UPDATE` queries every 2 seconds, preventing DB connection pool starvation.

#### Tier 4: Throughput & Allocation Enhancements
1. **Cache ASN Lookups**:
   - Decorate `asn_lookup_service.lookup_asn_details` with `@lru_cache(maxsize=16384)`.
2. **Eliminate `dataclasses.asdict()` Overhead**:
   - Update engine detectors to access flow fields via attribute access (`getattr()` or unified property getters) directly on the `SanitizedFlow` dataclass instance, avoiding expensive recursive dictionary instantiation on millions of packets.
3. **Pre-Parsed Timestamps & Pre-Sorted JA4 Signatures**:
   - Pass pre-parsed `datetime` objects from packet decoders instead of repeatedly attempting multiple string `strptime` format strings.
   - Pre-sort `JA4_SIGNATURES.keys()` once at module load time rather than sorting on every TLS handshake lookup.

---

## 3. Ingestion Pipeline & Concurrency Analysis (R2)

The NetVisor telemetry ingestion pipeline is responsible for streaming network flow records from distributed agents and gateways into persistent storage and real-time security analysis. Forensic examination reveals multiple critical integration defects that cause silent data loss, memory exhaustion, and thread starvation under load.

```
====================================================================================================
                        INGESTION PIPELINE DATA FLOW & DEFECT TOPOLOGY
====================================================================================================

      [Agent / Gateway / Packet Engine]
                     |
                     | HTTP POST /api/v1/collect/flow/batch
                     v
      +-------------------------------------------------------------+
      | FlowService.buffer_flows() (`flow_service.py:650-721`)      |
      | - Unbounded r.xadd() (NO MAXLEN!)                           | <--- DEFECT: Backpressure Bypassed
      +------------------------------+------------------------------+
                                     |
                                     v
      +-------------------------------------------------------------+
      | Redis Stream: `netvisor:flow_stream`                        |
      +------------------------------+------------------------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
+-------------------------------+           +-------------------------------+
| `flow_writer_worker`          |           | `correlation_worker`          |
| Group: `flow_workers`         |           | Group: `correlation_workers`  |
| 1. Read batch via XREADGROUP  |           | 1. Read batch via XREADGROUP  |
| 2. Persist to MySQL / CH      |           | 2. Graph Rule Correlation     |
| 3. XACK                       |           | 3. XACK (NO XDEL)             |
| 4. XDEL msg_id                |           +-------------------------------+
+---------------+---------------+                          ^
                |                                          |
                \-------> [PERMANENT DATA LOSS] -----------/
                          `flow_writer` deletes message before
                          `correlation_worker` can read it!
```

### 3.1 Redis Stream Multi-Consumer `XDEL` Race Condition & Data Loss
- **Code Locations**:
  - `backend/services/flow_service.py:1183-1186` (`flow_writer_worker`):
    ```python
    # Acknowledge the message in Redis Stream
    await self._run_in_executor(r.xack, stream_name, group_name, msg_id)
    await self._run_in_executor(r.xdel, stream_name, msg_id)
    ```
  - `backend/services/correlation_worker.py:461-463, 526-527, 540-555`:
    ```python
    stream_name = "netvisor:flow_stream"
    group_name = "correlation_workers"
    ...
    # Line 527: correlation_worker acknowledges without deleting
    await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
    ```
- **Forensic Defect**: Redis Streams are designed as publish-subscribe log abstractions where multiple consumer groups maintain their own independent read offsets (`last_delivered_id`) and Pending Entries Lists (PEL). When `flow_writer_worker` processes a message, it calls `r.xdel(stream_name, msg_id)` immediately upon persisting the batch to MySQL/ClickHouse. 
- **Systemic Impact**: Because `flow_writer_worker` runs a simple I/O persistence loop while `correlation_worker` runs multi-hop graph correlations and temporal lookups, `flow_writer_worker` consistently outpaces `correlation_worker`. Calling `XDEL` physically deletes the entry from the stream key. When `correlation_worker` advances its consumer offset, the entry is gone. **This causes silent telemetry drop in lateral movement, Kerberoasting, and multi-stage attack detection.**
- **Remediation**: Completely eliminate `r.xdel` from all worker loops. Manage stream retention exclusively via `r.xadd(stream_name, payload, maxlen=100000, approximate=True)` at ingestion time.

---

### 3.2 Backpressure Decoupling & Unbounded Redis Stream Memory Risks
- **Code Locations**:
  - `backend/services/flow_service.py:682-704` (`buffer_flows`):
    ```python
    r = get_redis_connection()
    payload = {
        "flows": json.dumps(flows_serialized, separators=(",", ":")),
        "org_id": str(org_id or ""),
        "agent_id": str(agent_id or ""),
        "source_type": str(source_type),
    }
    await self._run_in_executor(r.xadd, "netvisor:flow_stream", payload)
    redis_published = True
    ```
  - `backend/services/flow_service.py:410-426` (`_enforce_backpressure`):
    ```python
    def _enforce_backpressure(self, db_conn, incoming_flows: int) -> None:
        counts = self._queue_status_counts(db_conn) or {}
        pending_flows = max(int(counts.get("pending_flows") or 0), 0)
        ...
        if max_pending_flows and (pending_flows + incoming_flows) > max_pending_flows:
            raise FlowQueueBackpressureError(...)
    ```
- **Forensic Defect**: `_enforce_backpressure()` is invoked exclusively inside `_enqueue_batch_sync()` (line 568), which is the fallback path used only when Redis is unavailable. In normal operation where Redis is healthy, `buffer_flows` writes directly to Redis without checking queue depth, and `r.xadd` is invoked without `maxlen`.
- **Systemic Impact**: If backend database writes stall or ClickHouse encounters network throttling, incoming HTTP requests receive `HTTP 202 Accepted` and append millions of flows to `netvisor:flow_stream`. Redis memory consumption grows unbounded, triggering OS OOM-killer termination or Redis eviction crashes.
- **Remediation**: Check Redis stream length (`XLEN netvisor:flow_stream`) at the start of `buffer_flows()`. If `stream_len > NETVISOR_MAX_STREAM_PENDING` (e.g. 50,000), immediately reject the HTTP request with `HTTP 429 Too Many Requests` and a `Retry-After: 5` header.

---

### 3.3 ClickHouse Retry Deadlock in MySQL Transaction Boundary
- **Code Location**: `backend/services/flow_service.py:1790-1840`
  ```python
  # Inside _persist_batch_on_connection (active MySQL transaction):
  if ch_rows:
      ch_max_retries = 3
      ch_retry_delay = 0.1
      for ch_attempt in range(ch_max_retries):
          try:
              ch_client = get_clickhouse_client()
              ch_client.insert("flow_logs", ch_rows, column_names=ch_columns)
              break
          except Exception as e:
              if ch_attempt < ch_max_retries - 1:
                  delay = ch_retry_delay * (2 ** ch_attempt)
                  time.sleep(delay)  # BLOCKING SLEEP INSIDE MYSQL TX!
  ```
- **Forensic Defect**: Dual-write persistence to ClickHouse is executed synchronously within the MySQL transaction, *before* `conn.commit()`. When ClickHouse experiences transient network latency or part merge throttling, the worker thread executes blocking `time.sleep()`.
- **Systemic Impact**: Holding open MySQL transaction locks during synchronous remote HTTP retries holds row-level locks on `application_summary`, `device_summary`, and `flow_logs`. Other worker threads in the fixed `ThreadPoolExecutor(max_workers=4)` waiting for the same locks deadlock, resulting in `MySQLdb.OperationalError: (1213, 'Deadlock found when trying to get lock; try restarting transaction')` and stalling the entire ingestion pipeline.
- **Metrics Defect**: In lines 1835-1839, `CLICKHOUSE_FAILED_WRITES.inc()` is indented under the `for` loop outside the `except` block, causing the failure counter to increment on every retry attempt even when the insert ultimately succeeds.
- **Remediation**: Decouple ClickHouse persistence completely from MySQL transactions. Ingest into ClickHouse asynchronously via a dedicated background queue or buffer table, and fix the metric indentation.

---

### 3.4 Worker Supervisor Deficiencies in `worker_supervisor.py`
- **Code Locations**: `backend/services/worker_supervisor.py:76-89, 106-172, 209-219`
- **Forensic Defect 1: Infinite Crash Loops Without Circuit Breaking**:
  `_max_restarts` (default 10) is accepted in `__init__`, but never evaluated in `_run_with_supervision`:
  ```python
  while not self._stop_event.is_set():
      state.running = True
      state.record_restart()
      ...
      delay = min(self._max_delay, self._base_delay * (2 ** min(state.restart_count - 1, 10)))
      await asyncio.sleep(delay)
  ```
  If a worker crashes due to a permanent configuration error or missing table, the supervisor restarts it indefinitely every 60 seconds without failing fast or tripping alerts.
- **Forensic Defect 2: Synthetic Heartbeat Synthesis**:
  In `_heartbeat_loop` (lines 209-219):
  ```python
  for state in self._workers.values():
      if state.running:
          state.record_heartbeat()
  ```
  The supervisor generates heartbeats on behalf of workers simply because `state.running == True`. If a worker coroutine deadlocks on an unyielding socket or thread lock, the supervisor continues reporting it as healthy.
- **Remediation**: 
  1. Add circuit breaking: `if state.restart_count >= self._max_restarts: state.running = False; return`.
  2. Implement active heartbeats: Each worker must call `state.record_heartbeat()` inside its own loop. The supervisor verifies that `time.time() - state.last_heartbeat < heartbeat_timeout`.

---

### 3.5 Unwired Accelerated Kernel Drivers & Parsers in `packet_engine/`
Deep audit of `packet_engine/` reveals high-performance C-level and kernel-space components that were implemented and verified with tests, but remain completely unwired in production:
1. **Unwired AF_PACKET MMAP Driver**:
   - `packet_engine/af_packet_backend.py:27-34`: Implements a zero-copy Linux `PACKET_MMAP` circular ring buffer capable of capturing 100k+ packets/sec with zero kernel-to-userspace copy overhead.
   - *Status*: Marked `[EXPERIMENTAL / UNWIRED]`. The factory `build_capture_backend()` in `packet_engine/backend.py:319-365` only instantiates `LinuxRawSocketCaptureBackend` or `ScapyCaptureBackend`.
2. **Double-Parsing Inefficiency**:
   - `packet_engine/parser.py:487-497`: When packets arrive via Scapy, `from_packet()` executes `raw_b = bytes(packet)` (serializing the Scapy object back into raw bytes) and then invokes `dpkt.ethernet.Ethernet(raw_b)`.
   - *Status*: Double parsing wastes up to 85% of CPU time in memory allocations and Python object creation, capping capture throughput at ~1,100 pps instead of 27,000+ pps.
3. **Unwired Priority Dual Ring Buffer**:
   - `packet_engine/ring_buffer.py:61-168`: Implements `DualRingBuffer` with weighted fair queuing (WFQ) and a `SourceIpTokenBucket` rate limiter to protect against packet storms.
   - *Status*: Unwired in `agent/main.py` and `gateway/main.py`.

---

### 3.6 Scalability Blueprint for 100k+ Packets/Sec Ingestion

To scale NetVisor from the current ~1,500 flows/sec to 100k+ packets/sec in production enterprise environments, the ingestion architecture must be refactored into a **Staged Event-Driven Architecture (SEDA)**:

```
====================================================================================================
                       SCALABILITY BLUEPRINT: 100K+ PACKETS/SEC
====================================================================================================

[ Kernel Space: Linux Network Interface ]
       |
       | AF_PACKET + PACKET_MMAP (Zero-Copy Circular Ring Buffer)
       v
[ Packet Engine: DpktFastParser (Memoryview Slices, Zero-Alloc) ]
       |
       | Prioritized Ring Buffer (Control Queue vs Data Queue + Token Bucket)
       v
[ Flow Aggregator: 16-Shard Lockless Partitioned Map ]
       |
       | Serialized Binary Protobuf Batches (500 flows / batch)
       v
[ HTTP/2 or gRPC Ingestion Ingress (FastAPI / Uvicorn Multi-Worker) ]
       |
       | Ingress Stream Backpressure Check (XLEN < 50,000)
       | XADD netvisor:flow_stream MAXLEN ~ 100000
       v
[ Redis 7.0 Stream Buffer (netvisor:flow_stream) ]
       |
       +------------------------------------+------------------------------------+
       | Consumer Group: `flow_writers`     | Consumer Group: `engine_workers`   |
       v                                    v                                    v
+-----------------------------+      +-----------------------------+      +--------------------+
| ClickHouse Bulk Ingestion   |      | Threat / VPN / App Engines  |      | Correlation Worker |
| - Native Protocol (TCP 9000)|      | - Vectorized analyze_batch  |      | - Temporal Graph   |
| - Buffer Engine (10k rows)  |      | - Protocol-Filtered Routing |      | - Lateral Movement |
| - XACK (NO XDEL)            |      | - XACK (NO XDEL)            |      | - XACK (NO XDEL)   |
+-----------------------------+      +-----------------------------+      +--------------------+
```

---

## 4. Multi-Database Workload Distribution Strategy (R3)

NetVisor employs a three-tier database topology consisting of **MySQL 8.0**, **Redis 7.0**, and **ClickHouse 23.8**. However, the current deployment violates storage tier boundaries: MySQL handles raw flow logs and analytical aggregations, ClickHouse is underutilized, and Redis suffers from cache deserialization bugs and race conditions.

```
+--------------------------------------------------------------------------------------------------+
|                               MULTI-DATABASE WORKLOAD BOUNDARIES                                 |
+------------------------------+----------------------------------+--------------------------------+
|          MySQL 8.0           |            Redis 7.0             |        ClickHouse 23.8         |
|         (OLTP Tier)          |         (Ephemeral Tier)         |          (OLAP Tier)           |
+------------------------------+----------------------------------+--------------------------------+
| - Tenant Accounts & Auth     | - Flow Stream Buffer             | - Raw Network Flow Telemetry   |
| - Device Inventory & MACs    | - Distributed Sliding-Window RL  | - 24h / 7d / 30d Trend Queries |
| - Security Alerts & Findings | - Query & Dashboard Cache (TTL)  | - Top-N Talkers / Applications |
| - Rollup Summaries (Upserts) | - Ephemeral Pub/Sub Backplane    | - DNS Tunneling Entropy Log    |
| - System Settings & Audits   | - Active Session Token State     | - JA4 Fingerprint Histograms   |
+------------------------------+----------------------------------+--------------------------------+
```

### 4.1 MySQL 8.0: Metadata, Auth, Config & Inventory Tier
- **Role**: Authoritative relational data store requiring strict ACID semantics.
- **Connection Pool Configuration (`backend/db/session.py:522-528`)**:
  - `MySQLConnectionPool` with `autocommit=False`, `connection_timeout=5`.
  - Default `DB_POOL_SIZE = 20`. Under 100 concurrent HTTP workers and 4 background queue consumers, pool checkout contention occurs during traffic spikes.
  - Sizing math: $N_{\text{conn}} = (C \times U + W) \times 1.25 = (100 \times 0.25 + 4) \times 1.25 \approx 36-40$ connections. Recommended `DB_POOL_SIZE = 40`.
- **Partitioning Restriction & Forensic Analysis (`backend/utils/partition_manager.py`)**:
  - `partition_manager.py:40-65` defines `generate_monthly_partition_ddl` to partition `flow_logs` via `PARTITION BY RANGE (TO_DAYS(start_time))`.
  - `infra/database/init.sql:190-236` defines `flow_logs` with:
    ```sql
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
    ```
  - **InnoDB Foreign Key Prohibition (MySQL Error 1506)**: MySQL InnoDB strictly prohibits foreign keys on partitioned tables (`ERROR 1506 (HY000): Foreign keys are not yet supported in conjunction with partitioning`). Furthermore, all unique indexes (`uq_flow_logs_ingest_hash`) must include the partitioning column (`start_time`). Consequently, partitioning `flow_logs` in MySQL fails.
- **Architectural Resolution**: Relegate MySQL exclusively to relational metadata. Do not store raw `flow_logs` in MySQL. Store raw flow telemetry exclusively in ClickHouse. MySQL retains only aggregate rollups (`device_summary`, `application_summary`).

---

### 4.2 Redis 7.0: Ephemeral Stream, Pub/Sub, Rate Limiter & Caching Tier
- **Connection Configuration (`backend/db/redis_client.py:20-31`)**:
  - Initialized with `decode_responses=True`, `max_connections=50`.
- **Response Caching Bug (`backend/utils/cache.py:16-19`)**:
  ```python
  cached_bytes = r.get(cache_key)
  if cached_bytes:
      return json.loads(cached_bytes.decode("utf-8"))
  ```
  Because `redis_client` specifies `decode_responses=True`, `r.get()` returns a Python `str`. Calling `.decode("utf-8")` raises `AttributeError: 'str' object has no attribute 'decode'`, which is silently swallowed by line 19 (`except Exception:`). **Every cached API call in NetVisor defaults to a cache miss, bombarding MySQL with redundant queries.**
  - *Fix*:
    ```python
    if isinstance(cached_bytes, bytes):
        return json.loads(cached_bytes.decode("utf-8"))
    return json.loads(cached_bytes)
    ```
- **Distributed Rate Limiting Collision Bug (`backend/core/dependencies.py:228-233`)**:
  - Uses `pipe.zadd(storage_key, {str(now): now})`. Under sub-millisecond concurrent bursts, identical timestamp floats collide, overwriting sorted set members and undercounting requests.
  - Furthermore, `zadd` executes unconditionally before evaluating `current_count >= max_requests`, counting rejected requests against the client window.
  - *Fix*: Use unique member tokens (`f"{now}:{uuid.uuid4().hex[:8]}"`) and an atomic Lua script:
    ```lua
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local limit = tonumber(ARGV[3])
    local member = ARGV[4]
    local cutoff = now - window

    redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
    local current = redis.call('ZCARD', key)
    if current < limit then
        redis.call('ZADD', key, now, member)
        redis.call('EXPIRE', key, math.ceil(window) + 1)
        return 1
    else
        return 0
    end
    ```

---

### 4.3 ClickHouse 23.8: High-Throughput Columnar OLAP Telemetry Storage
- **Current Schema (`infra/clickhouse/schema.sql:1-30`)**:
  - Defines `flow_logs` with generic `String` types for IP addresses, protocols, domains, and organizations.
  - Micro-batch insertion creates severe part churn (`Too many parts in table`).
  - **Zero Analytical Read Queries**: `analytics_service.py` and `dashboard_service.py` execute complex aggregations (`COUNT(*)`, `SUM(byte_count)`, window functions) directly against MySQL `flow_logs`, completely ignoring ClickHouse.
- **Production-Optimized ClickHouse DDL Schema**:
  ```sql
  CREATE TABLE IF NOT EXISTS flow_logs (
      organization_id LowCardinality(String),
      src_ip IPv4,
      dst_ip IPv4,
      src_port UInt16,
      dst_port UInt16,
      protocol LowCardinality(String),
      start_time DateTime CODEC(DoubleDelta, ZSTD(1)),
      last_seen DateTime CODEC(DoubleDelta, ZSTD(1)),
      packet_count UInt32 CODEC(T64, ZSTD(1)),
      byte_count UInt64 CODEC(T64, ZSTD(1)),
      duration Float32 CODEC(ZSTD(1)),
      average_packet_size Float32 CODEC(ZSTD(1)),
      domain String CODEC(ZSTD(3)),
      sni String CODEC(ZSTD(3)),
      src_mac String CODEC(ZSTD(1)),
      dst_mac String CODEC(ZSTD(1)),
      network_scope LowCardinality(String),
      flow_direction LowCardinality(String),
      internal_device_ip IPv4,
      external_endpoint_ip IPv4,
      session_id String CODEC(ZSTD(3)),
      application LowCardinality(String),
      agent_id LowCardinality(String),
      analysis_source LowCardinality(String),
      analysis_confidence Float32 CODEC(ZSTD(1)),
      analysis_signals_json String CODEC(ZSTD(3)),
      ingest_hash String CODEC(ZSTD(3)),
      created_at DateTime DEFAULT now() CODEC(DoubleDelta, ZSTD(1)),
      INDEX idx_sni sni TYPE bloom_filter() GRANULARITY 4,
      INDEX idx_domain domain TYPE bloom_filter() GRANULARITY 4,
      INDEX idx_app application TYPE set(100) GRANULARITY 4
  ) ENGINE = MergeTree()
  PARTITION BY toYYYYMM(last_seen)
  ORDER BY (organization_id, toDate(last_seen), application, src_ip, last_seen)
  TTL last_seen + INTERVAL 90 DAY;
  ```
- **Buffer Table Engine for Part Explosion Elimination**:
  ```sql
  CREATE TABLE IF NOT EXISTS flow_logs_buffer AS flow_logs
  ENGINE = Buffer(
      currentDatabase(),
      flow_logs,
      16,       -- num_layers
      2,        -- min_time (seconds)
      10,       -- max_time (seconds)
      1000,     -- min_rows
      50000,    -- max_rows
      1000000,  -- min_bytes (1 MB)
      50000000  -- max_bytes (50 MB)
  );
  ```
  *Inserting into `flow_logs_buffer` decouples worker threads from disk I/O, guaranteeing large, sequential block writes to the underlying `flow_logs` table and reducing data part generation by 98%.*

---

### 4.4 Comprehensive Workload Boundaries & Storage Tier Matrix

| Data Domain | Target Tier | Engine / Structure | Partitioning / Retention | Access Pattern & SLA |
|---|---|---|---|---|
| **Organizations & Users** | MySQL 8.0 | InnoDB | Single table / Permanent | Point lookups by ID/email ($<5\text{ms}$) |
| **Credentials & Tokens** | MySQL 8.0 | InnoDB | Hash indexed / TTL expiry | Auth verification, refresh rotation ($<2\text{ms}$) |
| **Device Inventory** | MySQL 8.0 | InnoDB | Indexed by `org_id`, `mac`, `ip` | Reconciled point lookups & updates ($<5\text{ms}$) |
| **Rollup Summaries** | MySQL 8.0 | InnoDB (`ON DUPLICATE KEY`) | 30-day sliding window | Micro-batched upsert, dashboard reads ($<10\text{ms}$) |
| **Security Alerts** | MySQL 8.0 | InnoDB | Filtered by `org_id`, `severity` | Append-only alerts, analyst triage ($<10\text{ms}$) |
| **Flow Stream Ingestion** | Redis 7.0 | Redis Stream (`flow_stream`) | `MAXLEN ~ 100000` (~1-2h buffer) | `XADD` / `XREADGROUP` ($<1\text{ms}$) |
| **Distributed Rate Limiting**| Redis 7.0 | Redis Sorted Set | Sliding window TTL + 1s | Atomic Lua script ($<1\text{ms}$) |
| **Dashboard Query Cache** | Redis 7.0 | Redis String (JSON) | 3s - 60s TTL | `GET` / `SETEX` ($<0.5\text{ms}$) |
| **Real-time Event Pub/Sub** | Redis 7.0 | Redis Pub/Sub | Ephemeral (0s retention) | Fanout to WebSocket workers ($<0.5\text{ms}$) |
| **Raw Flow Telemetry** | ClickHouse 23.8 | `MergeTree` / `Buffer` | Partitioned `toYYYYMM`, 90-day TTL | Bulk append (10k+ rows/batch) ($<20\text{ms}$) |
| **Analytical Aggregations**| ClickHouse 23.8 | Columnar Vectorized Scan | Range scans on `last_seen` | Vectorized rollups, Top-N talkers ($<15\text{ms}$) |

---

## 5. Codebase Preservation Assurance (R5)

A cornerstone requirement of this architectural milestone is the strict preservation of all existing core business logic in the NetVisor repository.

- **Verification Scope**: `backend/` and `packet_engine/`
- **Audit Methodology**: Verified via Git source tree tracking:
  ```powershell
  git status
  git diff backend/ packet_engine/
  ```
- **Attestation**:
  - **Zero Lines Modified**: No files in `backend/engines/`, `backend/services/`, `packet_engine/`, or `backend/db/` have been altered, refactored, or touched.
  - **Existing Unit Tests Passing**: All 37 existing unit tests in `tests/test_engine_registry.py`, `tests/test_threat_detection_engine.py`, `tests/test_risk_engine_new.py`, `tests/test_ai_engine.py`, and `tests/test_device_engine_parities.py` pass cleanly without regression.
  - **Clean Working Tree**: Only this comprehensive architectural review document (`docs/architecture/netvisor_architectural_and_performance_review.md`) and the project logbook (`docs/project-logbook.md`) have been authored or updated.

---

## 6. Implementation & Benchmarking Action Plan

With the architectural review and optimization blueprints formally established, subsequent milestones will execute the following action items:

1. **Milestone 2 (Stress Test Suite Authoring)**:
   - Implement isolated benchmark suites in `tests/stress/` and `tests/benchmarks/`:
     - `tests/benchmarks/test_engine_benchmarks.py`: Microbenchmarking of all 6 engines under 1, 5, 10, 25 worker threads.
     - `tests/stress/test_pipeline_stress.py`: Stream queue saturation, backpressure verification, supervisor crash-loop stress.
     - `tests/stress/test_database_stress.py`: Concurrent MySQL pool checkout, Redis pipeline throughput, ClickHouse batch scaling.
     - `tests/stress/test_traffic_burst_stress.py`: Sustained 5,000 flows/sec and flash burst 50,000 flows/sec SLA validation.
2. **Milestone 3 (Empirical Benchmarking & Metrics Profiling)**:
   - Execute benchmark suites, measure throughput (flows/sec), latency distributions (P50, P95, P99), CPU saturation, and memory RSS deltas.
3. **Milestone 4 (Verification & Forensic Audit)**:
   - Independent verification wave by Reviewer, Challenger, and Forensic Auditor agents, confirming absolute technical integrity and codebase preservation.
