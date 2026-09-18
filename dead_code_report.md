# Dead Code & Unreachable Function Report

This report lists every function and class method that is defined in the repository but has **zero incoming calls from any production code path** executing at runtime.
Calls originating solely from `if __name__ == '__main__':` demo blocks, test suites (`tests/`), benchmarks, or docstrings are excluded from production call chains.

## Executive Summary
- **Total Analyzed Definitions**: 1,262 functions/methods across 190 Python files.
- **Framework Entry Points**: 84 FastAPI route handlers and 5 Mitmproxy/Lifespan hooks (invoked externally).
- **Pydantic Validators & Dunder Methods**: 46 items (called implicitly by Python runtime or model parsing).
- **Identified Dead / Unreachable Functions**: 65 items (31 completely unreferenced anywhere + 34 referenced solely in test files).

## 1. High-Risk Security, Redaction & Validation Audit

Special scrutiny was applied to functions with `sanitize`, `redact`, `validate`, `verify`, or `auth` in their names.
These are the most critical locations where a 'looks handled but isn't actually called' bug can hide.

### `agent/dpi/redaction.py` :: `redact_headers(headers)`
- **Equivalent / Replacement**: None (Intended to redact `Authorization`, `Cookie`, `Set-Cookie`, and `X-Auth-*` headers).
- **Analysis**: CRITICAL UNWIRED PIPELINE: `agent/dpi/event_buffer.py` line 222 calls `redact_headers(raw_event.get('headers') or {})`. However, in `agent/dpi/mitm_addon.py::response()`, the `DpiObservation` data class does NOT include a `headers` field, nor does `to_payload()` emit headers. Consequently, `raw_event.get('headers')` is always empty `{}`. Intercepted HTTP headers are never passed into `redact_headers()` and are therefore completely dropped before reaching the buffer.
- **Verdict**: Unwired / Defective Pipeline: The redaction logic was implemented and unit-tested in `tests/test_dpi_redaction.py`, but the upstream observation model in `agent/dpi/mitm_addon.py` / `packet_engine/parser.py` fails to populate the `headers` field.

### `agent/dpi/mitm_addon.py` :: `redact_url_secrets(url)` vs `agent/dpi/redaction.py` :: `redact_url(url)`
- **Equivalent / Replacement**: `agent/dpi/redaction.py::redact_url` performs comprehensive AST/regex redaction of query params (UUIDs, JWTs, high entropy tokens) and path keywords (`reset-password`, `magic`, `token`).
- **Analysis**: DUPLICATE / SHADOW IMPLEMENTATION: `mitm_addon.py` defines its own local `redact_url_secrets()` using a simple 1-line regex `(key|token|auth|password|secret|apikey)=[^&#]+`. `mitm_addon.py` redacts the URL with this naive regex first. Later, `event_buffer.py` calls `redact_url()` on the already-redacted URL. `mitm_addon.py` never imports `agent.dpi.redaction.redact_url`.
- **Verdict**: Duplicate Implementation: An older naive redaction function was written in `mitm_addon.py` and left in place when `agent/dpi/redaction.py` was introduced. While both execute sequentially, `redact_url_secrets` is redundant.

### `agent/dpi/mitm_addon.py` :: `sanitize_snippet(snippet)` vs `agent/dpi/redaction.py` :: `sanitize_text_snippet(value)`
- **Equivalent / Replacement**: `agent/dpi/mitm_addon.py::sanitize_snippet` regex-redacts bearer tokens, passwords, and API keys. `agent/dpi/redaction.py::sanitize_text_snippet` only strips null bytes and truncates length.
- **Analysis**: FUNCTIONAL DISCREPANCY: The function in `agent/dpi/redaction.py` is named `sanitize_text_snippet`, but does NOT sanitize sensitive credentials — it only enforces a byte limit. `mitm_addon.py` implemented `sanitize_snippet` to perform actual password/bearer token redaction before emitting to stdout.
- **Verdict**: Intentional Divergence / Naming Mismatch: `sanitize_text_snippet` in `redaction.py` is actually a byte-truncator/cleaner, whereas `sanitize_snippet` in `mitm_addon.py` is the actual credential scrubber.

### `agent/dpi/proxy_manager.py` :: `_verify_port_listening(port, host)`
- **Equivalent / Replacement**: `ProxyManager.start()` relies on `self.ready_event.wait(timeout=self.startup_timeout)` triggered when mitmdump prints to stdout.
- **Analysis**: ORPHANED HELPER: `_verify_port_listening` attempts a socket connection to verify mitmdump is listening on the proxy port. However, it is never called anywhere inside `ProxyManager` or `WebInspectionController`.
- **Verdict**: Orphaned / Unwired Implementation: Written as a health verification check during proxy startup, but replaced by stdout readiness signaling.

### `security/agent_auth.py` :: `canonical_path(path, query_params)`
- **Equivalent / Replacement**: `AgentApiClient.request()` in `agent/security/transport.py` passes `prepared.path_url`, while `AgentAuthService.authenticate_request()` in `backend/services/agent_auth_service.py` manually computes `path = request.url.path; if request.url.query: path = f'{path}?{request.url.query}'`.
- **Analysis**: ORPHANED PROTOCOL UTILITY: `canonical_path` was written to normalize paths and query parameter encoding for HMAC-SHA256 signature verification. Neither the agent transport client nor the backend auth service calls it; both use manual string concatenation.
- **Verdict**: Orphaned Protocol Function: Written as part of the initial specification in `security/agent_auth.py`, but superseded by inline path resolution on both client and server.

### `backend/services/agent_auth_service.py` :: `AgentAuthService._extract_agent_id(request, body)`
- **Equivalent / Replacement**: `AgentAuthService.authenticate_request()` directly extracts `request.headers.get(AGENT_ID_HEADER)`.
- **Analysis**: DEAD CODE / UNWIRED FALLBACK: `_extract_agent_id` contains complex fallback logic to search headers, query parameters, and JSON request bodies for an `agent_id`. In production, signed authentication strictly mandates the `X-Agent-Id` header (line 321), making `_extract_agent_id` completely unreachable.
- **Verdict**: Dead Code: Legacy fallback helper from before strict header-based HMAC enforcement was mandated.

## 2. Comprehensive Inventory of Unreachable Functions

The following functions and methods have **zero incoming calls from production code paths**.

| File | Function / Method | Line | What Does Equivalent Job Instead | Intentional vs Unwired / Duplicate |
| :--- | :--- | :--- | :--- | :--- |
| `agent/main.py` | **`NetworkAgent._detect_local_mac`** | 716 | NetworkAgent._detect_interfaces() (called in __init__) | Unwired / Duplicate: Redundant fallback MAC detector replaced by multi-interface enumeration. |
| `agent/device_detector.py` | **`device_compatibility_wrapper`** | 740 | DeviceDetector pipeline / backend device engine | Intentional Legacy Shim: Kept exclusively for backward compatibility in test suites. |
| `agent/traffic_metadata.py` | **`extract_domain_hint`** | 355 | packet_engine/metadata.py::extract_flow_hints() | Duplicate / Superseded: Agent-local copy of domain hint extractor superseded by packet_engine. |
| `agent/dpi/mitm_addon.py` | **`_browser_from_name`** | 49 | infer_browser_identity(headers) | Orphaned Helper: Replaced by header-based browser detection; never called. |
| `agent/dpi/proxy_manager.py` | **`_verify_port_listening`** | 23 | ProxyManager.ready_event signaling | Orphaned Helper: Socket probing check forgotten during proxy startup implementation. |
| `agent/dpi/aia_chaser.py` | **`AiaChaser.get_cached_intermediate_pem`** | 209 | AiaChaser.get_cached_domains() & cert injection | Public Inspection API: Accessor method used in test suite; not required in production flow. |
| `agent/dpi/cert_manager.py` | **`CertificateManager._is_currentuser_root_match`** | 207 | CertificateManager._verify_ca_installed() | Test-Only Verification Helper: Internal helper exercised by tests but bypassed in runtime setup. |
| `backend/core/config.py` | **`set_settings`** | 336 | Direct settings module instantiation | Test-Only Utility: Mutation helper used in tests to override configuration settings. |
| `backend/core/dependencies.py` | **`rate_limit`** | 281 | request_rate_limit() dependency factory | Superseded Prototype: Older rate-limiting dependency replaced by request_rate_limit. |
| `backend/db/session.py` | **`reset_schema_verification_cache`** | 753 | Automatic schema check on startup | Test-Only Utility: Cache reset utility designed for test isolation. |
| `backend/middleware/chaos_middleware.py` | **`chaos_disk_usage`** | 24 | Chaos injection middleware harness | Intentional Testing Harness: Chaos engineering helper activated only during fault-injection tests. |
| `backend/middleware/chaos_middleware.py` | **`chaos_getaddrinfo`** | 32 | Chaos injection middleware harness | Intentional Testing Harness: Chaos engineering helper for DNS failure injection. |
| `backend/services/agent_auth_service.py` | **`AgentAuthService._extract_agent_id`** | 277 | Direct X-Agent-Id header lookup | Dead Code: Legacy parameter extraction from query/body; signed auth strictly requires headers. |
| `backend/services/alert_service.py` | **`AlertService.get_risk_events`** | 97 | AlertService.list_alerts() | Unwired / Future API: Query method for risk events not wired into any API router. |
| `backend/services/analytics_service.py` | **`AnalyticsService._window_cutoff`** | 41 | Inline SQL interval calculations | Orphaned Helper: Time calculation helper bypassed in favor of SQL date math. |
| `backend/services/application_service.py` | **`ApplicationService._fallback_application_label`** | 239 | ApplicationService.classify() inline heuristics | Orphaned Helper: Fallback label generator replaced by classifier lookup. |
| `backend/services/application_service.py` | **`ApplicationService._is_noise_flow`** | 566 | intel/domain_intelligence.py::is_noise() | Duplicate: Service-level noise check superseded by shared intel module. |
| `backend/services/application_service.py` | **`ApplicationService._session_domain_key`** | 607 | Inline session grouping tuples | Orphaned Helper: Grouping key generator bypassed by inline tuple keys. |
| `backend/services/auth_service.py` | **`AuthService.revoke_token_family_by_user`** | 261 | AuthService.revoke_refresh_token() | Unwired Admin API: Token family mass-revocation method not wired into user router. |
| `backend/services/correlation_worker.py` | **`CorrelationWorker._is_infrastructure`** | 124 | External endpoint / ASN categorization | Orphaned Helper: Unused classification helper in correlation worker. |
| `backend/services/correlation_worker.py` | **`CorrelationWorker.cleanup_state`** | 188 | Automatic worker shutdown | Test-Only Lifecycle Method: Explicit state cleanup method only called in worker tests. |
| `backend/services/device_enrichment_service.py` | **`DeviceEnrichmentService.enrich_all_devices`** | 244 | Event-driven per-flow enrichment | Unwired Batch API: Bulk device enrichment batch method with no scheduled trigger. |
| `backend/services/device_service.py` | **`DeviceService.mark_stale_devices_offline`** | 1136 | Active heartbeat timeout checks | Unwired Maintenance Job: Stale device cleanup method not scheduled in worker supervisor. |
| `backend/services/flow_service.py` | **`FlowService._load_device_baselines`** | 243 | Inline baseline queries | Test-Only Helper: Baseline loader called exclusively in test fixtures. |
| `backend/services/flow_service.py` | **`FlowService._flow_log_exists_by_hash`** | 396 | Batch deduplication query in _process_batch | Duplicate / Superseded: Single-flow hash existence check replaced by bulk hash lookup. |
| `backend/services/flow_service.py` | **`FlowService._ensure_runtime_tables`** | 427 | db/session.py::require_runtime_schema() | Dead Code: Legacy DDL table creation superseded by centralized schema manager. |
| `backend/services/flow_service.py` | **`FlowService.build_alert_breakdown`** | 440 | engines/registry.py execution | Test-Only Helper: Breakdown generator tested in test_flow_service but not in prod pipeline. |
| `backend/services/flow_service.py` | **`FlowService._record_device_activity`** | 511 | device_service.record_flow_observation() | Orphaned Helper: Device activity recorder bypassed in favor of device_service. |
| `backend/services/flow_service.py` | **`FlowService._mark_batch_processed_sync`** | 840 | Async batch status updates in executor | Dead Code: Synchronous batch updater orphaned after async migration. |
| `backend/services/live_telemetry_store.py` | **`LiveTelemetryStore.record_agent_status`** | 263 | Heartbeat ingestion in agents.py | Test-Only Diagnostic API: Agent status recorder used in adversarial tests. |
| `backend/services/live_telemetry_store.py` | **`LiveTelemetryStore.record_gateway_status`** | 285 | Gateway heartbeat ingestion in gateway.py | Test-Only Diagnostic API: Gateway status recorder used in adversarial tests. |
| `backend/services/managed_device_service.py` | **`ManagedDeviceService._primary_key_columns`** | 40 | Direct schema column references | Orphaned Helper: Introspection helper not called in managed device queries. |
| `backend/services/ml_service.py` | **`MLService.predict_anomaly`** | 5 | Statistical engines (threat, risk) | Unwired Stub: Placeholder for ML model inference not connected to ingestion. |
| `backend/services/vpn_detector.py` | **`VPNDetector.tor_exit_count`** | 518 | Tor IP lookup cache | Unwired Accessor: Telemetry accessor method not wired into dashboard API. |
| `backend/services/vpn_detector.py` | **`VPNDetector.get_cached_asn`** | 521 | ASN lookup cache | Unwired Accessor: Cache getter method not wired into API endpoints. |
| `backend/services/worker_supervisor.py` | **`WorkerSupervisor.get_worker_state`** | 209 | WorkerSupervisor.health_check() | Test-Only Diagnostic API: State inspector only called in worker supervisor unit tests. |
| `backend/utils/partition_manager.py` | **`PartitionManager.is_table_partitioned`** | 14 | Static DB migration DDL | Unwired DBA Utility: Partition detection utility not scheduled at runtime. |
| `backend/utils/partition_manager.py` | **`PartitionManager.get_existing_partitions`** | 27 | Static DB migration DDL | Unwired DBA Utility: Partition listing utility not scheduled at runtime. |
| `backend/utils/partition_manager.py` | **`PartitionManager.generate_monthly_partition_ddl`** | 40 | Static DB migration DDL | Test-Only Utility: DDL generator only exercised in test_schema_modernization. |
| `backend/utils/partition_manager.py` | **`PartitionManager.drop_expired_partitions`** | 68 | run_backup_retention.py script | Unwired Maintenance API: Partition drop logic implemented in standalone script instead. |
| `packet_engine/advanced_decoders.py` | **`JA3Fingerprinter.calculate_ja3`** | 25 | extract_ja4_fingerprint() | Superseded Prototype: JA3 fingerprinter superseded by modern JA4 fingerprinting. |
| `packet_engine/advanced_decoders.py` | **`SMB2Dissector.parse_smb2_header`** | 76 | dpkt / scapy SMB dissectors | Test-Only Prototype: Experimental dissector exercised in sprint 6 tests but not in pipeline. |
| `packet_engine/advanced_decoders.py` | **`KerberosDissector.parse_kerberos_message`** | 124 | dpkt / scapy Kerberos dissectors | Unwired Prototype: Experimental Kerberos dissector with 0 calls in prod or tests. |
| `packet_engine/af_packet_backend.py` | **`AFPacketMmapBackend.start_capture`** | 56 | build_capture_backend() (Scapy / Raw socket) | Unwired Linux Kernel Backend: AF_PACKET MMAP engine built for Sprint 6 but never wired into factory. |
| `packet_engine/bpf_filter.py` | **`BPFFilterEngine.should_pass_packet`** | 45 | Scapy BPF filter strings in kernel | Test-Only Prototype: Userspace BPF filter engine tested in sprint 6 but kernel BPF used at runtime. |
| `packet_engine/classifier_fast.py` | **`classify_packet_tier_fast`** | 4 | packet_engine/classifier.py::PacketClassifier | Benchmark / Prototype: High-speed tier classifier used only in benchmark scripts. |
| `packet_engine/cpu_affinity.py` | **`CPUAffinityManager.pin_capture_thread`** | 63 | OS default thread scheduling | Unwired Optimization: Thread affinity pinning built for kernel acceleration but never invoked. |
| `packet_engine/cpu_affinity.py` | **`CPUAffinityManager.pin_worker_thread`** | 67 | OS default thread scheduling | Unwired Optimization: Worker thread CPU pinning built for sprint 6 but uncalled. |
| `packet_engine/dpkt_parser.py` | **`DpktFastParser.parse_packet_memoryview`** | 36 | packet_engine/parser.py | Benchmark / Prototype: Zero-copy DPKT parser tested in benchmark_parser_performance. |
| `packet_engine/exporter.py` | **`FlowExporterPipeline.export_batch`** | 55 | agent/main.py upload worker queue | Unwired Pipeline: Standalone flow export pipeline bypassed by direct queue ingestion. |
| `packet_engine/flow_aggregator.py` | **`FlowManager.get_active_flows`** | 187 | FlowManager.status_snapshot() | Unwired Diagnostic Method: Flow inspection accessor not called in production. |
| `packet_engine/flow_aggregator.py` | **`FlowManager.update_from_packet`** | 229 | FlowManager.update_from_observation() | Superseded Method: Older direct-packet ingestion replaced by observation-based ingestion. |
| `packet_engine/metadata.py` | **`extract_domain_hint`** | 442 | extract_flow_hints() | Superseded Helper: Standalone domain extractor superseded by comprehensive flow hint extractor. |
| `packet_engine/metrics.py` | **`NetVisorMetricsExporter.update_metrics`** | 21 | Prometheus metrics in backend | Test-Only Exporter: Packet engine standalone Prometheus exporter tested only in unit tests. |
| `packet_engine/metrics.py` | **`NetVisorMetricsExporter.generate_prometheus_exposition`** | 37 | Prometheus metrics in backend | Test-Only Exporter: Exposition generator called only in test_packet_engine_hardening. |
| `packet_engine/object_pool.py` | **`PacketObservationPool.get_pool`** | 61 | Direct object allocation | Test-Only Optimization: Pre-allocated object pools built for sprint 6, exercised only in tests. |
| `packet_engine/object_pool.py` | **`FlowObservationPool.get_pool`** | 72 | Direct object allocation | Test-Only Optimization: Flow observation object pool tested in sprint 6, not wired in prod. |
| `packet_engine/object_pool.py` | **`HttpTransactionPool.get_pool`** | 83 | Direct object allocation | Test-Only Optimization: HTTP transaction object pool tested in sprint 6, not wired in prod. |
| `packet_engine/object_pool.py` | **`TLSHandshakeMetadataPool.get_pool`** | 94 | Direct object allocation | Test-Only Optimization: TLS metadata pool tested in sprint 6, not wired in prod. |
| `packet_engine/parser.py` | **`PacketObservation.observed_at_iso`** | 215 | Direct observation.timestamp formatting | Unused Property: Formatted timestamp accessor never called in production. |
| `packet_engine/parser.py` | **`PacketObservation.to_flow_observation`** | 218 | FlowManager.update_from_observation | Test-Only Converter: Direct conversion method called in sprint 1 tests but not by FlowManager. |
| `packet_engine/quic_parser.py` | **`extract_quic_metadata`** | 57 | agent/dpi/quic_guard.py (firewall blocking) | Unwired Dissector: QUIC payload parser tested in sprint 4, but agent DPI blocks QUIC instead of parsing it. |
| `packet_engine/ring_buffer.py` | **`DualRingBuffer.get_health_metrics`** | 114 | Internal queue telemetry | Test-Only Diagnostic: Ring buffer health method called only in throughput benchmarks. |
| `packet_engine/ring_buffer.py` | **`wfq_worker_drain_loop`** | 140 | Direct worker queue drain loops | Unwired Helper: Standalone WFQ drain loop function exported in __init__ but never invoked. |
| `packet_engine/stream_registry.py` | **`StreamConsumerRegistry.register_consumer`** | 32 | Static consumer dispatch | Unwired Extension Hook: Consumer registration method with no dynamic consumers registered. |
| `packet_engine/stream_registry.py` | **`StreamConsumerRegistry.process_stream`** | 37 | Direct consumer dispatch | Test-Only Method: Stream processing method tested in sprint 4, not hooked into live capture. |
| `packet_engine/tcp_stream.py` | **`seq_gte`** | 37 | Inline sequence number comparisons | Test-Only Helper: Sequence number comparator called only in test_packet_engine_validation. |
| `packet_engine/tcp_stream.py` | **`TCPStreamTrackerManager.process_packet_segment`** | 343 | Direct packet parsing | Test-Only Method: Packet segment feeder called only in sprint 3 unit tests. |
| `packet_engine/tls_consumer.py` | **`parse_tls_server_hello_record`** | 41 | parse_tls_client_hello_record() | Unwired Dissector: Server Hello parser called in validate_live_capture.py and tests, never in agent flow. |
| `intel/domain_intelligence.py` | **`classify_domain`** | 145 | intel/app_classifier.py::get_service_info() | Duplicate / Superseded: Category string classifier superseded by get_service_info tuple. |
| `security/agent_auth.py` | **`canonical_path`** | 19 | prepared.path_url (client) & request.url.path (server) | Orphaned Protocol Utility: Specification helper bypassed by native library path handling. |

## 3. Root Cause Classification & Recommendations

Analysis of why these 65 functions are unreachable reveals four distinct patterns:
1. **Unwired Sprint Features (Kernel Acceleration & Protocol Decoders)**: Decoders built during Sprint 4 and Sprint 6 (`JA3Fingerprinter`, `KerberosDissector`, `SMB2Dissector`, `AFPacketMmapBackend`, `extract_quic_metadata`, `parse_tls_server_hello_record`, `CPUAffinityManager`, `BPFFilterEngine`) were thoroughly unit-tested but never wired into the production `build_capture_backend()` factory or `FlowManager` pipeline.
2. **Duplicate Evolution / Refactoring Residuals**: Newer architectures replaced older functions without removing them. Examples: `agent/dpi/mitm_addon.py` using a local regex while `agent/dpi/redaction.py` was built; `FlowManager.update_from_packet` superseded by `update_from_observation`; `classify_domain` superseded by `get_service_info`.
3. **Missing Data Pipeline Wiring (`redact_headers`)**: `redact_headers()` in `agent/dpi/redaction.py` is invoked at runtime by `EventBuffer`, but the upstream producer `agent/dpi/mitm_addon.py` never collects or forwards HTTP headers in `DpiObservation`. The redaction function is running on empty dictionaries.
4. **Unwired Maintenance & Admin Capabilities**: Several enterprise maintenance functions (`DeviceService.mark_stale_devices_offline`, `PartitionManager.drop_expired_partitions`, `AuthService.revoke_token_family_by_user`, `DeviceEnrichmentService.enrich_all_devices`) exist as fully implemented methods on services but lack scheduled execution triggers in `worker_supervisor.py` or API routes in `backend/api/`.