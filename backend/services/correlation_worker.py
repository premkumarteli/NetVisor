import asyncio
import logging
import json
import time
import ipaddress
import random
from typing import Optional, Literal
from datetime import datetime, timezone
from collections import defaultdict, deque, OrderedDict
from backend.db.redis_client import get_redis_connection
from backend.middleware.prometheus_middleware import INCIDENTS_CREATED, ALERTS_GENERATED
from backend.realtime import emit_event
from backend.core.config import settings
from backend.utils.network import normalize_ip_v2, classify_ip_scope_v2
from backend.services.evidence_cache import evidence_cache, EvidenceSnapshot

logger = logging.getLogger("netvisor.services.correlation")

class TenantState:
    """
    Holds the correlation graph, scan history, and suppression state isolated per tenant.
    All operations on a TenantState are designed to run under the Single-Owner Actor Model.
    """
    def __init__(self) -> None:
        # (src_ip, dst_ip) -> deque[float] (up to 5 timestamps)
        self.connection_history: dict[tuple[str, str], deque[float]] = {}
        
        # dst_ip -> set[src_ip] (reverse index for fast temporal causality lookups)
        self.incoming_index: dict[str, set[src_ip]] = defaultdict(set)
        
        # (prior_src, pivot, target, detector_type) -> details dict
        # Using OrderedDict to maintain insertion/update order for fast O(1) eviction
        self.suppression_cache: OrderedDict[tuple[str, str, str, str], dict] = OrderedDict()
        
        # src_ip -> deque[(timestamp, dst_ip)] (fast scan tracking, capped at 100 targets)
        self.scan_history: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque(maxlen=100))
        
        # Tracks the insertion order of edges for O(1) eviction
        # Invariant: edge_order may contain stale tombstones; connection_history is authoritative; eviction skips stale entries.
        self.edge_order: deque[tuple[str, str]] = deque()

class CorrelationWorker:
    """
    Single-Owner Actor Model:
    This class is designed to run as a single-owner event processor. Only the main
    execution task loop (or single worker thread) is allowed to mutate the tenant
    correlation states. External synchronization is avoided on the hot paths to maximize
    throughput and reduce event loop overhead.
    """
    def __init__(self) -> None:
        self._worker_id = f"correlation-worker-{time.time_ns()}"
        
        # org_id -> TenantState
        self.tenant_states: dict[str, TenantState] = defaultdict(TenantState)
        
        self.last_cleanup = time.time()

        # Cache variables for parsed configuration settings
        self._cached_cidrs_raw = ""
        self._cached_cidrs = {}
        self._cached_assets_raw = ""
        self._cached_assets_ips = {}
        self._cached_assets_nets = {}

    def _get_org_cidrs(self, org_id: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        raw = settings.NETVISOR_ORGANIZATION_CIDRS
        if self._cached_cidrs_raw != raw:
            try:
                parsed_json = json.loads(raw)
                temp_map = {}
                for oid, cidrs in parsed_json.items():
                    nets = []
                    for c in cidrs:
                        try:
                            nets.append(ipaddress.ip_network(c.strip()))
                        except Exception as e:
                            logger.error("Invalid CIDR: %s, error: %s", c, e)
                    temp_map[oid] = nets
                self._cached_cidrs = temp_map
                self._cached_cidrs_raw = raw
            except Exception as e:
                logger.error("Failed to parse NETVISOR_ORGANIZATION_CIDRS: %s", e)
                
        return self._cached_cidrs.get(org_id, [])
        
    def _get_infra_assets(self, org_id: str) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
        raw = settings.NETVISOR_INFRASTRUCTURE_ASSETS
        if self._cached_assets_raw != raw:
            try:
                parsed_json = json.loads(raw)
                temp_ips = defaultdict(set)
                temp_nets = defaultdict(list)
                for asset in parsed_json:
                    oid = asset.get("org_id")
                    ip = asset.get("cidr_or_ip")
                    if oid and ip:
                        try:
                            ip_str = ip.strip()
                            if "/" in ip_str:
                                temp_nets[oid].append(ipaddress.ip_network(ip_str))
                            else:
                                normalized_ip = normalize_ip_v2(ip_str)
                                if normalized_ip:
                                    temp_ips[oid].add(normalized_ip)
                        except Exception:
                            pass
                self._cached_assets_ips = temp_ips
                self._cached_assets_nets = temp_nets
                self._cached_assets_raw = raw
            except Exception as e:
                logger.error("Failed to parse NETVISOR_INFRASTRUCTURE_ASSETS: %s", e)
                
        return (
            self._cached_assets_ips.get(org_id, set()),
            self._cached_assets_nets.get(org_id, [])
        )

    def _is_infrastructure(self, ip_str: str, org_id: str) -> bool:
        infra_ips, infra_nets = self._get_infra_assets(org_id)
        if ip_str in infra_ips:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in infra_nets:
                if ip_obj in net:
                    return True
        except Exception:
            pass
        return False

    def _cleanup_old_data(self):
        """Clean up state history older than TTL windows across all tenants."""
        now = time.time()
        if now - self.last_cleanup < 30:
            return
        self.last_cleanup = now
        
        for org_id, state in list(self.tenant_states.items()):
            # 1. Prune connection_history
            expired_edges = []
            for edge_key, timestamps in list(state.connection_history.items()):
                while timestamps and now - timestamps[0] > 60:
                    timestamps.popleft()
                if not timestamps:
                    expired_edges.append(edge_key)
                    
            for edge_key in expired_edges:
                del state.connection_history[edge_key]
                src_ip, dst_ip = edge_key
                state.incoming_index[dst_ip].discard(src_ip)
                if not state.incoming_index[dst_ip]:
                    del state.incoming_index[dst_ip]
                # Clean up edge_order (lazy clean or direct filter)
                while state.edge_order and state.edge_order[0] == edge_key:
                    state.edge_order.popleft()

            # Compaction check for edge_order to avoid growing tombstone queue with expired entries
            if len(state.edge_order) > 2 * len(state.connection_history) + 1000:
                state.edge_order = deque([edge for edge in state.edge_order if edge in state.connection_history])

            # 2. Prune scan_history deques
            empty_scan_sources = []
            for src_ip, history in list(state.scan_history.items()):
                while history and now - history[0][0] > 10.0:
                    history.popleft()
                if not history:
                    empty_scan_sources.append(src_ip)
            for src_ip in empty_scan_sources:
                del state.scan_history[src_ip]

            # 3. Prune suppression_cache (TTL 300s since last_seen)
            expired_supps = []
            for supp_key, entry in list(state.suppression_cache.items()):
                if now - entry["last_seen"] > 300.0:
                    expired_supps.append(supp_key)
            for supp_key in expired_supps:
                del state.suppression_cache[supp_key]

        # 4. Clean up shared evidence cache
        evidence_cache.cleanup_expired(now)

    def cleanup_state(self):
        """Clear all correlation worker owned tenant states. Keeps shared evidence cache untouched."""
        self.tenant_states.clear()
        logger.info("Correlation worker local tenant states cleared successfully.")

    def _should_promote(self, evidence_a: Optional[EvidenceSnapshot], evidence_b: Optional[EvidenceSnapshot], evidence_c: Optional[EvidenceSnapshot]) -> bool:
        """
        Determines if a LateralMovementCandidate should be promoted to a Finding.
        - Critical evidence on any node -> Promote
        - High evidence with lateral-relevant signal -> Promote
        - Medium promotion:
          1. Medium-or-higher evidence on pivot B AND B has a lateral-relevant signal
          2. OR: Relevant evidence exists on at least two distinct nodes among A, B, C
          3. OR: Multiple independent detector families support the chain (3+ unique signals)
        """
        LATERAL_RELEVANT_SIGNALS = {"MALWARE", "BRUTE_FORCE", "REMOTE_SERVICE", "PORT_SCAN", "AUTH_ANOMALY"}
        
        snaps = [s for s in [evidence_a, evidence_b, evidence_c] if s is not None]
        if not snaps:
            return False
            
        # Rule 1: Any CRITICAL active severity -> Promote
        if any(s.max_severity == "critical" for s in snaps):
            return True
            
        # Rule 2: HIGH severity + lateral-relevant signal -> Promote
        for s in snaps:
            if s.max_severity == "high" and any(sig in LATERAL_RELEVANT_SIGNALS for sig in s.signals):
                return True
                
        # Rule 3: MEDIUM severity checks
        has_medium = any(s.max_severity == "medium" for s in snaps)
        if has_medium:
            # 1. Medium-or-higher evidence on pivot B and B has a lateral-relevant signal
            if (
                evidence_b is not None 
                and evidence_b.max_severity in ("medium", "high")
                and any(sig in LATERAL_RELEVANT_SIGNALS for sig in evidence_b.signals)
            ):
                return True
                
            # 2. Relevant evidence exists on at least two distinct nodes among A, B, C
            nodes_with_relevant_signals = 0
            for snap in [evidence_a, evidence_b, evidence_c]:
                if snap is not None and any(sig in LATERAL_RELEVANT_SIGNALS for sig in snap.signals):
                    nodes_with_relevant_signals += 1
            if nodes_with_relevant_signals >= 2:
                return True
                
            # 3. Multiple independent detector families support the chain (3+ unique signals)
            all_signals = set()
            for s in snaps:
                all_signals.update(s.signals)
            if len(all_signals) >= 3:
                return True
                
        return False

    def _determine_severity_and_confidence(
        self,
        evidence_a: Optional[EvidenceSnapshot],
        evidence_b: Optional[EvidenceSnapshot],
        evidence_c: Optional[EvidenceSnapshot],
    ) -> tuple[str, int, str]:
        """
        Derives incident severity, confidence score, and confidence level based on supporting evidence strength.
        """
        snaps = [s for s in [evidence_a, evidence_b, evidence_c] if s is not None]
        if not snaps:
            return "MEDIUM", 60, "LOW"
            
        # Check for critical malware or auth anomaly evidence
        has_critical_malware_auth = any(
            s.max_severity == "critical" and any(sig in {"MALWARE", "AUTH_ANOMALY"} for sig in s.signals)
            for s in snaps
        )
        if has_critical_malware_auth:
            return "CRITICAL", 95, "HIGH"
            
        # Critical evidence of any type
        if any(s.max_severity == "critical" for s in snaps):
            return "CRITICAL", 90, "HIGH"
            
        # High relevant evidence
        if any(s.max_severity == "high" for s in snaps):
            return "HIGH", 80, "HIGH"
            
        # Multi-node relevant evidence (signals on at least two distinct nodes)
        nodes_with_signals = sum(1 for s in snaps if s)
        if nodes_with_signals >= 2:
            return "HIGH", 75, "MEDIUM"
            
        # Pivot medium evidence
        if evidence_b is not None and evidence_b.max_severity == "medium":
            return "MEDIUM", 65, "MEDIUM"
            
        return "MEDIUM", 60, "LOW"

    def analyze_flows(self, org_id: str, flows: list) -> list[dict]:
        """
        Analyzes a batch of flows for correlation patterns.
        Enforces organization boundary, cycle rejection, temporal ordering, and evidence gating.
        """
        incidents = []
        now = time.time()
        state = self.tenant_states[org_id]

        # Retrieve organization parameters once per batch to avoid O(F) overhead
        org_cidrs = self._get_org_cidrs(org_id)
        infra_ips, infra_nets = self._get_infra_assets(org_id)

        for flow in flows:
            src_raw = flow.get("src_ip")
            dst_raw = flow.get("dst_ip")
            
            src_ip = normalize_ip_v2(src_raw)
            dst_ip = normalize_ip_v2(dst_raw)
            
            if not src_ip or not dst_ip:
                continue

            if src_ip == dst_ip:
                continue

            # Classify IP scopes using deployment context
            src_scope = classify_ip_scope_v2(src_ip, org_cidrs, infra_ips, infra_nets)
            dst_scope = classify_ip_scope_v2(dst_ip, org_cidrs, infra_ips, infra_nets)

            # Define invalid correlation scopes that should not enter the connection graph
            INVALID_SCOPES = {"MULTICAST", "BROADCAST", "LOOPBACK", "UNSPECIFIED", "LINK_LOCAL", "EXTERNAL"}
            if src_scope in INVALID_SCOPES or dst_scope in INVALID_SCOPES:
                continue

            edge_key = (src_ip, dst_ip)

            # Edge state bounded constraint validation
            if edge_key not in state.connection_history:
                # O(1) edge counting and FIFO eviction using edge_order deque
                if len(state.connection_history) >= settings.NETVISOR_MAX_EDGES_PER_ORG:
                    while state.edge_order:
                        oldest_edge = state.edge_order.popleft()
                        if oldest_edge in state.connection_history:
                            del state.connection_history[oldest_edge]
                            o_src, o_dst = oldest_edge
                            state.incoming_index[o_dst].discard(o_src)
                            if not state.incoming_index[o_dst]:
                                del state.incoming_index[o_dst]
                            break

                preds = state.incoming_index[dst_ip]
                if len(preds) < settings.NETVISOR_MAX_PREDECESSORS_PER_NODE:
                    state.connection_history[edge_key] = deque(maxlen=5)
                    state.connection_history[edge_key].append(now)
                    state.incoming_index[dst_ip].add(src_ip)
                    state.edge_order.append(edge_key)
            else:
                state.connection_history[edge_key].append(now)

            # 1. Check for Horizontal Scan: 5+ distinct targets within 10 seconds
            # Optimized O(T) lookup using source-indexed scan_history
            source_scan = state.scan_history[src_ip]
            source_scan.append((now, dst_ip))
            
            # Prune older than 10 seconds
            while source_scan and now - source_scan[0][0] > 10.0:
                source_scan.popleft()
                
            unique_targets = {target for _, target in source_scan}
            if len(unique_targets) >= 5:
                incident = {
                    "type": "horizontal_scan",
                    "severity": "HIGH",
                    "confidence_score": 80,
                    "confidence_level": "HIGH",
                    "message": f"Potential horizontal port/IP scan detected from {src_ip} targeting {len(unique_targets)} endpoints.",
                    "src_ip": src_ip,
                    "targets": list(unique_targets),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                incidents.append(incident)
                # Clear scan history for this source to avoid duplicate scan triggers in next iterations
                source_scan.clear()

            # 2. Check for Lateral Movement: A -> B and B -> C
            # Requirement: Candidates require Internal/Infrastructure for A, B, C
            ALLOWED_LATERAL_SCOPES = {"INTERNAL", "INFRASTRUCTURE"}
            if src_scope in ALLOWED_LATERAL_SCOPES and dst_scope in ALLOWED_LATERAL_SCOPES:
                predecessors = state.incoming_index.get(src_ip, set())
                for prior_src in predecessors:
                    # Enforce cycle rejection: prior_src (A), src_ip (B), and dst_ip (C) must be distinct
                    if prior_src == src_ip or prior_src == dst_ip or src_ip == dst_ip:
                        continue

                    # Validate temporal causality: t1 < t2 and t2 - t1 <= window
                    prior_edge_key = (prior_src, src_ip)
                    prior_timestamps = state.connection_history.get(prior_edge_key)
                    if not prior_timestamps:
                        continue

                    t2 = now
                    valid_t1_found = False
                    for t1 in prior_timestamps:
                        if t1 < t2 and (t2 - t1) <= settings.NETVISOR_CORRELATION_WINDOW_SECONDS:
                            valid_t1_found = True
                            break

                    if valid_t1_found:
                        # Candidate detected. Now evaluate severity-aware supporting security evidence
                        evidence_a = evidence_cache.get_active(org_id, prior_src, now)
                        evidence_b = evidence_cache.get_active(org_id, src_ip, now)
                        evidence_c = evidence_cache.get_active(org_id, dst_ip, now)

                        if self._should_promote(evidence_a, evidence_b, evidence_c):
                            supp_key = (prior_src, src_ip, dst_ip, "lateral_movement")

                            # Suppression Cache Bounds Enforcement (O(1) popitem)
                            if supp_key not in state.suppression_cache:
                                if len(state.suppression_cache) >= settings.NETVISOR_MAX_SUPPRESSION_ENTRIES_PER_ORG:
                                    state.suppression_cache.popitem(last=False)

                                state.suppression_cache[supp_key] = {
                                    "occurrence_count": 1,
                                    "first_seen": now,
                                    "last_seen": now,
                                    "last_emitted": now
                                }
                                should_emit = True
                            else:
                                state.suppression_cache[supp_key]["occurrence_count"] += 1
                                state.suppression_cache[supp_key]["last_seen"] = now
                                state.suppression_cache.move_to_end(supp_key)
                                
                                # Suppress warning logs if emitted within the last 5 minutes (300 seconds)
                                last_emitted = state.suppression_cache[supp_key]["last_emitted"]
                                if (now - last_emitted) >= 300.0:
                                    state.suppression_cache[supp_key]["last_emitted"] = now
                                    should_emit = True
                                else:
                                    should_emit = False

                            if should_emit:
                                signals = set()
                                for s in [evidence_a, evidence_b, evidence_c]:
                                    if s:
                                        signals.update(s.signals)

                                severity_str, confidence_score, confidence_level = self._determine_severity_and_confidence(
                                    evidence_a, evidence_b, evidence_c
                                )

                                incident = {
                                    "type": "lateral_movement",
                                    "severity": severity_str,
                                    "confidence_score": confidence_score,
                                    "confidence_level": confidence_level,
                                    "message": f"Lateral movement finding: {prior_src} -> {src_ip} -> {dst_ip} supported by signals: {list(signals)}.",
                                    "src_ip": src_ip,
                                    "chain": [prior_src, src_ip, dst_ip],
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "occurrence_count": state.suppression_cache[supp_key]["occurrence_count"],
                                }
                                incidents.append(incident)
                        else:
                            logger.debug(
                                "Lateral movement candidate detected: %s -> %s -> %s (no supporting evidence)",
                                prior_src, src_ip, dst_ip
                            )

        self._cleanup_old_data()
        return incidents

    async def start(self):
        """Starts the correlation consumer loop."""
        stream_name = "netvisor:flow_stream"
        group_name = "correlation_workers"
        
        logger.info("Starting Correlation Worker...")
        
        use_redis = False
        while True:
            if not use_redis:
                try:
                    r = get_redis_connection()
                    await asyncio.to_thread(r.ping)
                    use_redis = True
                    try:
                        await asyncio.to_thread(r.xgroup_create, stream_name, group_name, id="0", mkstream=True)
                    except Exception as e:
                        if "BUSYGROUP" not in str(e):
                            raise
                    logger.info("Connected to Redis Stream '%s' for correlation analysis.", stream_name)
                except Exception as e:
                    logger.warning("Redis not available for correlation worker, retrying: %s", e)
                    await asyncio.sleep(5.0)
                    continue

            try:
                # 1. Periodic Pending Message Reclamation & DLQ routing
                if random.random() < 0.1:
                    try:
                        pending_info = await asyncio.to_thread(
                            r.xpending_range, stream_name, group_name, min="-", max="+", count=10
                        )
                        for p in pending_info:
                            if isinstance(p, dict):
                                msg_id = p.get("message_id") or p.get("name") or p.get("id")
                                idle_ms = p.get("time_since_delivered") or p.get("idle") or p.get("elapsed_milliseconds") or 0
                                delivery_count = p.get("times_delivered") or p.get("delivered") or 0
                            elif isinstance(p, (list, tuple)) and len(p) >= 4:
                                msg_id = str(p[0]) if p[0] else None
                                idle_ms = p[2] if isinstance(p[2], (int, float)) else 0
                                delivery_count = p[3] if isinstance(p[3], (int, float)) else 0
                            else:
                                continue
                            
                            try:
                                idle_ms = int(idle_ms)
                                delivery_count = int(delivery_count)
                            except (ValueError, TypeError):
                                continue
                            
                            if msg_id and idle_ms > 15000:
                                if delivery_count > 5:
                                    logger.warning(
                                        "[CORRELATION] Message %s exceeded delivery limit (%s times). Routing to DLQ.",
                                        msg_id, delivery_count
                                    )
                                    msgs = await asyncio.to_thread(r.xrange, stream_name, min=msg_id, max=msg_id)
                                    if msgs:
                                        await asyncio.to_thread(
                                            r.xadd, f"{stream_name}:deadletter", msgs[0][1]
                                        )
                                    # ACK the failed message to remove from PEL, but do NOT delete it from stream
                                    await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
                                else:
                                    # Reclaim message for this worker
                                    await asyncio.to_thread(
                                        r.xclaim, stream_name, group_name, self._worker_id,
                                        min_idle_time=15000, message_ids=[msg_id]
                                    )
                                    logger.info("[CORRELATION] Reclaimed pending message %s", msg_id)
                    except Exception as reclaim_err:
                        logger.warning("Failed to reclaim pending messages: %s", reclaim_err)

                # 2. Read messages (first read pending for this worker, then new)
                messages = await asyncio.to_thread(
                    r.xreadgroup,
                    groupname=group_name,
                    consumername=self._worker_id,
                    streams={stream_name: "0"},
                    count=5,
                    block=100
                )
                if not messages or not messages[0][1]:
                    messages = await asyncio.to_thread(
                        r.xreadgroup,
                        groupname=group_name,
                        consumername=self._worker_id,
                        streams={stream_name: ">"},
                        count=5,
                        block=1000
                    )

                if not messages or not messages[0][1]:
                    await asyncio.sleep(0.5)
                    continue

                for s_name, s_msgs in messages:
                    for msg_id, payload in s_msgs:
                        try:
                            if not isinstance(payload, dict):
                                await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
                                continue

                            flows_json = payload.get("flows")
                            if not flows_json:
                                # Not a flow message or empty payload, ack and discard
                                await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
                                continue

                            try:
                                flows = json.loads(flows_json)
                            except (json.JSONDecodeError, TypeError) as parse_err:
                                logger.warning("Corrupted flow payload in stream (%s): %s", msg_id, parse_err)
                                await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
                                continue

                            if not isinstance(flows, list):
                                await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
                                continue

                            org_id = payload.get("org_id") or "default-org-id"
                            
                            # Authoritative org_id context passing
                            incidents = self.analyze_flows(org_id, flows)
                            
                            for inc in incidents:
                                logger.warning("[CORRELATION ENGINE] %s", inc["message"])
                                INCIDENTS_CREATED.inc()
                                ALERTS_GENERATED.labels(severity=inc["severity"]).inc()
                                
                                await emit_event(
                                    "alert_event",
                                    {
                                        "organization_id": org_id,
                                        "id": f"corr-{time.time_ns()}",
                                        "severity": inc["severity"],
                                        "score": inc["confidence_score"],
                                        "confidence_level": inc["confidence_level"],
                                        "message": inc["message"],
                                        "src_ip": inc["src_ip"],
                                        "application": "Security Correlator",
                                        "time": inc["timestamp"]
                                    }
                                )

                            await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)

                        except Exception as inner_err:
                            logger.error("Error in correlation analyzer: %s", inner_err)
                            # Exception occurs during analysis: do NOT ACK. It stays in PEL for retry or DLQ routing.
            except Exception as loop_err:
                if "Timeout reading from socket" in str(loop_err):
                    logger.debug("Redis correlation stream idle timeout: %s", loop_err)
                else:
                    logger.error("Error in correlation worker loop: %s", loop_err)
                    use_redis = False
                await asyncio.sleep(0.5)

correlation_worker = CorrelationWorker()
