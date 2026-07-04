import asyncio
import logging
import json
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from app.db.redis_client import get_redis_connection
from app.middleware.prometheus_middleware import INCIDENTS_CREATED, ALERTS_GENERATED
from app.realtime import emit_event

logger = logging.getLogger("netvisor.services.correlation")

class CorrelationWorker:
    def __init__(self) -> None:
        self._worker_id = f"correlation-worker-{time.time_ns()}"
        # Connection tracking for port scanning: src_ip -> deque of (timestamp, dst_ip)
        self.connection_history = defaultdict(lambda: deque(maxlen=100))
        # Chain tracking for lateral movement: src_ip -> set of dst_ips
        self.connections_map = defaultdict(set)
        self.last_cleanup = time.time()

    def _cleanup_old_data(self):
        """Clean up history older than 60 seconds."""
        now = time.time()
        if now - self.last_cleanup < 30:
            return
        self.last_cleanup = now
        
        # Cleanup scan history
        for src_ip, history in list(self.connection_history.items()):
            while history and now - history[0][0] > 60:
                history.popleft()
            if not history:
                del self.connection_history[src_ip]

        # Reset connections map periodically to prevent memory growth
        self.connections_map.clear()

    def analyze_flows(self, flows: list) -> list[dict]:
        """Analyzes a batch of flows for correlation patterns and returns generated incidents."""
        incidents = []
        now = time.time()

        for flow in flows:
            src_ip = flow.get("src_ip")
            dst_ip = flow.get("dst_ip")
            if not src_ip or not dst_ip:
                continue

            # Skip localhost or same-IP traffic
            if src_ip == dst_ip:
                continue

            # Record connection
            self.connection_history[src_ip].append((now, dst_ip))
            self.connections_map[src_ip].add(dst_ip)

            # 1. Check for Horizontal Scan: 5+ distinct dst_ips within 10 seconds
            recent_dsts = set()
            for ts, dip in self.connection_history[src_ip]:
                if now - ts <= 10:
                    recent_dsts.add(dip)
            
            if len(recent_dsts) >= 5:
                incident = {
                    "type": "horizontal_scan",
                    "severity": "HIGH",
                    "message": f"Potential horizontal port/IP scan detected from {src_ip} targeting {len(recent_dsts)} endpoints.",
                    "src_ip": src_ip,
                    "targets": list(recent_dsts),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                incidents.append(incident)
                # Clear to avoid duplicate alerts immediately
                self.connection_history[src_ip].clear()

            # 2. Check for Lateral Movement: A -> B and B -> C
            # If B connects to C, check if someone connected to B recently
            for prior_src, dsts in list(self.connections_map.items()):
                if src_ip in dsts and dst_ip not in dsts:
                    # prior_src connected to src_ip, and src_ip connected to dst_ip!
                    # This forms prior_src -> src_ip -> dst_ip chain!
                    incident = {
                        "type": "lateral_movement",
                        "severity": "CRITICAL",
                        "message": f"Lateral movement chain detected: {prior_src} -> {src_ip} -> {dst_ip}.",
                        "src_ip": src_ip,
                        "chain": [prior_src, src_ip, dst_ip],
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    incidents.append(incident)

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
                    # Create group
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
                # Read new messages
                messages = await asyncio.to_thread(
                    r.xreadgroup,
                    groupname=group_name,
                    consumername=self._worker_id,
                    streams={stream_name: ">"},
                    count=10,
                    block=2000
                )

                if not messages or not messages[0][1]:
                    await asyncio.sleep(0.5)
                    continue

                for s_name, s_msgs in messages:
                    for msg_id, payload in s_msgs:
                        try:
                            flows_json = payload.get("flows")
                            flows = json.loads(flows_json)
                            
                            # Analyze
                            incidents = self.analyze_flows(flows)
                            
                            for inc in incidents:
                                logger.warning("[CORRELATION ENGINE] %s", inc["message"])
                                # Update Prometheus Metrics
                                INCIDENTS_CREATED.inc()
                                ALERTS_GENERATED.labels(severity=inc["severity"]).inc()
                                
                                # Emit realtime alert event
                                await emit_event(
                                    "alert_event",
                                    {
                                        "organization_id": payload.get("org_id") or "default-org-id",
                                        "id": f"corr-{time.time_ns()}",
                                        "severity": inc["severity"],
                                        "score": 85 if inc["severity"] == "CRITICAL" else 75,
                                        "message": inc["message"],
                                        "src_ip": inc["src_ip"],
                                        "application": "Security Correlator",
                                        "time": inc["timestamp"]
                                    }
                                )

                            # ACK the message (correlation worker does not delete, flow worker deletes)
                            await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)

                        except Exception as inner_err:
                            logger.error("Error in correlation analyzer: %s", inner_err)
                            # ACK anyway to prevent block
                            await asyncio.to_thread(r.xack, stream_name, group_name, msg_id)
            except Exception as loop_err:
                logger.error("Error in correlation worker loop: %s", loop_err)
                use_redis = False
                await asyncio.sleep(2.0)

correlation_worker = CorrelationWorker()
