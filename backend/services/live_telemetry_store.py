import threading
import time
import logging
from collections import defaultdict, deque
from typing import Optional, Any

logger = logging.getLogger("netvisor.services.live_telemetry")

class LiveTelemetryStore:
    def __init__(self):
        self._global_lock = threading.Lock()
        self._locks = defaultdict(threading.Lock)
        self._states = defaultdict(self._create_empty_org_state)
        
        # Start background pruning daemon thread
        self._stop_pruning = threading.Event()
        self._prune_thread = threading.Thread(target=self._prune_loop, daemon=True)
        self._prune_thread.start()

    def _get_org_lock(self, org_id: str) -> threading.Lock:
        with self._global_lock:
            return self._locks[org_id]

    def _prune_loop(self) -> None:
        while not self._stop_pruning.is_set():
            try:
                time.sleep(5)
                now = time.time()
                with self._global_lock:
                    orgs = list(self._states.keys())
                for org_id in orgs:
                    with self._get_org_lock(org_id):
                        self.prune_old_samples(org_id, now)
            except Exception:
                logger.exception("Error in live telemetry background prune loop")

    def _create_empty_org_state(self):
        return {
            "bytes_in_window": 0.0,
            "packets_in_window": 0,
            "active_devices": {},        # ip -> last_seen_timestamp
            "total_devices_count": 0,
            "recent_alerts": deque(maxlen=100),
            "recent_activity": deque(maxlen=500),  # 500-item in-memory ring buffer for activity stream
            "risk_distribution": defaultdict(int),
            "top_applications": defaultdict(float),
            "top_protocols": defaultdict(float),
            "bandwidth_samples": deque(),  # deque of (timestamp, byte_count)
            "active_flows": {},          # flow_key -> last_seen_timestamp
            "flows_24h": 0,
            "known_ips": set(),
        }

    def _format_bytes(self, byte_count: float) -> str:
        if byte_count >= 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        if byte_count >= 1024:
            return f"{byte_count / 1024:.1f} KB"
        return f"{int(byte_count)} B"

    def initialize_from_db(self, conn) -> None:
        """Prime the live telemetry store with initial values from MySQL."""
        cursor = conn.cursor(dictionary=True)
        try:
            # 1. Total devices count and known IPs per org
            cursor.execute("SELECT ip, organization_id FROM devices")
            for row in cursor.fetchall() or []:
                org_id = row.get("organization_id") or "default"
                ip = row.get("ip")
                if ip:
                    self._states[org_id]["known_ips"].add(ip)
                
                # Reset counter to 0 first and increment
                self._states[org_id]["total_devices_count"] = len(self._states[org_id]["known_ips"])

            # 2. Risk distribution of unresolved alerts in the last 24 hours
            cursor.execute(
                """
                SELECT organization_id, severity, COUNT(*) AS count
                FROM alerts
                WHERE resolved = FALSE AND timestamp >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)
                GROUP BY organization_id, severity
                """
            )
            for row in cursor.fetchall() or []:
                org_id = row.get("organization_id") or "default"
                sev = str(row.get("severity") or "LOW").upper()
                self._states[org_id]["risk_distribution"][sev] = int(row.get("count") or 0)

            # 3. Flows count in the last 24 hours
            cursor.execute(
                """
                SELECT organization_id, COUNT(*) AS count
                FROM flow_logs
                WHERE last_seen >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)
                GROUP BY organization_id
                """
            )
            for row in cursor.fetchall() or []:
                org_id = row.get("organization_id") or "default"
                self._states[org_id]["flows_24h"] = int(row.get("count") or 0)

            # 4. Recent alerts
            cursor.execute(
                """
                SELECT id, organization_id, device_ip, severity, risk_score, breakdown_json, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 100
                """
            )
            for row in cursor.fetchall() or []:
                org_id = row.get("organization_id") or "default"
                alert_data = {
                    "id": row.get("id"),
                    "severity": row.get("severity"),
                    "score": row.get("risk_score"),
                    "src_ip": row.get("device_ip"),
                    "time": str(row.get("timestamp")),
                }
                # Add a message field for frontend UI compatibility
                try:
                    import json
                    breakdown = json.loads(row.get("breakdown_json") or "{}")
                    alert_data["message"] = breakdown.get("message") or "Suspicious activity detected"
                except Exception:
                    alert_data["message"] = "Suspicious activity detected"
                self._states[org_id]["recent_alerts"].append(alert_data)

            # 5. Recent activity ring buffer priming
            cursor.execute(
                """
                SELECT
                    f.last_seen,
                    f.src_ip,
                    f.dst_ip,
                    f.src_port,
                    f.dst_port,
                    f.external_endpoint_ip,
                    f.sni,
                    f.domain,
                    COALESCE(NULLIF(f.application, ''), 'Other') AS application,
                    f.protocol,
                    f.byte_count,
                    COALESCE(r.risk_level, 'LOW') AS severity,
                    f.organization_id
                FROM flow_logs f
                LEFT JOIN device_risks r ON f.src_ip = r.device_id
                ORDER BY f.last_seen DESC
                LIMIT 100
                """
            )
            for row in cursor.fetchall() or []:
                org_id = row.get("organization_id") or "default"
                act = {
                    "time": str(row.get("last_seen") or ""),
                    "last_seen": str(row.get("last_seen") or ""),
                    "src_ip": row.get("src_ip"),
                    "dst_ip": row.get("dst_ip"),
                    "src_port": row.get("src_port"),
                    "dst_port": row.get("dst_port"),
                    "external_endpoint_ip": row.get("external_endpoint_ip"),
                    "sni": row.get("sni"),
                    "domain": row.get("domain"),
                    "application": row.get("application") or "Other",
                    "protocol": row.get("protocol"),
                    "byte_count": row.get("byte_count") or 0,
                    "severity": row.get("severity") or "LOW",
                    "management_mode": "managed" if row.get("src_ip") in self._states[org_id]["known_ips"] else "byod",
                }
                self._states[org_id]["recent_activity"].append(act)

            logger.info("LiveTelemetryStore primed successfully from DB.")
        except Exception:
            logger.exception("Failed to prime LiveTelemetryStore from DB.")
        finally:
            cursor.close()

    def record_flow(self, organization_id: str, flow_key: tuple, bytes_count: int, packets_count: int, app: str, proto: str, is_new: bool, is_end: bool) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            now = time.time()
            state["bandwidth_samples"].append((now, bytes_count))
            state["bytes_in_window"] += bytes_count
            state["packets_in_window"] += packets_count

            # Track active flows
            if is_new:
                state["active_flows"][flow_key] = now
                state["flows_24h"] += 1
            else:
                state["active_flows"][flow_key] = now

            if is_end:
                state["active_flows"].pop(flow_key, None)

            # Track top applications and protocols
            if app:
                state["top_applications"][app] += bytes_count
            if proto:
                state["top_protocols"][proto] += bytes_count

    def _is_private_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private and not ip_obj.is_multicast and not ip_obj.is_loopback
        except Exception:
            return False

    def record_device_seen(self, organization_id: str, ip: str) -> None:
        if not self._is_private_ip(ip):
            return
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            if ip in state["known_ips"]:
                state["active_devices"][ip] = time.time()

    def register_known_ip(self, organization_id: str, ip: str) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            state["known_ips"].add(ip)
            state["total_devices_count"] = len(state["known_ips"])

    def increment_device_count(self, organization_id: str) -> None:
        # Kept for backward compatibility, register_known_ip updates count automatically
        pass

    def record_alert(self, organization_id: str, alert_data: dict) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            state["recent_alerts"].appendleft(alert_data)
            severity = str(alert_data.get("severity") or "LOW").upper()
            state["risk_distribution"][severity] += 1

    def prune_old_samples(self, organization_id: str, now: float) -> None:
        state = self._states[organization_id or "default"]
        # Bandwidth sliding window (60s)
        cutoff = now - 60.0
        samples = state["bandwidth_samples"]
        while samples and samples[0][0] < cutoff:
            ts, bytes_val = samples.popleft()
            state["bytes_in_window"] = max(0.0, state["bytes_in_window"] - bytes_val)

        # Active devices inactivity timeout (5m)
        device_cutoff = now - 300.0
        active_devs = state["active_devices"]
        for ip, last_seen in list(active_devs.items()):
            if last_seen < device_cutoff:
                del active_devs[ip]

        # Active flows inactivity timeout (60s)
        flow_cutoff = now - 60.0
        active_fls = state["active_flows"]
        for fkey, last_seen in list(active_fls.items()):
            if last_seen < flow_cutoff:
                del active_fls[fkey]

    def record_agent_status(
        self,
        organization_id: str,
        agent_id: str,
        status: str = "online",
        queue_depth: int = 0,
        errors: int = 0,
        degraded: Optional[bool] = None,
    ) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            if "agents" not in state:
                state["agents"] = {}
            is_deg = degraded if degraded is not None else (status.lower() == "online" and (queue_depth > 0 or errors > 0))
            state["agents"][agent_id] = {
                "status": status,
                "queue_depth": queue_depth,
                "errors": errors,
                "degraded": is_deg,
            }

    def record_gateway_status(
        self,
        organization_id: str,
        gateway_id: str,
        status: str = "online",
        queue_depth: int = 0,
        errors: int = 0,
        degraded: Optional[bool] = None,
    ) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            if "gateways" not in state:
                state["gateways"] = {}
            is_deg = degraded if degraded is not None else (status.lower() == "online" and (queue_depth > 0 or errors > 0))
            state["gateways"][gateway_id] = {
                "status": status,
                "queue_depth": queue_depth,
                "errors": errors,
                "degraded": is_deg,
            }

    def get_overview_stats(self, organization_id: Optional[str], db_conn=None) -> dict:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            bandwidth_bytes = state["bytes_in_window"]
            bandwidth_mbps = round((bandwidth_bytes * 8) / (60 * 1000 * 1000), 4)
            bandwidth_str = self._format_bytes(bandwidth_bytes / 60) + "/s"

            high_risk = state["risk_distribution"].get("HIGH", 0) + state["risk_distribution"].get("CRITICAL", 0)
            total_threats = sum(state["risk_distribution"].values())

            base_stats = {
                "active_devices": len(state["active_devices"]),
                "total_devices": state["total_devices_count"],
                "high_risk": high_risk,
                "flows_24h": state["flows_24h"],
                "bandwidth": bandwidth_str,
                "bandwidth_value": bandwidth_mbps,
                "bandwidth_bytes_sec": round(bandwidth_bytes / 60, 2),
                "risk_distribution": dict(state["risk_distribution"]),
                "threat_summary": {
                    "total": total_threats,
                    "high_critical": high_risk
                }
            }
            mem_agents = dict(state.get("agents", {})) if "agents" in state else None
            mem_gateways = dict(state.get("gateways", {})) if "gateways" in state else None

        agents_summary = {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}
        gateways_summary = {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}

        if db_conn is not None:
            try:
                from .agent_service import agent_service
                from .gateway_service import gateway_service

                effective_org_id = None if organization_id == "default" else organization_id
                agents_summary = agent_service.get_agents_summary(db_conn, organization_id=effective_org_id)
                gateways_summary = gateway_service.get_gateways_summary(db_conn, organization_id=effective_org_id)
            except Exception as exc:
                logger.debug("Failed to fetch fleet summaries from DB for live telemetry overview: %s", exc)

        # Merge in-memory state overrides if present (e.g. for unit testing fresh_telemetry_store or realtime updates)
        if mem_agents:
            if db_conn is None:
                agents_summary = {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}
            agents_summary["total"] += len(mem_agents)
            for a in mem_agents.values():
                st = str(a.get("status", "")).lower()
                if st == "online":
                    agents_summary["online"] += 1
                else:
                    agents_summary["offline"] += 1
                qd = int(a.get("queue_depth") or 0)
                agents_summary["queue_depth"] += qd
                err = int(a.get("errors") or 0)
                if st == "online" and (bool(a.get("degraded")) or qd > 0 or err > 0):
                    agents_summary["degraded"] += 1

        if mem_gateways:
            if db_conn is None:
                gateways_summary = {"online": 0, "offline": 0, "total": 0, "degraded": 0, "queue_depth": 0}
            gateways_summary["total"] += len(mem_gateways)
            for g in mem_gateways.values():
                st = str(g.get("status", "")).lower()
                if st == "online":
                    gateways_summary["online"] += 1
                else:
                    gateways_summary["offline"] += 1
                qd = int(g.get("queue_depth") or 0)
                gateways_summary["queue_depth"] += qd
                err = int(g.get("errors") or 0)
                if st == "online" and (bool(g.get("degraded")) or qd > 0 or err > 0):
                    gateways_summary["degraded"] += 1


        fleet_summary = {
            "total_queue_depth": agents_summary.get("queue_depth", 0) + gateways_summary.get("queue_depth", 0),
            "total_degraded": agents_summary.get("degraded", 0) + gateways_summary.get("degraded", 0),
        }

        base_stats["agents_summary"] = agents_summary
        base_stats["gateways_summary"] = gateways_summary
        base_stats["fleet_summary"] = fleet_summary

        return base_stats


    def get_recent_alerts(self, organization_id: Optional[str], limit: int = 12) -> list[dict]:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            alerts = list(self._states[org_id]["recent_alerts"])
            return alerts[:limit]

    def record_recent_activity(self, organization_id: Optional[str], activity_dict: dict) -> None:
        """Appends a new flow activity event to the in-memory 500-item ring buffer."""
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            self._states[org_id]["recent_activity"].appendleft(activity_dict)

    def get_recent_activity(self, organization_id: Optional[str] = None, limit: int = 50) -> list[dict]:
        """Returns recent activity events instantly from in-memory ring buffer."""
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            items = list(self._states[org_id]["recent_activity"])
            return items[:limit]


# Global singleton store instance
live_telemetry_store = LiveTelemetryStore()
