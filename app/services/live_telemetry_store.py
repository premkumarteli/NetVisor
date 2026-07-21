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
            "risk_distribution": defaultdict(int),
            "top_applications": defaultdict(float),
            "top_protocols": defaultdict(float),
            "bandwidth_samples": deque(),  # deque of (timestamp, byte_count)
            "active_flows": {},          # flow_key -> last_seen_timestamp
            "flows_24h": 0,
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
            # 1. Total devices count per org
            cursor.execute("SELECT organization_id, COUNT(*) AS count FROM devices GROUP BY organization_id")
            for row in cursor.fetchall() or []:
                org_id = row.get("organization_id") or "default"
                self._states[org_id]["total_devices_count"] = int(row.get("count") or 0)

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

    def record_device_seen(self, organization_id: str, ip: str) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            state["active_devices"][ip] = time.time()

    def increment_device_count(self, organization_id: str) -> None:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            state["total_devices_count"] += 1

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

    def get_overview_stats(self, organization_id: Optional[str]) -> dict:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            state = self._states[org_id]
            bandwidth_bytes = state["bytes_in_window"]
            bandwidth_mbps = round((bandwidth_bytes * 8) / (60 * 1000 * 1000), 4)
            bandwidth_str = self._format_bytes(bandwidth_bytes / 60) + "/s"

            high_risk = state["risk_distribution"].get("HIGH", 0) + state["risk_distribution"].get("CRITICAL", 0)
            total_threats = sum(state["risk_distribution"].values())

            # Return a structure perfectly matching dashboard_service get_overview_stats format
            return {
                "active_devices": len(state["active_devices"]),
                "total_devices": state["total_devices_count"],
                "high_risk": high_risk,
                "flows_24h": state["flows_24h"],
                "bandwidth": bandwidth_str,
                "bandwidth_value": bandwidth_mbps,
                "risk_distribution": dict(state["risk_distribution"]),
                "threat_summary": {
                    "total": total_threats,
                    "high_critical": high_risk
                }
            }

    def get_recent_alerts(self, organization_id: Optional[str], limit: int = 12) -> list[dict]:
        org_id = organization_id or "default"
        with self._get_org_lock(org_id):
            alerts = list(self._states[org_id]["recent_alerts"])
            return alerts[:limit]

# Global singleton store instance
live_telemetry_store = LiveTelemetryStore()
