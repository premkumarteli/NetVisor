import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.core.config import settings

logger = logging.getLogger("netvisor.services.clickhouse_analytics")


class ClickHouseAnalyticsBridge:
    """
    High-Performance Columnar Analytical Query Bridge.

    Routes heavy aggregation queries (dashboard stats, device rollups, bandwidth metrics)
    to ClickHouse for sub-50ms SIMD evaluation. Transparently falls back to MySQL
    if ClickHouse is unreachable or disabled.
    """

    def is_available(self) -> bool:
        """Checks if ClickHouse is enabled and reachable."""
        if not getattr(settings, "CLICKHOUSE_ENABLED", True):
            return False
        try:
            from backend.db.clickhouse_client import get_clickhouse_client
            client = get_clickhouse_client()
            # Fast ping command
            client.command("SELECT 1")
            return True
        except Exception:
            return False

    def query_dashboard_flow_stats(self, organization_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves 24-hour total flows, bytes, and 1-minute bandwidth from ClickHouse.
        Returns None if ClickHouse is offline, signaling fallback to MySQL.
        """
        try:
            from backend.db.clickhouse_client import get_clickhouse_client
            client = get_clickhouse_client()

            org_clause = "AND organization_id = %(org_id)s" if organization_id else ""
            params = {"org_id": organization_id or ""}

            # 24-hour totals
            query_24h = f"""
                SELECT
                    count() AS flows_24h,
                    coalesce(sum(byte_count), 0) AS bytes_24h
                FROM flow_logs
                WHERE last_seen >= now() - INTERVAL 1 DAY
                {org_clause}
            """
            res_24h = client.query(query_24h, parameters=params)
            flows_24h = 0
            bytes_24h = 0
            if res_24h.result_rows:
                flows_24h = int(res_24h.result_rows[0][0] or 0)
                bytes_24h = int(res_24h.result_rows[0][1] or 0)

            # 1-minute bandwidth bytes
            query_1m = f"""
                SELECT
                    coalesce(sum(byte_count), 0) AS bandwidth_bytes
                FROM flow_logs
                WHERE last_seen >= now() - INTERVAL 1 MINUTE
                {org_clause}
            """
            res_1m = client.query(query_1m, parameters=params)
            bandwidth_bytes = 0
            if res_1m.result_rows:
                bandwidth_bytes = int(res_1m.result_rows[0][0] or 0)

            return {
                "flows_24h": flows_24h,
                "bytes_24h": bytes_24h,
                "bandwidth_bytes": bandwidth_bytes,
            }
        except Exception as e:
            logger.debug("ClickHouse dashboard flow query failed (falling back to MySQL): %s", e)
            return None

    def query_device_rollup(
        self, organization_id: Optional[str] = None, hours: int = 24, limit: int = 50
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieves top bandwidth devices and flow counts from ClickHouse.
        Returns None if ClickHouse is offline.
        """
        try:
            from backend.db.clickhouse_client import get_clickhouse_client
            client = get_clickhouse_client()

            org_clause = "AND organization_id = %(org_id)s" if organization_id else ""
            params = {
                "org_id": organization_id or "",
                "hours": hours,
                "limit": limit,
            }

            query = f"""
                SELECT
                    coalesce(nullif(internal_device_ip, ''), src_ip) AS device_ip,
                    count() AS flow_count,
                    coalesce(sum(byte_count), 0) AS bandwidth_bytes,
                    uniqExact(dst_ip) AS distinct_targets,
                    max(last_seen) AS last_seen
                FROM flow_logs
                WHERE last_seen >= now() - INTERVAL %(hours)s HOUR
                {org_clause}
                GROUP BY device_ip
                ORDER BY bandwidth_bytes DESC, flow_count DESC
                LIMIT %(limit)s
            """
            result = client.query(query, parameters=params)
            rows = []
            for r in result.result_rows:
                last_seen_dt = r[4]
                if isinstance(last_seen_dt, datetime):
                    last_seen_str = last_seen_dt.isoformat()
                else:
                    last_seen_str = str(last_seen_dt or "")

                rows.append({
                    "device_ip": r[0],
                    "flow_count": int(r[1] or 0),
                    "bandwidth_bytes": int(r[2] or 0),
                    "distinct_targets": int(r[3] or 0),
                    "last_seen": last_seen_str,
                })
            return rows
        except Exception as e:
            logger.debug("ClickHouse device rollup query failed (falling back to MySQL): %s", e)
            return None


clickhouse_analytics = ClickHouseAnalyticsBridge()
