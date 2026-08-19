from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..core.config import settings
from ..db.session import require_runtime_schema


class GatewayService:
    def __init__(self) -> None:
        self._schema_ready = False

    def _column_exists(self, cursor, table_name: str, column_name: str) -> bool:
        cursor.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND column_name = %s
            LIMIT 1
            """,
            (table_name, column_name),
        )
        return cursor.fetchone() is not None

    def ensure_table(self, db_conn) -> None:
        if self._schema_ready:
            return
        require_runtime_schema(db_conn)
        self._schema_ready = True

    def upsert_gateway(
        self,
        db_conn,
        *,
        gateway_id: str,
        organization_id: str | None,
        hostname: str | None,
        capture_mode: str | None,
    ) -> None:
        if not gateway_id:
            return

        self.ensure_table(db_conn)

        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gateways (gateway_id, organization_id, hostname, capture_mode, created_at, last_seen)
                VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    organization_id = COALESCE(VALUES(organization_id), organization_id),
                    hostname = VALUES(hostname),
                    capture_mode = VALUES(capture_mode),
                    last_seen = UTC_TIMESTAMP()
                """,
                (
                    gateway_id,
                    organization_id,
                    hostname or "Unknown",
                    capture_mode or "promiscuous",
                ),
            )
            db_conn.commit()
        finally:
            cursor.close()

    def _heartbeat_age_seconds(self, last_seen) -> Optional[int]:
        if not last_seen:
            return None
        dt = None
        if isinstance(last_seen, str):
            val = last_seen.strip()
            if val.endswith("Z") or val.endswith("z"):
                val = val[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(val)
            except (ValueError, TypeError):
                try:
                    dt = datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    return None
        elif isinstance(last_seen, datetime):
            dt = last_seen
        else:
            return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        delta = datetime.now(timezone.utc) - dt
        return max(int(delta.total_seconds()), 0)

    def get_gateways_summary(
        self,
        db_conn,
        organization_id: str | None = None,
        online_window_seconds: int = 20,
    ) -> dict[str, int]:
        self.ensure_table(db_conn)
        cursor = db_conn.cursor(dictionary=True)
        try:
            params: list = []
            where_clause = ""
            if organization_id and not settings.SINGLE_ORG_MODE:
                where_clause = " WHERE g.organization_id = %s OR g.organization_id IS NULL"
                params.append(organization_id)

            query = f"""
                SELECT
                    g.gateway_id,
                    g.organization_id,
                    g.hostname,
                    g.capture_mode,
                    g.cert_status,
                    g.last_seen,
                    COALESCE(q.queue_depth, 0) AS queue_depth,
                    COALESCE(q.flow_ingest_errors, 0) AS flow_ingest_errors
                FROM gateways g
                LEFT JOIN (
                    SELECT
                        source_id,
                        SUM(CASE WHEN status IN ('pending', 'retrying') THEN flow_count ELSE 0 END) AS queue_depth,
                        SUM(CASE WHEN attempt_count > 0 OR status IN ('failed', 'deadletter') THEN 1 ELSE 0 END) AS flow_ingest_errors
                    FROM flow_ingest_batches
                    WHERE source_type = 'gateway'
                    GROUP BY source_id
                ) q ON q.source_id = g.gateway_id
                {where_clause}
                ORDER BY g.last_seen DESC
            """
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall() or []

            total = len(rows)
            online = 0
            offline = 0
            degraded = 0
            total_queue_depth = 0

            for row in rows:
                last_seen = row.get("last_seen")
                age = self._heartbeat_age_seconds(last_seen)
                is_online = age is not None and age <= online_window_seconds

                if is_online:
                    online += 1
                else:
                    offline += 1

                qd = int(row.get("queue_depth") or 0)
                total_queue_depth += qd

                errors = int(row.get("flow_ingest_errors") or 0)
                cert_status = str(row.get("cert_status") or "none").lower()

                if is_online:
                    if errors > 0 or qd > 0 or cert_status != "active":
                        degraded += 1

            return {
                "online": online,
                "offline": offline,
                "total": total,
                "degraded": degraded,
                "queue_depth": total_queue_depth,
            }
        finally:
            cursor.close()


gateway_service = GatewayService()

