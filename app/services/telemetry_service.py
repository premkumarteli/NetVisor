import json
from datetime import datetime, timezone
from typing import List, Dict, Any

from ..db.session import get_db_connection

class TelemetryService:
    def ingest_logs(self, conn, agent_id: str, organization_id: str, logs: List[Dict[str, Any]]) -> int:
        """Ingest a batch of telemetry logs from an agent."""
        if not logs:
            return 0
            
        cursor = conn.cursor()
        try:
            records = []
            for log in logs:
                records.append((
                    agent_id,
                    organization_id,
                    log.get("log_level", "INFO"),
                    log.get("category", "system"),
                    log.get("message", ""),
                    json.dumps(log.get("metadata") or {}),
                    log.get("timestamp", datetime.now(timezone.utc).isoformat())
                ))
            
            cursor.executemany(
                """
                INSERT INTO telemetry_logs (
                    agent_id, organization_id, log_level, category, message, metadata_json, timestamp
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                records
            )
            return cursor.rowcount
        finally:
            cursor.close()

telemetry_service = TelemetryService()
