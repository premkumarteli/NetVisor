import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from ..db.session import get_db_connection

class ConfigService:
    def get_agent_config(self, conn, agent_id: str, organization_id: str) -> Dict[str, Any]:
        """Fetch the current configuration for an agent."""
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT capture_backend, promiscuous_mode, flow_flush_interval_seconds,
                       max_buffer_mb, telemetry_enabled, telemetry_interval_seconds
                FROM agent_configs
                WHERE agent_id = %s AND organization_id = %s
                """,
                (agent_id, organization_id)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "capture_backend": row["capture_backend"],
                    "promiscuous_mode": bool(row["promiscuous_mode"]),
                    "flow_flush_interval_seconds": row["flow_flush_interval_seconds"],
                    "max_buffer_mb": row["max_buffer_mb"],
                    "telemetry_enabled": bool(row["telemetry_enabled"]),
                    "telemetry_interval_seconds": row["telemetry_interval_seconds"],
                }
            
            # Default fallback if no config exists
            return self._get_default_config()
        finally:
            cursor.close()

    def update_agent_config(self, conn, agent_id: str, organization_id: str, config: Dict[str, Any]) -> None:
        """Upsert the configuration for an agent."""
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO agent_configs (
                    agent_id, organization_id, capture_backend, promiscuous_mode,
                    flow_flush_interval_seconds, max_buffer_mb, telemetry_enabled, telemetry_interval_seconds
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    capture_backend = VALUES(capture_backend),
                    promiscuous_mode = VALUES(promiscuous_mode),
                    flow_flush_interval_seconds = VALUES(flow_flush_interval_seconds),
                    max_buffer_mb = VALUES(max_buffer_mb),
                    telemetry_enabled = VALUES(telemetry_enabled),
                    telemetry_interval_seconds = VALUES(telemetry_interval_seconds)
                """,
                (
                    agent_id,
                    organization_id,
                    config.get("capture_backend", "auto"),
                    config.get("promiscuous_mode", True),
                    config.get("flow_flush_interval_seconds", 60),
                    config.get("max_buffer_mb", 500),
                    config.get("telemetry_enabled", True),
                    config.get("telemetry_interval_seconds", 60),
                )
            )
        finally:
            cursor.close()

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "capture_backend": "auto",
            "promiscuous_mode": True,
            "flow_flush_interval_seconds": 60,
            "max_buffer_mb": 500,
            "telemetry_enabled": True,
            "telemetry_interval_seconds": 60,
        }

config_service = ConfigService()
