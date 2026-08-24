from typing import List, Optional, Dict, Any
import logging
import json
from datetime import datetime, timezone

from ..core.config import settings

logger = logging.getLogger("netvisor.services.alerts")

class AlertService:
    def get_alerts(
        self,
        db_conn,
        organization_id: str,
        limit: int = 50,
        severities: Optional[List[str]] = None,
        alert_types: Optional[List[str]] = None,
        resolved: Optional[bool] = None,
        hours: Optional[int] = None,
    ) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            conditions = ["organization_id = %s"]
            params: list = [organization_id]

            if severities:
                placeholders = ", ".join(["%s"] * len(severities))
                conditions.append(f"severity IN ({placeholders})")
                params.extend(severities)

            if alert_types:
                placeholders = ", ".join(["%s"] * len(alert_types))
                conditions.append(f"alert_type IN ({placeholders})")
                params.extend(alert_types)

            if resolved is not None:
                conditions.append("resolved = %s")
                params.append(resolved)

            if hours is not None and hours > 0:
                conditions.append("timestamp >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s HOUR)")
                params.append(hours)

            query = f"""
                SELECT * FROM alerts
                WHERE {" AND ".join(conditions)}
                ORDER BY timestamp DESC LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            for r in rows:
                if r.get('breakdown_json'):
                    try:
                        r['breakdown'] = json.loads(r['breakdown_json'])
                    except Exception:
                        r['breakdown'] = {}
                reasons = r.get("breakdown", {}).get("reasons", [])
                if reasons:
                    r["message"] = ", ".join(reasons)
                elif not r.get("message"):
                    r["message"] = f"{r.get('severity', 'LOW').title()} risk activity detected ({r.get('alert_type', 'ANOMALY')})"
            return rows
        finally:
            cursor.close()

    def record_risk_event(
        self,
        db_conn,
        *,
        organization_id: str,
        device_id: str,
        risk_type: str,
        score: int,
        confidence: float = 1.0,
        evidence_json: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            evidence_str = json.dumps(evidence_json) if evidence_json else None
            cursor.execute(
                """
                INSERT INTO risk_events (
                    organization_id, device_id, risk_type, confidence, score, evidence_json, timestamp
                )
                VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP())
                """,
                (organization_id, device_id, risk_type, confidence, score, evidence_str)
            )
            db_conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error("Failed to record risk event: %s", e)
            db_conn.rollback()
            return None
        finally:
            cursor.close()

    def get_risk_events(
        self,
        db_conn,
        organization_id: str,
        device_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            conditions = ["organization_id = %s"]
            params: list = [organization_id]
            if device_id:
                conditions.append("device_id = %s")
                params.append(device_id)

            query = f"""
                SELECT id, organization_id, device_id, risk_type, confidence, score, evidence_json, timestamp
                FROM risk_events
                WHERE {" AND ".join(conditions)}
                ORDER BY timestamp DESC LIMIT %s
            """
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            for r in rows:
                if r.get("evidence_json") and isinstance(r["evidence_json"], str):
                    try:
                        r["evidence_json"] = json.loads(r["evidence_json"])
                    except Exception:
                        pass
                if r.get("timestamp") and hasattr(r["timestamp"], "strftime"):
                    r["timestamp"] = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            return rows
        finally:
            cursor.close()

    def get_risk_ranking(self, db_conn, organization_id: str, limit: int = 10) -> List[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            if organization_id and not settings.SINGLE_ORG_MODE:
                cursor.execute("""
                    SELECT device_id, device_id AS ip_address, current_score, risk_level, reasons
                    FROM device_risks
                    WHERE organization_id = %s
                    ORDER BY current_score DESC LIMIT %s
                """, (organization_id, limit))
            else:
                cursor.execute("""
                    SELECT device_id, device_id AS ip_address, current_score, risk_level, reasons
                    FROM device_risks
                    ORDER BY current_score DESC LIMIT %s
                """, (limit,))
            return cursor.fetchall()
        finally:
            cursor.close()

alert_service = AlertService()

