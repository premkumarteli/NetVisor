from __future__ import annotations

import logging
from typing import Optional, Dict, Any
from datetime import datetime
import hashlib
import threading
from collections import defaultdict

from ..db.session import get_db_connection
from ..core.config import settings

logger = logging.getLogger("netvisor.audit")


class AuditService:
    def __init__(self):
        self.enabled = True  # Could be made configurable
        self._locks = defaultdict(threading.Lock)

    def _log_audit_event(
        self,
        organization_id: str,
        username: str,
        action: str,
        ip_address: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[str] = None,
    ) -> None:
        if not self.enabled:
            return
            
        org_id = organization_id or "default-org-id"
        lock = self._locks[org_id]
        with lock:
            conn = None
            cursor = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                prev_id = None
                prev_chain_hash = settings.AUDIT_CHAIN_GENESIS
                
                if hasattr(cursor, "fetchone"):
                    cursor.execute(
                        """
                        SELECT id, chain_hash
                        FROM audit_logs
                        WHERE organization_id = %s
                        ORDER BY id DESC
                        LIMIT 1
                        FOR UPDATE
                        """,
                        (org_id,),
                    )
                    prev_row = cursor.fetchone()
                    if prev_row:
                        if isinstance(prev_row, dict):
                            prev_id = prev_row.get("id")
                            prev_chain_hash = prev_row.get("chain_hash") or settings.AUDIT_CHAIN_GENESIS
                        else:
                            prev_id = prev_row[0]
                            prev_chain_hash = prev_row[1] or settings.AUDIT_CHAIN_GENESIS
                
                created_at = datetime.now()
                cursor.execute(
                    """
                    INSERT INTO audit_logs (organization_id, username, action, ip_address, resource, details, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        org_id,
                        username,
                        action,
                        ip_address,
                        resource,
                        details,
                        created_at,
                    ),
                )
                
                new_id = getattr(cursor, "lastrowid", None)
                
                if new_id and settings.AUDIT_CHAIN_ENABLED:
                    created_at_str = created_at.strftime("%Y-%m-%d %H:%M:%S")
                    payload_str = f"{new_id}|{org_id}|{username}|{action}|{ip_address or ''}|{resource or ''}|{details or ''}|{created_at_str}"
                    entry_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
                    
                    chain_input = f"{entry_hash}|{prev_chain_hash}"
                    chain_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
                    
                    cursor.execute(
                        """
                        UPDATE audit_logs
                        SET entry_hash = %s, chain_hash = %s, prev_id = %s
                        WHERE id = %s
                        """,
                        (entry_hash, chain_hash, prev_id, new_id),
                    )
                
                conn.commit()
            except Exception as exc:
                if conn:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                logger.error(f"Failed to write audit log: {exc}")
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()

    def log_agent_registration(
        self,
        organization_id: str,
        username: str,
        agent_id: str,
        action: str = "agent_registration",
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log agent registration events."""
        audit_details = f"agent_id: {agent_id}"
        if details:
            audit_details += f"; {details}"
        self._log_audit_event(
            organization_id=organization_id,
            username=username or "system",
            action=action,
            ip_address=ip_address,
            resource=agent_id,
            details=audit_details,
        )

    def log_credential_rotation(
        self,
        organization_id: str,
        username: str,
        agent_id: str,
        action: str = "agent_credential_rotation",
        ip_address: Optional[str] = None,
    ) -> None:
        """Log agent credential rotation events."""
        self._log_audit_event(
            organization_id=organization_id,
            username=username or "system",
            action=action,
            ip_address=ip_address,
            resource=agent_id,
            details=f"agent_id: {agent_id}",
        )

    def log_inspection_toggle(
        self,
        organization_id: str,
        username: str,
        agent_id: str,
        device_ip: str,
        enabled: bool,
        action: str = "web_inspection_toggle",
        ip_address: Optional[str] = None,
    ) -> None:
        """Log web inspection enable/disable events."""
        status = "enabled" if enabled else "disabled"
        self._log_audit_event(
            organization_id=organization_id,
            username=username or "system",
            action=action,
            ip_address=ip_address,
            resource=agent_id,
            details=f"agent_id: {agent_id}; device_ip: {device_ip}; inspection_{status}",
        )

    def log_ca_operation(
        self,
        organization_id: str,
        username: str,
        operation: str,  # install/remove/rotate
        action: str = "ca_operation",
        ip_address: Optional[str] = None,
    ) -> None:
        """Log CA install/remove/rotation events."""
        self._log_audit_event(
            organization_id=organization_id,
            username=username or "system",
            action=action,
            ip_address=ip_address,
            resource="ca",
            details=f"ca_operation: {operation}",
        )

    def log_auth_attempt(
        self,
        *,
        username: str,
        action: str,
        organization_id: str | None = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> None:
        self._log_audit_event(
            organization_id=organization_id or "default-org-id",
            username=username or "unknown",
            action=action,
            ip_address=ip_address,
            resource=resource,
            details=details,
        )



# Global instance
audit_service = AuditService()
