"""
DPI governance service for explicit admin approval, audit trail, and safe defaults.
Provides hardened security controls for DPI/MITM operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional
import logging
import uuid

from ..core.config import settings
from ..db.session import get_db_connection
from ..services.audit_service import audit_service

logger = logging.getLogger("netvisor.dpi_governance")


class DPIGovernanceService:
    """Service for DPI governance with admin approval and audit trail."""
    
    def __init__(self) -> None:
        self._schema_ready = False
        
    def ensure_schema(self, db_conn) -> None:
        """Ensure DPI governance tables exist."""
        if self._schema_ready:
            return
            
        cursor = db_conn.cursor()
        try:
            # DPI policy approvals table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dpi_policy_approvals (
                    approval_id CHAR(36) PRIMARY KEY,
                    organization_id CHAR(36) NOT NULL,
                    policy_type VARCHAR(32) NOT NULL,
                    policy_config JSON,
                    requested_by VARCHAR(100) NOT NULL,
                    approved_by VARCHAR(100),
                    approval_status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                    approval_reason TEXT,
                    rejection_reason TEXT,
                    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at DATETIME,
                    effective_from DATETIME,
                    expires_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_dpi_approval_org (organization_id),
                    INDEX idx_dpi_approval_status (approval_status),
                    INDEX idx_dpi_approval_type (policy_type),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            """)
            
            # DPI operation audit table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dpi_operation_audit (
                    audit_id CHAR(36) PRIMARY KEY,
                    organization_id CHAR(36) NOT NULL,
                    agent_id VARCHAR(100),
                    operation_type VARCHAR(32) NOT NULL,
                    operation_details JSON,
                    policy_approval_id CHAR(36),
                    user_context JSON,
                    source_ip VARCHAR(50),
                    operation_status ENUM('initiated', 'completed', 'failed', 'blocked') DEFAULT 'initiated',
                    error_message TEXT,
                    bytes_inspected BIGINT DEFAULT 0,
                    domains_analyzed INT DEFAULT 0,
                    threats_detected INT DEFAULT 0,
                    operation_start DATETIME DEFAULT CURRENT_TIMESTAMP,
                    operation_end DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_dpi_audit_org (organization_id),
                    INDEX idx_dpi_audit_agent (agent_id),
                    INDEX idx_dpi_audit_status (operation_status),
                    INDEX idx_dpi_audit_timestamp (operation_start),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY (policy_approval_id) REFERENCES dpi_policy_approvals(approval_id) ON DELETE SET NULL
                )
            """)
            
            # DPI safe defaults configuration
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dpi_safe_defaults (
                    default_id CHAR(36) PRIMARY KEY,
                    organization_id CHAR(36) NOT NULL,
                    policy_type VARCHAR(32) NOT NULL,
                    safe_config JSON NOT NULL,
                    is_mandatory BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uq_dpi_default_org_type (organization_id, policy_type),
                    INDEX idx_dpi_default_org (organization_id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            """)
            
            db_conn.commit()
            self._schema_ready = True
            logger.info("DPI governance schema initialized")
        finally:
            cursor.close()
            
    def request_policy_approval(
        self,
        db_conn,
        *,
        organization_id: str,
        policy_type: str,
        policy_config: Dict,
        requested_by: str,
        source_ip: Optional[str] = None
    ) -> Dict:
        """Request approval for DPI policy."""
        approval_id = str(uuid.uuid4())
        cursor = db_conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO dpi_policy_approvals (
                    approval_id, organization_id, policy_type, policy_config,
                    requested_by, requested_at
                ) VALUES (%s, %s, %s, %s, %s, NOW())
            """, (
                approval_id, organization_id, policy_type,
                json.dumps(policy_config), requested_by
            ))
            
            db_conn.commit()
            
            # Log audit trail
            audit_service.log_dpi_operation(
                organization_id=organization_id,
                username=requested_by,
                action="dpi_policy_approval_requested",
                details=f"policy_type: {policy_type}; approval_id: {approval_id}",
                source_ip=source_ip
            )
            
            logger.info(f"DPI policy approval requested: {policy_type} for org {organization_id}")
            
            return {
                "approval_id": approval_id,
                "status": "pending",
                "message": "Policy approval request submitted for admin review"
            }
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to create DPI policy approval request: {e}")
            raise
        finally:
            cursor.close()
            
    def approve_policy(
        self,
        db_conn,
        *,
        approval_id: str,
        approved_by: str,
        approval_reason: str,
        effective_hours: int = 24
    ) -> Dict:
        """Approve a DPI policy request."""
        cursor = db_conn.cursor()
        try:
            # Get the approval request
            cursor.execute("""
                SELECT * FROM dpi_policy_approvals 
                WHERE approval_id = %s AND approval_status = 'pending'
            """, (approval_id,))
            
            request = cursor.fetchone()
            if not request:
                raise ValueError(f"Approval request {approval_id} not found or already processed")
                
            # Update approval
            effective_from = datetime.now(timezone.utc)
            expires_at = effective_from + timezone.timedelta(hours=effective_hours)
            
            cursor.execute("""
                UPDATE dpi_policy_approvals 
                SET approval_status = 'approved',
                    approved_by = %s,
                    approval_reason = %s,
                    reviewed_at = NOW(),
                    effective_from = %s,
                    expires_at = %s
                WHERE approval_id = %s
            """, (approved_by, approval_reason, effective_from, expires_at, approval_id))
            
            db_conn.commit()
            
            # Log audit trail
            audit_service.log_dpi_operation(
                organization_id=request["organization_id"],
                username=approved_by,
                action="dpi_policy_approved",
                details=f"approval_id: {approval_id}; reason: {approval_reason}; effective_hours: {effective_hours}",
            )
            
            logger.info(f"DPI policy approved: {approval_id} by {approved_by}")
            
            return {
                "approval_id": approval_id,
                "status": "approved",
                "effective_from": effective_from.isoformat(),
                "expires_at": expires_at.isoformat(),
                "message": "Policy approved and activated"
            }
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to approve DPI policy: {e}")
            raise
        finally:
            cursor.close()
            
    def reject_policy(
        self,
        db_conn,
        *,
        approval_id: str,
        rejected_by: str,
        rejection_reason: str
    ) -> Dict:
        """Reject a DPI policy request."""
        cursor = db_conn.cursor()
        try:
            # Get the approval request
            cursor.execute("""
                SELECT * FROM dpi_policy_approvals 
                WHERE approval_id = %s AND approval_status = 'pending'
            """, (approval_id,))
            
            request = cursor.fetchone()
            if not request:
                raise ValueError(f"Approval request {approval_id} not found or already processed")
                
            # Update approval
            cursor.execute("""
                UPDATE dpi_policy_approvals 
                SET approval_status = 'rejected',
                    approved_by = %s,
                    rejection_reason = %s,
                    reviewed_at = NOW()
                WHERE approval_id = %s
            """, (rejected_by, rejection_reason, approval_id))
            
            db_conn.commit()
            
            # Log audit trail
            audit_service.log_dpi_operation(
                organization_id=request["organization_id"],
                username=rejected_by,
                action="dpi_policy_rejected",
                details=f"approval_id: {approval_id}; reason: {rejection_reason}",
            )
            
            logger.info(f"DPI policy rejected: {approval_id} by {rejected_by}")
            
            return {
                "approval_id": approval_id,
                "status": "rejected",
                "message": "Policy request rejected"
            }
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to reject DPI policy: {e}")
            raise
        finally:
            cursor.close()
            
    def get_active_policy(
        self,
        db_conn,
        *,
        organization_id: str,
        policy_type: str
    ) -> Optional[Dict]:
        """Get currently active DPI policy."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT * FROM dpi_policy_approvals 
                WHERE organization_id = %s 
                    AND policy_type = %s 
                    AND approval_status = 'approved'
                    AND effective_from <= NOW()
                    AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY effective_from DESC 
                LIMIT 1
            """, (organization_id, policy_type))
            
            return cursor.fetchone()
        finally:
            cursor.close()
            
    def record_operation(
        self,
        db_conn,
        *,
        organization_id: str,
        agent_id: Optional[str],
        operation_type: str,
        operation_details: Dict,
        policy_approval_id: Optional[str] = None,
        user_context: Optional[Dict] = None,
        source_ip: Optional[str] = None
    ) -> str:
        """Record DPI operation in audit trail."""
        audit_id = str(uuid.uuid4())
        cursor = db_conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO dpi_operation_audit (
                    audit_id, organization_id, agent_id, operation_type,
                    operation_details, policy_approval_id, user_context,
                    source_ip, operation_start
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                audit_id, organization_id, agent_id, operation_type,
                json.dumps(operation_details), policy_approval_id,
                json.dumps(user_context) if user_context else None,
                source_ip
            ))
            
            db_conn.commit()
            return audit_id
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to record DPI operation: {e}")
            raise
        finally:
            cursor.close()
            
    def complete_operation(
        self,
        db_conn,
        *,
        audit_id: str,
        operation_status: str,
        bytes_inspected: int = 0,
        domains_analyzed: int = 0,
        threats_detected: int = 0,
        error_message: Optional[str] = None
    ) -> bool:
        """Complete DPI operation audit record."""
        cursor = db_conn.cursor()
        try:
            cursor.execute("""
                UPDATE dpi_operation_audit 
                SET operation_status = %s,
                    operation_end = NOW(),
                    bytes_inspected = %s,
                    domains_analyzed = %s,
                    threats_detected = %s,
                    error_message = %s
                WHERE audit_id = %s
            """, (
                operation_status, bytes_inspected, domains_analyzed,
                threats_detected, error_message, audit_id
            ))
            
            db_conn.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to complete DPI operation: {e}")
            return False
        finally:
            cursor.close()
            
    def get_pending_approvals(self, db_conn, organization_id: str) -> List[Dict]:
        """Get pending DPI policy approvals."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT * FROM dpi_policy_approvals 
                WHERE organization_id = %s AND approval_status = 'pending'
                ORDER BY requested_at DESC
            """, (organization_id,))
            
            return cursor.fetchall()
        finally:
            cursor.close()
            
    def get_operation_audit(
        self,
        db_conn,
        *,
        organization_id: str,
        agent_id: Optional[str] = None,
        operation_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get DPI operation audit records."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            query = """
                SELECT * FROM dpi_operation_audit 
                WHERE organization_id = %s
            """
            params = [organization_id]
            
            if agent_id:
                query += " AND agent_id = %s"
                params.append(agent_id)
                
            if operation_type:
                query += " AND operation_type = %s"
                params.append(operation_type)
                
            query += " ORDER BY operation_start DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            return cursor.fetchall()
        finally:
            cursor.close()
            
    def set_safe_default(
        self,
        db_conn,
        *,
        organization_id: str,
        policy_type: str,
        safe_config: Dict,
        is_mandatory: bool = False
    ) -> str:
        """Set safe default configuration for DPI policy."""
        default_id = str(uuid.uuid4())
        cursor = db_conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO dpi_safe_defaults 
                (default_id, organization_id, policy_type, safe_config, is_mandatory)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                safe_config = VALUES(safe_config),
                is_mandatory = VALUES(is_mandatory),
                updated_at = NOW()
            """, (
                default_id, organization_id, policy_type,
                json.dumps(safe_config), is_mandatory
            ))
            
            db_conn.commit()
            
            logger.info(f"Safe default set for DPI policy: {policy_type} in org {organization_id}")
            return default_id
            
        except Exception as e:
            db_conn.rollback()
            logger.error(f"Failed to set DPI safe default: {e}")
            raise
        finally:
            cursor.close()
            
    def get_safe_defaults(self, db_conn, organization_id: str) -> Dict[str, Dict]:
        """Get safe defaults for all DPI policies."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT policy_type, safe_config, is_mandatory 
                FROM dpi_safe_defaults 
                WHERE organization_id = %s
            """, (organization_id,))
            
            return {row["policy_type"]: {
                "config": row["safe_config"],
                "is_mandatory": row["is_mandatory"]
            } for row in cursor.fetchall()}
        finally:
            cursor.close()


# Global instance
dpi_governance_service = DPIGovernanceService()
