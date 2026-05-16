"""
API endpoints for DPI governance with admin approval and audit trail.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..services.dpi_governance_service import dpi_governance_service

router = APIRouter()


@router.post("/policy-approvals", response_model=Dict)
async def request_policy_approval(
    request_data: Dict = Body(...),
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Request approval for DPI policy configuration."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        result = dpi_governance_service.request_policy_approval(
            conn,
            organization_id=org_id,
            policy_type=request_data["policy_type"],
            policy_config=request_data["policy_config"],
            requested_by=current_user.get("username"),
            source_ip=current_user.get("source_ip")
        )
        
        return {
            "message": "Policy approval request submitted",
            "approval_id": result["approval_id"],
            "status": result["status"]
        }
        
    finally:
        conn.close()


@router.get("/policy-approvals", response_model=List[Dict])
async def get_pending_approvals(
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query("pending", description="Filter by status")
):
    """Get DPI policy approval requests."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        if status == "pending":
            return dpi_governance_service.get_pending_approvals(conn, organization_id=org_id)
        else:
            # Get all approvals with status filter
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT * FROM dpi_policy_approvals 
                    WHERE organization_id = %s AND approval_status = %s
                    ORDER BY requested_at DESC
                """, (org_id, status))
                return cursor.fetchall()
            finally:
                cursor.close()
                
    finally:
        conn.close()


@router.post("/policy-approvals/{approval_id}/approve", response_model=Dict)
async def approve_policy_request(
    approval_id: str,
    approval_data: Dict = Body(...),
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Approve a DPI policy request."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        result = dpi_governance_service.approve_policy(
            conn,
            approval_id=approval_id,
            approved_by=current_user.get("username"),
            approval_reason=approval_data["approval_reason"],
            effective_hours=approval_data.get("effective_hours", 24)
        )
        
        return {
            "message": "Policy approved and activated",
            "approval_id": result["approval_id"],
            "status": result["status"],
            "effective_from": result.get("effective_from"),
            "expires_at": result.get("expires_at")
        }
        
    finally:
        conn.close()


@router.post("/policy-approvals/{approval_id}/reject", response_model=Dict)
async def reject_policy_request(
    approval_id: str,
    rejection_data: Dict = Body(...),
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Reject a DPI policy request."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        result = dpi_governance_service.reject_policy(
            conn,
            approval_id=approval_id,
            rejected_by=current_user.get("username"),
            rejection_reason=rejection_data["rejection_reason"]
        )
        
        return {
            "message": "Policy request rejected",
            "approval_id": result["approval_id"],
            "status": result["status"]
        }
        
    finally:
        conn.close()


@router.get("/active-policies", response_model=Dict)
async def get_active_policies(
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID"),
    policy_type: Optional[str] = Query(None, description="Filter by policy type")
):
    """Get currently active DPI policies."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        if policy_type:
            active_policy = dpi_governance_service.get_active_policy(
                conn, organization_id=org_id, policy_type=policy_type
            )
            return {"policy": active_policy}
        else:
            # Return all active policies
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT * FROM dpi_policy_approvals 
                    WHERE organization_id = %s 
                        AND approval_status = 'approved'
                        AND effective_from <= NOW()
                        AND (expires_at IS NULL OR expires_at > NOW())
                    ORDER BY policy_type
                """, (org_id,))
                policies = cursor.fetchall()
                return {"policies": policies}
            finally:
                cursor.close()
                
    finally:
        conn.close()


@router.post("/safe-defaults", response_model=Dict)
async def set_safe_default(
    default_data: Dict = Body(...),
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Set safe default configuration for DPI policy."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        default_id = dpi_governance_service.set_safe_default(
            conn,
            organization_id=org_id,
            policy_type=default_data["policy_type"],
            safe_config=default_data["safe_config"],
            is_mandatory=default_data.get("is_mandatory", False)
        )
        
        return {
            "message": "Safe default configuration set",
            "default_id": default_id
        }
        
    finally:
        conn.close()


@router.get("/safe-defaults", response_model=Dict)
async def get_safe_defaults(
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Get safe defaults for DPI policies."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        defaults = dpi_governance_service.get_safe_defaults(conn, organization_id=org_id)
        return {"defaults": defaults}
        
    finally:
        conn.close()


@router.get("/audit-logs", response_model=List[Dict])
async def get_audit_logs(
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    operation_type: Optional[str] = Query(None, description="Filter by operation type"),
    limit: int = Query(100, description="Maximum number of records to return")
):
    """Get DPI operation audit logs."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        return dpi_governance_service.get_operation_audit(
            conn,
            organization_id=org_id,
            agent_id=agent_id,
            operation_type=operation_type,
            limit=limit
        )
        
    finally:
        conn.close()


@router.post("/operations/{audit_id}/complete", response_model=Dict)
async def complete_operation(
    audit_id: str,
    completion_data: Dict = Body(...),
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Complete DPI operation audit record."""
    conn = get_db_connection()
    try:
        dpi_governance_service.ensure_schema(conn)
        
        success = dpi_governance_service.complete_operation(
            conn,
            audit_id=audit_id,
            operation_status=completion_data["operation_status"],
            bytes_inspected=completion_data.get("bytes_inspected", 0),
            domains_analyzed=completion_data.get("domains_analyzed", 0),
            threats_detected=completion_data.get("threats_detected", 0),
            error_message=completion_data.get("error_message")
        )
        
        return {
            "message": "Operation audit record completed",
            "audit_id": audit_id,
            "success": success
        }
        
    finally:
        conn.close()
