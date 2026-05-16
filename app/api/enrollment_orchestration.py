"""
API endpoints for enrollment orchestration and visibility.
"""

from datetime import datetime, timezone
from typing import List, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..services.enrollment_orchestration_service import enrollment_orchestration_service

router = APIRouter()


@router.get("/summary", response_model=Dict)
async def get_enrollment_summary(
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Get comprehensive enrollment status summary."""
    conn = get_db_connection()
    try:
        enrollment_orchestration_service.ensure_schema(conn)
        return enrollment_orchestration_service.get_enrollment_summary(conn, organization_id=org_id)
    finally:
        conn.close()


@router.get("/pending-retries", response_model=List[Dict])
async def get_pending_retries(
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Get agents scheduled for retry."""
    conn = get_db_connection()
    try:
        enrollment_orchestration_service.ensure_schema(conn)
        return enrollment_orchestration_service.get_pending_retries(conn, organization_id=org_id)
    finally:
        conn.close()


@router.post("/{agent_id}/trigger-retry")
async def trigger_enrollment_retry(
    agent_id: str,
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Manually trigger enrollment retry for an agent."""
    conn = get_db_connection()
    try:
        enrollment_orchestration_service.ensure_schema(conn)
        
        # Check if agent exists and is in retryable state
        state = enrollment_orchestration_service.get_enrollment_state(conn, agent_id=agent_id)
        if not state:
            raise HTTPException(status_code=404, detail="Agent enrollment state not found")
            
        if state["current_state"] not in ["failed", "error", "permanently_failed"]:
            raise HTTPException(
                status_code=400, 
                detail=f"Agent {agent_id} is not in a retryable state. Current state: {state['current_state']}"
            )
        
        success = enrollment_orchestration_service.schedule_retry(
            conn, 
            agent_id=agent_id, 
            retry_delay_seconds=5  # Immediate retry for manual trigger
        )
        
        if not success:
            raise HTTPException(
                status_code=429, 
                detail="Agent has exceeded maximum retry limit"
            )
            
        return {"message": f"Retry scheduled for agent {agent_id}"}
        
    finally:
        conn.close()


@router.post("/{agent_id}/reset-state")
async def reset_enrollment_state(
    agent_id: str,
    current_user: dict = Depends(require_org_admin),
    org_id: str = Query(..., description="Organization ID")
):
    """Reset agent enrollment state for fresh enrollment attempt."""
    conn = get_db_connection()
    try:
        enrollment_orchestration_service.ensure_schema(conn)
        
        # Reset to initial state
        enrollment_orchestration_service.transition_state(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            new_state="initializing",
            event_data={"action": "manual_reset", "initiated_by": current_user.get("username")}
        )
        
        return {"message": f"Enrollment state reset for agent {agent_id}"}
        
    finally:
        conn.close()
