from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..schemas.agent_schema import AgentDetails, AgentSummary, EnrollmentRequestSummary, EnrollmentReviewRequest
from ..services.agent_enrollment_service import agent_enrollment_service
from ..services.agent_auth_service import agent_auth_service
from ..services.audit_service import audit_service
from ..services.agent_service import agent_service

router = APIRouter()


def _resolve_source_ip(request: Request) -> str | None:
    forwarded_for = str(request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or None
    real_ip = str(request.headers.get("X-Real-IP") or "").strip()
    if real_ip:
        return real_ip
    return request.client.host if request.client else None


@router.get("/", response_model=List[AgentSummary])
async def list_agents(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return agent_service.get_agents(conn, organization_id=org_id)
    finally:
        conn.close()


@router.get("/enrollment-requests", response_model=List[EnrollmentRequestSummary])
async def list_enrollment_requests(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return agent_enrollment_service.list_requests(conn, organization_id=org_id)
    finally:
        conn.close()


@router.post("/enrollment-requests/{request_id}/approve", response_model=EnrollmentRequestSummary)
async def approve_enrollment_request(
    request_id: str,
    payload: EnrollmentReviewRequest,
    request: Request,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        try:
            request_row = agent_enrollment_service.approve_request(
                conn,
                request_id=request_id,
                reviewed_by=str(current_user.get("username") or "system"),
                review_reason=payload.review_reason,
                organization_id=org_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        
        source_ip = _resolve_source_ip(request)
        audit_service.log_agent_registration(
            organization_id=str(org_id),
            username=str(current_user.get("username") or "system"),
            agent_id=request_row["agent_id"],
            action="agent_enrollment_approved",
            details=f"request_id: {request_id}; reason: {payload.review_reason}",
            ip_address=source_ip,
        )
        return request_row
    finally:
        conn.close()


@router.post("/enrollment-requests/{request_id}/reject", response_model=EnrollmentRequestSummary)
async def reject_enrollment_request(
    request_id: str,
    payload: EnrollmentReviewRequest,
    request: Request,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        try:
            request_row = agent_enrollment_service.reject_request(
                conn,
                request_id=request_id,
                reviewed_by=str(current_user.get("username") or "system"),
                review_reason=payload.review_reason,
                organization_id=org_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        
        source_ip = _resolve_source_ip(request)
        audit_service.log_agent_registration(
            organization_id=str(org_id),
            username=str(current_user.get("username") or "system"),
            agent_id=request_row["agent_id"],
            action="agent_enrollment_rejected",
            details=f"request_id: {request_id}; reason: {payload.review_reason}",
            ip_address=source_ip,
        )
        return request_row
    finally:
        conn.close()


@router.post("/{agent_id}/revoke", response_model=EnrollmentRequestSummary)
async def revoke_agent_enrollment(
    agent_id: str,
    payload: EnrollmentReviewRequest,
    request: Request,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        request_row = agent_enrollment_service.get_request_by_agent_id(conn, agent_id=agent_id, organization_id=org_id)
        if not request_row:
            raise HTTPException(status_code=404, detail="Enrollment request not found")

        revoked_credentials = agent_auth_service.revoke_credential(conn, agent_id=agent_id)
        try:
            request_row = agent_enrollment_service.revoke_request(
                conn,
                agent_id=agent_id,
                reviewed_by=str(current_user.get("username") or "system"),
                review_reason=payload.review_reason,
                organization_id=org_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        conn.commit()
        
        source_ip = _resolve_source_ip(request)
        audit_service.log_agent_registration(
            organization_id=str(org_id),
            username=str(current_user.get("username") or "system"),
            agent_id=agent_id,
            action="agent_enrollment_revoked",
            details=f"review_reason: {payload.review_reason}; credentials_revoked: {revoked_credentials}",
            ip_address=source_ip,
        )
        return request_row
    finally:
        conn.close()


@router.get("/{agent_id}", response_model=AgentDetails)
async def get_agent_details(
    agent_id: str,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        details = agent_service.get_agent_details(conn, agent_id, organization_id=org_id)
        if not details:
            raise HTTPException(status_code=404, detail="Agent not found")
        return details
    finally:
        conn.close()
