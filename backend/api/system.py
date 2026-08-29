from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel

from ..core.config import settings
from ..core.dependencies import require_org_admin, require_super_admin, request_rate_limit, admin_required
from ..db.session import get_db
from ..services.alert_service import alert_service
from ..services.release_service import release_service
from ..services.system_service import system_service

router = APIRouter()

admin_mutation_rate_limit = request_rate_limit(
    limit=settings.ADMIN_MUTATION_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="admin_mutation",
)


def _resolve_source_ip(request: Request) -> str | None:
    from ..utils.network import resolve_source_ip
    ip = resolve_source_ip(request)
    return None if ip == "unknown" else ip



class ToggleRequest(BaseModel):
    active: bool


@router.get("/admin-stats")
def get_admin_stats(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    return system_service.get_admin_stats(conn)


@router.get("/status")
def get_system_status(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    runtime = system_service.get_runtime_status(conn)
    return {
        "active": runtime["active"],
        "maintenance_mode": runtime["maintenance_mode"],
        "runtime": runtime,
        "release": release_service.snapshot(),
        "backup": system_service.latest_backup_status(),
        "backup_retention": system_service.backup_retention_status(),
    }


@router.get("/release")
def get_release_status(current_user: dict = Depends(require_org_admin)):
    return {
        "release": release_service.snapshot(),
        "backup": system_service.latest_backup_status(),
        "backup_retention": system_service.backup_retention_status(),
    }


@router.get("/logs")
def get_system_logs(
    current_user: dict = Depends(require_org_admin),
    limit: int = 20,
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    recent_alerts = alert_service.get_alerts(conn, organization_id=org_id, limit=limit * 2)
    vpn_alerts = [
        alert
        for alert in recent_alerts
        if (alert.get("breakdown", {}).get("vpn_score", 0) or 0) > 0.3
        or "Possible VPN/Proxy Usage" in alert.get("breakdown", {}).get("reasons", [])
    ][:limit]
    return {
        "admin": system_service.list_logs(conn, organization_id=org_id, limit=limit),
        "vpn": vpn_alerts,
    }


@router.post("/settings/maintenance")
def set_maintenance_mode(
    payload: ToggleRequest,
    request: Request,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    ip = _resolve_source_ip(request)
    return system_service.set_maintenance(
        conn,
        active=payload.active,
        username=current_user.get("username", "admin"),
        organization_id=current_user.get("organization_id"),
        ip_address=ip,
    )


@router.post("/settings/monitoring")
def set_monitoring_state(
    payload: ToggleRequest,
    request: Request,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    ip = _resolve_source_ip(request)
    return system_service.set_monitoring(
        conn,
        active=payload.active,
        username=current_user.get("username", "admin"),
        organization_id=current_user.get("organization_id"),
        ip_address=ip,
    )


@router.post("/actions/scan")
def trigger_scan(
    request: Request,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    ip = _resolve_source_ip(request)
    return system_service.trigger_scan(
        conn,
        username=current_user.get("username", "admin"),
        organization_id=current_user.get("organization_id"),
        ip_address=ip,
    )


class ResetTenantPayload(BaseModel):
    confirm_org_id: str


class ResetPlatformPayload(BaseModel):
    confirm_platform_reset: str


@router.post("/settings/reset-tenant-data")
def reset_tenant_data(
    payload: ResetTenantPayload,
    request: Request,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    if not org_id or payload.confirm_org_id != org_id:
        raise HTTPException(
            status_code=400,
            detail="Confirmation organization ID does not match your authenticated organization ID."
        )

    ip = _resolve_source_ip(request)
    return system_service.reset_operational_data(
        conn,
        username=current_user.get("username", "admin"),
        organization_id=org_id,
        ip_address=ip,
    )


@router.post("/settings/reset-platform")
def reset_platform_data(
    payload: ResetPlatformPayload,
    request: Request,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_super_admin),
    conn = Depends(get_db),
):
    if payload.confirm_platform_reset != "RESET":
        raise HTTPException(
            status_code=400,
            detail="Confirmation token must be exactly 'RESET' to wipe the platform."
        )

    ip = _resolve_source_ip(request)
    return system_service.reset_operational_data(
        conn,
        username=current_user.get("username", "admin"),
        organization_id=None,
        ip_address=ip,
    )


@router.post("/reset-data")
def reset_data(
    request: Request,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(admin_required),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id") if current_user.get("role") == "org_admin" else None
    ip = _resolve_source_ip(request)
    return system_service.reset_operational_data(
        conn,
        username=current_user.get("username", "admin"),
        organization_id=org_id,
        ip_address=ip,
    )
