from typing import Optional
from fastapi import APIRouter, Depends

from ..core.dependencies import get_current_user, require_org_admin
from ..db.session import get_db, get_db_connection
from ..services.dashboard_service import dashboard_service
from ..services.live_telemetry_store import live_telemetry_store

router = APIRouter()


@router.get("/overview")
def get_dashboard_overview(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    return live_telemetry_store.get_overview_stats(organization_id=org_id, db_conn=conn)


@router.get("/activity")
def get_dashboard_activity(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
    limit: int = 50,
):
    org_id = current_user.get("organization_id")
    return dashboard_service.get_recent_activity(conn, organization_id=org_id, limit=limit)


@router.get("/traffic-history")
def get_traffic_history(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
    hours: int = 24,
    resolution: str = "hour",
    window: Optional[int] = None,
):
    org_id = current_user.get("organization_id")
    return dashboard_service.get_traffic_history(
        conn,
        hours=hours,
        resolution=resolution,
        window=window,
        organization_id=org_id,
    )


@router.get("/device-stats")
def get_device_stats(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
    limit: int = 5
):
    org_id = current_user.get("organization_id")
    return dashboard_service.get_device_activity_stats(conn, limit=limit, organization_id=org_id)


@router.get("/bundle")
def get_dashboard_bundle(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
    limit: int = 50,
):
    org_id = current_user.get("organization_id")
    from ..services.device_service import device_service
    from ..services.application_service import application_service

    overview = live_telemetry_store.get_overview_stats(organization_id=org_id, db_conn=conn)
    activity = dashboard_service.get_recent_activity(conn, organization_id=org_id, limit=limit)
    alerts = live_telemetry_store.get_recent_alerts(organization_id=org_id, limit=12)
    devices = device_service.get_devices(conn, organization_id=org_id, include_observed=False)[:10]
    apps = application_service.get_application_summary(conn, organization_id=org_id)[:10]
    traffic = dashboard_service.get_traffic_history(conn, hours=24, resolution="hour", organization_id=org_id)

    return {
        "overview": overview,
        "activity": activity,
        "alerts": alerts,
        "devices": devices,
        "apps": apps,
        "traffic_history": traffic,
    }
