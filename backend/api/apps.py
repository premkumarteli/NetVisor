from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..core.dependencies import require_org_admin
from ..db.session import get_db
from ..services.application_service import application_service

router = APIRouter()


class AppOverrideRequest(BaseModel):
    domain: str = Field(..., description="Domain or hostname to override (e.g. 'custom-app.internal.net')")
    application_name: str = Field(..., description="Human-readable application name (e.g. 'Inventory Manager')")
    category: str = Field(default="web", description="Category: 'ai', 'dev', 'chat', 'cloud', 'security', 'web', 'streaming', 'infra'")


@router.get("/summary")
def get_apps_summary(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    return application_service.get_application_summary(conn, organization_id=org_id)


@router.get("/overrides")
def list_app_overrides(
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    return application_service.get_admin_overrides(conn, organization_id=org_id)


@router.post("/overrides", status_code=status.HTTP_201_CREATED)
def create_or_update_app_override(
    payload: AppOverrideRequest,
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    try:
        return application_service.set_admin_override(
            conn,
            domain=payload.domain,
            app_name=payload.application_name,
            category=payload.category,
            organization_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.delete("/overrides/{domain}")
def delete_app_override(
    domain: str,
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    decoded_domain = unquote(domain)
    deleted = application_service.delete_admin_override(
        conn,
        domain=decoded_domain,
        organization_id=org_id,
    )
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Override not found")
    return {"status": "success", "message": f"Override for '{decoded_domain}' removed."}


@router.get("/{app_name}/devices")
def get_app_devices(
    app_name: str,
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    decoded_name = unquote(app_name)
    return {
        "application": decoded_name,
        "devices": application_service.get_application_devices(
            conn,
            app_name=decoded_name,
            organization_id=org_id,
        ),
    }


@router.get("/{app_name}/workspace")
def get_app_workspace(
    app_name: str,
    current_user: dict = Depends(require_org_admin),
    conn = Depends(get_db),
):
    org_id = current_user.get("organization_id")
    decoded_name = unquote(app_name)
    return application_service.get_application_workspace(
        conn,
        app_name=decoded_name,
        organization_id=org_id,
    )


