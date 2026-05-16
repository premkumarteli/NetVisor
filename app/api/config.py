from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..db.session import get_db_connection
from ..services.config_service import config_service
from .agents import validate_agent_key, _require_authenticated_agent_id

import logging

logger = logging.getLogger("netvisor.api.config")
router = APIRouter()

@router.get("/config")
async def get_agent_config(
    request: Request,
    auth_context: dict = Depends(validate_agent_key)
):
    """
    Endpoint for agents and gateways to pull their dynamic configuration.
    """
    conn = get_db_connection()
    try:
        agent_id = _require_authenticated_agent_id(auth_context, claimed_agent_id=None, source="config_sync")
        org_id = auth_context.get("organization_id")
        
        config = config_service.get_agent_config(conn, agent_id, str(org_id))
        return JSONResponse(status_code=200, content={"status": "success", "config": config})
    finally:
        conn.close()

@router.put("/admin/agents/{agent_id}/config")
async def update_agent_config(
    agent_id: str,
    request: Request
):
    """
    Admin endpoint to update configuration for a specific agent.
    Requires admin authentication (simplified here).
    """
    # TODO: Add proper admin auth check here
    body = await request.json()
    conn = get_db_connection()
    try:
        org_id = body.get("organization_id", "default-org-id")
        config_service.update_agent_config(conn, agent_id, org_id, body.get("config", {}))
        conn.commit()
        return JSONResponse(status_code=200, content={"status": "success", "message": "Config updated"})
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to update config for {agent_id}: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Internal server error"})
    finally:
        conn.close()
