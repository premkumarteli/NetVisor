from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..db.session import get_db_connection
from ..services.telemetry_service import telemetry_service
from .agents import validate_agent_key, _require_authenticated_agent_id

import logging

logger = logging.getLogger("netvisor.api.telemetry")
router = APIRouter()

@router.post("/telemetry/batch")
async def ingest_telemetry_batch(
    request: Request,
    auth_context: dict = Depends(validate_agent_key)
):
    """
    Endpoint for agents to push advanced telemetry logs.
    """
    conn = get_db_connection()
    try:
        agent_id = _require_authenticated_agent_id(auth_context, claimed_agent_id=None, source="telemetry_ingest")
        org_id = auth_context.get("organization_id")
        
        body = await request.json()
        logs = body.get("logs", [])
        
        ingested_count = telemetry_service.ingest_logs(conn, agent_id, str(org_id), logs)
        conn.commit()
        return JSONResponse(status_code=200, content={"status": "success", "ingested": ingested_count})
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to ingest telemetry from {auth_context.get('agent_id')}: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": "Failed to process telemetry logs"})
    finally:
        conn.close()

@router.get("/admin/agents/{agent_id}/telemetry")
async def get_agent_telemetry(
    agent_id: str,
    limit: int = 100
):
    """
    Admin endpoint to view telemetry logs for a specific agent.
    """
    # TODO: Add proper admin auth check here
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, log_level, category, message, metadata_json, timestamp 
            FROM telemetry_logs 
            WHERE agent_id = %s 
            ORDER BY timestamp DESC 
            LIMIT %s
            """,
            (agent_id, limit)
        )
        logs = cursor.fetchall()
        return JSONResponse(status_code=200, content={"status": "success", "logs": logs})
    finally:
        cursor.close()
        conn.close()
