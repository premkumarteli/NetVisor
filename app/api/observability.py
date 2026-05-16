"""
API endpoints for enhanced operational observability.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Query
from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..services.observability_service import observability_service

router = APIRouter()


@router.get("/startup-summary", response_model=Dict)
async def get_startup_summary(
    current_user: dict = Depends(require_org_admin)
):
    """Get comprehensive startup timing summary."""
    return observability_service.get_startup_summary()


@router.get("/health-summary", response_model=Dict)
async def get_health_summary(
    current_user: dict = Depends(require_org_admin)
):
    """Get comprehensive health check summary."""
    return observability_service.get_health_summary()


@router.get("/performance-summary", response_model=Dict)
async def get_performance_summary(
    current_user: dict = Depends(require_org_admin),
    component: Optional[str] = Query(None, description="Filter by component name")
):
    """Get performance metrics summary with trends."""
    return observability_service.get_performance_summary()


@router.get("/component-status", response_model=Dict)
async def get_component_status(
    current_user: dict = Depends(require_org_admin),
    component: Optional[str] = Query(None, description="Filter by component name")
):
    """Get current component operational status."""
    return observability_service.get_component_status()


@router.post("/record-health-check")
async def record_health_check(
    current_user: dict = Depends(require_org_admin),
    check_data: Dict = Body(...),
):
    """Record a health check result (for automated checks)."""
    observability_service.record_health_check(
        component=check_data["component"],
        check_type=check_data["check_type"],
        status=check_data["status"],
        details=check_data.get("details"),
        duration_ms=check_data.get("duration_ms"),
    )
    
    return {"message": "Health check recorded"}


@router.post("/record-performance-metric")
async def record_performance_metric(
    current_user: dict = Depends(require_org_admin),
    metric_data: Dict = Body(...),
):
    """Record a performance metric."""
    observability_service.record_performance_metric(
        component=metric_data["component"],
        metric_name=metric_data["metric_name"],
        value=metric_data["value"],
        unit=metric_data.get("unit"),
        labels=metric_data.get("labels"),
    )
    
    return {"message": "Performance metric recorded"}
