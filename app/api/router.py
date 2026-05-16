from fastapi import APIRouter

from . import health, auth, devices, flows, alerts, agents, gateway, dashboard, system, apps, analytics, agent_monitoring, web_inspection, dpi, logs, enrollment_orchestration, observability, dpi_governance, config, telemetry

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(flows.router, prefix="/collect/flow", tags=["flows"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(agents.router, prefix="/collect", tags=["agents"])
api_router.include_router(agent_monitoring.router, prefix="/agents", tags=["agent-monitoring"])
api_router.include_router(gateway.router, prefix="/gateway", tags=["gateway"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(system.router, prefix="/system", tags=["system"])
api_router.include_router(apps.router, prefix="/apps", tags=["apps"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["analytics"])
api_router.include_router(web_inspection.router, prefix="/web", tags=["web-inspection"])
api_router.include_router(dpi.router, prefix="/dpi", tags=["dpi"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(enrollment_orchestration.router, prefix="/enrollment", tags=["enrollment-orchestration"])
api_router.include_router(observability.router, prefix="/observability", tags=["observability"])
api_router.include_router(dpi_governance.router, prefix="/dpi-governance", tags=["dpi-governance"])
api_router.include_router(config.router, tags=["config"])
api_router.include_router(telemetry.router, tags=["telemetry"])
