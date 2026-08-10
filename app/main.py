from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import socketio
import logging
import os

from .core.config import settings
from .api.router import api_router
from .realtime import (
    AUTHENTICATED_SOCKET_ROOM,
    SocketAuthenticationError,
    authenticate_socket_connection,
    configure_socket_server,
    socket_room_for_organization,
)
from .db.session import ensure_bootstrap_state, get_db_connection
from .services.agent_enrollment_service import agent_enrollment_service
from .services.application_service import application_service
from .middleware.request_context import RequestContextMiddleware
from .services.system_service import system_service
from .services.web_inspection_service import web_inspection_service
from .middleware.csrf_protection import CSRFProtectionMiddleware
from .middleware.transport_security import TransportSecurityMiddleware
from .middleware.mtls_middleware import MTLSMiddleware
from .middleware.prometheus_middleware import PrometheusMiddleware, metrics_endpoint_handler
from .middleware.chaos_middleware import ChaosMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware

def _resolve_log_level() -> int:
    configured = str(getattr(settings, "LOG_LEVEL", "INFO") or "INFO").upper()
    return getattr(logging, configured, logging.INFO)


# Logging configuration
logging.basicConfig(level=_resolve_log_level())
logging.getLogger("python_multipart").setLevel(logging.WARNING)
logging.getLogger("engineio").setLevel(logging.WARNING)
logging.getLogger("socketio").setLevel(logging.WARNING)
logger = logging.getLogger("netvisor")


def _allowed_origins() -> list[str]:
    raw = getattr(settings, "CORS_ORIGINS_RAW", "")
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["http://127.0.0.1:8000", "http://localhost:8000"]


def _validate_runtime_config() -> None:
    """Validate critical configuration settings on startup (Issue #11)."""
    if settings.ENVIRONMENT == "production" and not settings.ALLOW_LAN_HTTP:
        if not settings.AUTH_COOKIE_SECURE:
            raise RuntimeError(
                "NETVISOR_AUTH_COOKIE_SECURE must be enabled (True) in a production environment. "
                "Set NETVISOR_ENVIRONMENT=development or enable NETVISOR_ALLOW_LAN_HTTP=true for lab testing."
            )

    normalized_same_site = str(settings.AUTH_COOKIE_SAMESITE or "lax").lower()
    if normalized_same_site not in {"lax", "strict", "none"}:
        raise RuntimeError("NETVISOR_AUTH_COOKIE_SAMESITE must be one of: lax, strict, none.")
    if normalized_same_site == "none" and not settings.AUTH_COOKIE_SECURE:
        logger.warning("NETVISOR_AUTH_COOKIE_SAMESITE=none without NETVISOR_AUTH_COOKIE_SECURE=true may be rejected by browsers.")
    normalized_worker_mode = str(settings.FLOW_WORKER_MODE or "embedded").lower()
    if normalized_worker_mode not in {"embedded", "disabled", "external"}:
        raise RuntimeError("NETVISOR_FLOW_WORKER_MODE must be one of: embedded, disabled, external.")
    if len(settings.SECRET_KEY or "") < 16:
        raise RuntimeError("NETVISOR_SECRET_KEY must be set to a strong value before startup.")
    if len(settings.AGENT_MASTER_KEY or "") < 16:
        raise RuntimeError("NETVISOR_AGENT_MASTER_KEY must be set to a strong value before startup.")
    if len(settings.GATEWAY_MASTER_KEY or "") < 16:
        raise RuntimeError("NETVISOR_GATEWAY_MASTER_KEY must be set to a strong value before startup.")
    if len(settings.AGENT_API_KEY or "") < 16:
        raise RuntimeError("AGENT_API_KEY must be set to a strong value before startup.")
    if len(settings.GATEWAY_API_KEY or "") < 16:
        raise RuntimeError("GATEWAY_API_KEY must be set to a strong value before startup.")
    if settings.AGENT_API_KEY == settings.GATEWAY_API_KEY:
        logger.warning("AGENT_API_KEY and GATEWAY_API_KEY are identical. Use distinct secrets for collection roles.")
    if settings.AGENT_MASTER_KEY == settings.GATEWAY_MASTER_KEY:
        logger.warning(
            "NETVISOR_AGENT_MASTER_KEY and NETVISOR_GATEWAY_MASTER_KEY are identical. Use distinct signing roots."
        )
    if settings.ALLOW_LAN_HTTP:
        logger.warning(
            "NETVISOR_ALLOW_LAN_HTTP=true weakens transport security and should only be used in an isolated lab environment."
        )

    # Call config.py validate_config (Issue #11: Configuration Validation Gaps)
    validation_errors = settings.validate_config()
    if validation_errors:
        for err in validation_errors:
            logger.error("Configuration validation error: %s", err)
        raise RuntimeError("Configuration validation failed. See logs for details.")
    
    # Issue #11: Validate additional configuration settings
    config_errors = settings.validate_config()
    if config_errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {err}" for err in config_errors)
        raise RuntimeError(error_msg)
    
# Socket.IO setup
p_sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins=_allowed_origins(), cors_credentials=True)
configure_socket_server(p_sio)

from .services.flow_service import flow_service
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    logger.info("NetVisor Backend Starting Up...")
    _validate_runtime_config()
    ensure_bootstrap_state()
    startup_conn = None
    try:
        startup_conn = get_db_connection()
        agent_enrollment_service.ensure_schema(startup_conn)
        flow_service._ensure_flow_log_schema(startup_conn)
        application_service.ensure_schema(startup_conn)
        web_inspection_service.ensure_schema(startup_conn)
        if settings.RESET_RUNTIME_ON_STARTUP:
            runtime_result = system_service.prepare_clean_runtime(startup_conn, reason="startup")
            logger.info("Startup runtime reset complete: %s", runtime_result["message"])
        
        # Prime LiveTelemetryStore
        from .services.live_telemetry_store import live_telemetry_store
        live_telemetry_store.initialize_from_db(startup_conn)
    finally:
        if startup_conn:
            startup_conn.close()

    # Start BroadcastScheduler and EventDispatcher
    from .services.broadcast_scheduler import broadcast_scheduler
    from .services.event_dispatcher import event_dispatcher
    broadcast_scheduler.start()
    event_dispatcher.start()

    flow_writer_task = None
    correlation_task = None
    if str(settings.FLOW_WORKER_MODE or "embedded").lower() == "embedded":
        flow_writer_task = asyncio.create_task(flow_service.flow_writer_worker())
        logger.info("Embedded flow worker started.")
        
        try:
            from .services.correlation_worker import correlation_worker
            correlation_task = asyncio.create_task(correlation_worker.start())
            logger.info("Correlation worker started.")
        except Exception as e:
            logger.error("Failed to start correlation worker: %s", e)
    else:
        logger.info("Embedded flow worker disabled (mode=%s).", settings.FLOW_WORKER_MODE)
    yield
    # Shutdown logic
    logger.info("NetVisor Backend Shutting Down...")
    
    # Stop BroadcastScheduler and EventDispatcher
    broadcast_scheduler.stop()
    event_dispatcher.stop()

    # Export all database tables to db_dump unconditionally on shutdown
    shutdown_export_conn = None
    try:
        shutdown_export_conn = get_db_connection()
        system_service.export_all_tables_to_db_dump(shutdown_export_conn)
        logger.info("Shutdown full database export to db_dump complete.")
    except Exception as e:
        logger.error("Shutdown full database export failed: %s", e)
    finally:
        if shutdown_export_conn:
            shutdown_export_conn.close()

    shutdown_conn = None
    if settings.BACKUP_AND_RESET_ON_SHUTDOWN:
        try:
            shutdown_conn = get_db_connection()
            runtime_result = system_service.backup_and_reset_runtime_data(shutdown_conn, reason="shutdown")
            logger.info("Shutdown runtime backup/reset complete: %s", runtime_result["message"])
        finally:
            if shutdown_conn:
                shutdown_conn.close()

    for task in (flow_writer_task, correlation_task):
        if task:
            task.cancel()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Transport security middleware - enforces HTTPS for agent/gateway endpoints, with an explicit lab-only LAN HTTP override
app.add_middleware(TransportSecurityMiddleware)
app.add_middleware(MTLSMiddleware)
app.add_middleware(CSRFProtectionMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(PrometheusMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
if settings.CHAOS_ENABLED:
    app.add_middleware(ChaosMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

def redact_secrets_from_string(text: str) -> str:
    if not text:
        return ""
    import re
    # Fernet tokens: gAAAAA...
    fernet_pattern = r"\bgAAAAA[A-Za-z0-9_-]{30,}\b"
    # JWT tokens: eyJ...
    jwt_pattern = r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    # Basic auth / Bearer tokens or authorization headers: authorization: bearer ...
    auth_header_pattern = r"(?i)\b(authorization|session|cookie|token|password|secret|key|pwd)\b\s*[:=]\s*\"?[A-Za-z0-9_-]{6,}\b"
    
    text = re.sub(fernet_pattern, "[REDACTED_FERNET_TOKEN]", text)
    text = re.sub(jwt_pattern, "[REDACTED_JWT_TOKEN]", text)
    text = re.sub(auth_header_pattern, r"\1=[REDACTED]", text)
    
    # Redact common database password patterns, e.g. mysql://user:password@host
    db_conn_pattern = r"\b([a-zA-Z0-9+.-]+://[^:]+:)([^@]+)(@[^\s]+)\b"
    text = re.sub(db_conn_pattern, r"\1[REDACTED]\3", text)
    
    return text


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    exc_msg = f"Unhandled Exception: {exc}"
    tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    
    redacted_msg = redact_secrets_from_string(exc_msg)
    redacted_tb = redact_secrets_from_string(tb_str)
    
    logger.error("%s\n%s", redacted_msg, redacted_tb)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

@app.get("/ping")
async def ping():
    return {"status": "pong"}

@app.get("/metrics")
async def metrics(request: Request):
    return metrics_endpoint_handler(request)


@p_sio.event
async def connect(sid, environ, auth=None):
    try:
        socket_context = await asyncio.to_thread(authenticate_socket_connection, environ)
        await p_sio.save_session(
            sid,
            {
                "user_id": socket_context.get("user_id"),
                "organization_id": socket_context.get("organization_id"),
                "role": socket_context.get("role"),
            },
        )
        await p_sio.enter_room(sid, AUTHENTICATED_SOCKET_ROOM)
        org_room = socket_room_for_organization(socket_context.get("organization_id"))
        if org_room:
            await p_sio.enter_room(sid, org_room)
        logger.info(
            "Socket connected: %s user=%s org=%s",
            sid,
            socket_context.get("user_id"),
            socket_context.get("organization_id"),
        )
    except SocketAuthenticationError as exc:
        logger.warning("Rejected socket connection %s: %s", sid, exc)
        return False
    except Exception as exc:
        logger.error("Socket connection failed for %s: %s", sid, exc, exc_info=True)
        return False


@p_sio.event
async def disconnect(sid):
    logger.info("Socket disconnected: %s", sid)

# Static Files
frontend_assets_dir = "frontend/dist/assets"
if os.path.isdir(frontend_assets_dir):
    app.mount("/assets", StaticFiles(directory=frontend_assets_dir), name="assets")
else:
    logger.warning("Frontend assets directory not found: %s", frontend_assets_dir)

# Helper to serve React Index (Catch-All MUST be last, but before SocketIO wrap)
@app.get("/{full_path:path}")
async def serve_react_app(request: Request, full_path: str):
    if full_path.startswith("api") or full_path.startswith("socket.io"):
        return JSONResponse(status_code=404, content={"status": "error", "message": "Not Found"})

    if os.path.exists("frontend/dist/index.html"):
        return FileResponse("frontend/dist/index.html")
    return {"status": "error", "message": "Frontend build not found. Run 'npm run build'."}

# Wrap with Socket.IO
app = socketio.ASGIApp(p_sio, app, socketio_path='socket.io')
