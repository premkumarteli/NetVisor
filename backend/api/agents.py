from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status, Body, Query
from fastapi.responses import JSONResponse

from ..core.config import settings
from ..core.dependencies import request_rate_limit
from ..db.session import get_db_connection
from ..services.agent_service import agent_service
from ..services.agent_enrollment_service import agent_enrollment_service
from ..services.agent_auth_service import agent_auth_service, AgentAuthenticationError
from ..services.audit_service import audit_service
from ..services.device_service import device_service
from ..services.managed_device_service import managed_device_service
from ..services.metrics_service import metrics_service
from ..services.web_inspection_service import web_inspection_service
from ..schemas.user_schema import GenericResponse
from .dpi import dpi_event_emitter
from security import REENROLL_REQUEST_HEADER

import asyncio
import hmac
import logging
import mysql.connector


logger = logging.getLogger("netvisor.api.agents")
router = APIRouter()

agent_bootstrap_rate_limit = request_rate_limit(
    limit=settings.AGENT_BOOTSTRAP_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="agent_bootstrap",
    key_builder=lambda request: (
        f"{request.headers.get('X-Agent-Id') or (request.client.host if request.client else 'unknown')}:reenroll"
        if request.headers.get(REENROLL_REQUEST_HEADER) == "1"
        else request.headers.get("X-Agent-Id") or (request.client.host if request.client else "unknown")
    ),
)
agent_control_rate_limit = request_rate_limit(
    limit=settings.AGENT_CONTROL_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="agent_control",
    key_builder=lambda request: request.headers.get("X-Agent-Id") or (request.client.host if request.client else "unknown"),
)


def _collect_response(
    *,
    auth_context: dict | None = None,
    auth_mode: str | None = None,
    agent_id: str | None = None,
    key_version: int | None = None,
    **payload,
) -> dict:
    response = {
        "status": "success",
        "server_time": datetime.now(timezone.utc).isoformat(),
        "backend_tls_pins": agent_auth_service.transport_pins(),
    }
    effective_mode = auth_mode or str((auth_context or {}).get("auth_mode") or "").strip()
    effective_agent_id = agent_id or str((auth_context or {}).get("agent_id") or "").strip() or None
    effective_key_version = key_version if key_version is not None else (auth_context or {}).get("key_version")
    if effective_mode:
        response["agent_auth"] = {
            "mode": effective_mode,
            "agent_id": effective_agent_id,
            "key_version": effective_key_version,
        }
    response.update(payload)
    return response


async def validate_agent_bootstrap_key(request: Request):
    key = str(request.headers.get("X-API-Key") or "")
    if not hmac.compare_digest(key, settings.AGENT_API_KEY):
        metrics_service.increment("agent_bootstrap_auth_failures_total")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized Agent Key")
    metrics_service.increment("agent_bootstrap_auth_success_total")
    return True


async def validate_agent_key(request: Request):
    from starlette.requests import ClientDisconnect
    try:
        body = await request.body()
    except ClientDisconnect:
        raise HTTPException(status_code=400, detail="Client disconnected")

    def _authenticate():
        conn = get_db_connection()
        try:
            context = agent_auth_service.authenticate_request(conn, request, body)
            conn.commit()
            return context
        except AgentAuthenticationError:
            conn.rollback()
            raise
        finally:
            conn.close()

    try:
        import anyio
        return await anyio.to_thread.run_sync(_authenticate)
    except AgentAuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


def _require_authenticated_agent_id(auth_context: dict, claimed_agent_id: str | None, *, source: str) -> str:
    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    claimed = str(claimed_agent_id or "").strip()
    if not claimed:
        raise HTTPException(status_code=400, detail=f"agent_id is required in {source}")

    if authenticated_agent_id != claimed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent ID mismatch: authenticated agent ID does not match {source} agent ID",
        )

    return authenticated_agent_id


def _require_signed_agent_auth(auth_context: dict) -> None:
    if str(auth_context.get("auth_mode") or "") != "signed":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signed agent authentication is required for this operation.",
        )


def _resolve_org_id(cursor, requested_org_id: str | None) -> str | None:
    if requested_org_id and not settings.SINGLE_ORG_MODE:
        return requested_org_id

    cursor.execute("SELECT id FROM organizations LIMIT 1")
    org_row = cursor.fetchone()
    if org_row:
        return org_row["id"]

    return requested_org_id or settings.DEFAULT_ORGANIZATION_ID


def _resolve_source_ip(request: Request) -> str | None:
    from ..utils.network import resolve_source_ip
    ip = resolve_source_ip(request)
    return None if ip == "unknown" else ip


def _lookup_agent_organization_id(cursor, agent_id: str) -> str | None:
    cursor.execute(
        """
        SELECT organization_id
        FROM agents
        WHERE id = %s
        LIMIT 1
        """,
        (agent_id,),
    )
    row = cursor.fetchone()
    return row["organization_id"] if row else None


@router.post("/register")
async def register_agent(
    request: Request,
    reg: dict,
    _rate_limited: bool = Depends(agent_bootstrap_rate_limit),
    authorized: bool = Depends(validate_agent_bootstrap_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        metrics_service.increment("agent_registration_attempts_total")
        agent_id = str(reg.get("agent_id") or "").strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required")

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, reg.get("organization_id"))
        cursor.close()
        cursor = None

        logger.info("Registering agent %s for org %s", agent_id, org_id)

        source_ip = _resolve_source_ip(request)
        bootstrap_method = "reenroll" if bool(reg.get("reenroll")) else "bootstrap"
        enrollment_result = agent_enrollment_service.record_request(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            hostname=reg.get("hostname"),
            device_ip=reg.get("device_ip"),
            device_mac=reg.get("device_mac"),
            os_family=reg.get("os"),
            agent_version=reg.get("version"),
            bootstrap_method=bootstrap_method,
            source_ip=source_ip,
        )
        enrollment_request = enrollment_result["request"] or {}
        enrollment_status = str(enrollment_request.get("status") or "pending_review")
        pending_retry_seconds = max(int(settings.AGENT_ENROLLMENT_RETRY_SECONDS), 1)
        if enrollment_result.get("status_changed") and enrollment_status == "pending_review":
            audit_service.log_agent_registration(
                organization_id=str(org_id),
                username="system",
                agent_id=agent_id,
                action="agent_enrollment_requested",
                details=(
                    f"request_id: {enrollment_request.get('request_id')}; "
                    f"bootstrap_method: {bootstrap_method}; "
                    f"source_ip: {source_ip or 'unknown'}; "
                    f"hostname: {reg.get('hostname') or 'Unknown'}; "
                    f"device_ip: {reg.get('device_ip') or '-'}; "
                    f"device_mac: {reg.get('device_mac') or '-'}"
                ),
                ip_address=source_ip,
            )

        existing_credential = agent_auth_service.get_active_credential(conn, agent_id=agent_id)
        force_reenroll = bool(reg.get("reenroll"))
        credential = None

        response = _collect_response(
            auth_mode="bootstrap",
            agent_id=agent_id,
            organization_id=org_id,
            enrollment_status=enrollment_status,
            enrollment_request_id=enrollment_request.get("request_id"),
            enrollment_attempt_count=int(enrollment_request.get("attempt_count") or 0),
            enrollment_next_retry_seconds=pending_retry_seconds,
        )

        if enrollment_status != "approved":
            response["message"] = "Enrollment pending Fleet approval."
            response["agent_credentials"] = None
            return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=response)

        if existing_credential and force_reenroll:
            credential = agent_auth_service.rotate_credential(conn, agent_id=agent_id)
            metrics_service.increment("agent_registration_reenrollments_total")
        elif not existing_credential:
            credential = agent_auth_service.issue_initial_credential(conn, agent_id=agent_id)
            metrics_service.increment("agent_registration_initial_enrollments_total")
        else:
            metrics_service.increment("agent_registration_reregistrations_total")

        if credential:
            agent_enrollment_service.mark_credential_issued(
                conn,
                agent_id=agent_id,
                issued_at=credential.issued_at,
            )

        agent_service.upsert_agent(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            api_key=None,
            hostname=reg.get("hostname"),
            ip_address=reg.get("device_ip"),
            os_family=reg.get("os"),
            version=reg.get("version"),
            inspection_state=reg.get("web_inspection"),
            cpu_usage=float(reg.get("cpu_usage") or 0.0),
            ram_usage=float(reg.get("ram_usage") or 0.0),
        )

        managed_device_service.upsert_device(
            conn,
            agent_id=agent_id,
            organization_id=org_id,
            device_ip=reg.get("device_ip"),
            device_mac=reg.get("device_mac"),
            hostname=reg.get("hostname"),
            os_family=reg.get("os"),
        )
        device_service.touch_device_seen(
            conn,
            ip=reg.get("device_ip"),
            organization_id=org_id,
            seen_at=reg.get("time"),
            agent_id=agent_id,
            hostname=reg.get("hostname"),
            mac=reg.get("device_mac"),
            vendor="Managed Agent",
            device_type="Managed Device",
            os_family=reg.get("os"),
            create_if_missing=True,
        )

        audit_service.log_agent_registration(
            organization_id=str(org_id),
            username="system",
            agent_id=agent_id,
            action="agent_enrollment_completed" if credential else "agent_reregistration",
            details=(
                "first_time"
                if credential and not force_reenroll
                else "reenrollment" if credential and force_reenroll
                else "already_registered"
            ),
            ip_address=source_ip,
        )

        conn.commit()

        if credential:
            response["agent_credentials"] = credential.as_response()
            response["message"] = "Agent enrollment approved."
        else:
            response["agent_credentials"] = None
            response["message"] = "Agent already registered. Use explicit rotation endpoint for credential updates."
        return response
    except Exception as exc:
        conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/heartbeat")
async def agent_heartbeat(
    hb: dict,
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    max_retries = 3
    for attempt in range(max_retries):
        conn = get_db_connection()
        cursor = None
        try:
            agent_id = _require_authenticated_agent_id(auth_context, hb.get("agent_id"), source="request payload")

            cursor = conn.cursor(dictionary=True)
            org_id = _resolve_org_id(cursor, hb.get("organization_id"))
            cursor.close()
            cursor = None

            agent_service.upsert_agent(
                conn,
                agent_id=agent_id,
                organization_id=org_id,
                api_key=None,
                hostname=hb.get("hostname"),
                ip_address=hb.get("device_ip"),
                os_family=hb.get("os"),
                version=hb.get("version"),
                inspection_state=hb.get("web_inspection"),
                cpu_usage=float(hb.get("cpu_usage") or 0.0),
                ram_usage=float(hb.get("ram_usage") or 0.0),
                integrity_status=hb.get("integrity_status"),
                manifest_hash=hb.get("manifest_hash"),
            )

            managed_device_service.upsert_device(
                conn,
                agent_id=agent_id,
                organization_id=org_id,
                device_ip=hb.get("device_ip"),
                device_mac=hb.get("device_mac"),
                hostname=hb.get("hostname"),
                os_family=hb.get("os"),
            )
            device_service.touch_device_seen(
                conn,
                ip=hb.get("device_ip"),
                organization_id=org_id,
                seen_at=hb.get("time"),
                agent_id=agent_id,
                hostname=hb.get("hostname"),
                mac=hb.get("device_mac"),
                vendor="Managed Agent",
                device_type="Managed Device",
                os_family=hb.get("os"),
                create_if_missing=True,
            )
            conn.commit()
            return _collect_response(
                auth_context=auth_context,
                organization_id=org_id,
            )
        except mysql.connector.Error as exc:
            conn.rollback()
            if exc.errno == 1213 and attempt < max_retries - 1:
                logger.warning("Deadlock encountered in agent_heartbeat, retrying (attempt %s/%s)...", attempt + 1, max_retries)
                await asyncio.sleep(0.1 * (attempt + 1))
                continue
            logger.error("Failed agent heartbeat: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to process heartbeat")
        except HTTPException:
            conn.rollback()
            raise
        except Exception as exc:
            conn.rollback()
            logger.error("Failed agent heartbeat: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to process heartbeat")
        finally:
            if cursor:
                cursor.close()
            conn.close()


@router.get("/web-policy")
async def get_web_policy(
    agent_id: str = Query(...),
    device_ip: str = Query(...),
    organization_id: str | None = Query(default=None),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    conn = get_db_connection()
    cursor = None
    try:
        authenticated_agent_id = _require_authenticated_agent_id(
            auth_context,
            agent_id,
            source="query parameter",
        )

        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, organization_id)
        cursor.close()
        cursor = None

        policy = web_inspection_service.get_policy(
            conn,
            agent_id=authenticated_agent_id,
            device_ip=device_ip,
            organization_id=org_id,
        )
        return _collect_response(auth_context=auth_context, **policy)
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/web-events/batch")
async def receive_web_events(
    events: list = Body(...),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    if not events:
        return _collect_response(auth_context=auth_context, count=0)

    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    for index, event in enumerate(events):
        _require_authenticated_agent_id(
            auth_context,
            event.get("agent_id"),
            source=f"event at index {index}",
        )

    max_retries = 3
    for attempt in range(max_retries):
        conn = get_db_connection()
        try:
            count = web_inspection_service.store_events(conn, events)
            conn.commit()
            loop = asyncio.get_event_loop()
            for event in events:
                if "timestamp" not in event:
                    from datetime import datetime, timezone

                    event["timestamp"] = datetime.now(timezone.utc).isoformat()
                if "app" not in event:
                    event["app"] = event.get("browser_name") or event.get("process_name") or "Unknown"

                event["agent_id"] = authenticated_agent_id
                loop.create_task(dpi_event_emitter.emit(event))
            return _collect_response(auth_context=auth_context, count=count)
        except mysql.connector.Error as exc:
            conn.rollback()
            if exc.errno == 1213 and attempt < max_retries - 1:
                logger.warning("Deadlock encountered while storing web events, retrying (attempt %s/%s)...", attempt + 1, max_retries)
                await asyncio.sleep(0.1 * (attempt + 1))
                continue
            logger.error("Failed to store web inspection events: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to store web events")
        except Exception as exc:
            conn.rollback()
            logger.error("Failed to store web inspection events: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to store web events")
        finally:
            conn.close()


@router.post("/rotate-credential")
async def rotate_agent_credential(
    request: Request,
    authorization: dict = Body(...),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    """Explicitly rotate agent credential - returns new credential only when called."""
    _require_signed_agent_auth(auth_context)

    conn = get_db_connection()
    cursor = None
    try:
        agent_id = _require_authenticated_agent_id(auth_context, authorization.get("agent_id"), source="request body")

        cursor = conn.cursor(dictionary=True)
        org_id = _lookup_agent_organization_id(cursor, agent_id) or settings.DEFAULT_ORGANIZATION_ID or "default-org-id"
        cursor.close()
        cursor = None

        credential = agent_auth_service.rotate_credential(conn, agent_id=agent_id)
        conn.commit()

        source_ip = _resolve_source_ip(request)
        audit_service.log_credential_rotation(
            organization_id=str(org_id),
            username="system",
            agent_id=agent_id,
            ip_address=source_ip,
        )

        return _collect_response(
            auth_context=auth_context,
            agent_credentials=credential.as_response(),
            message="Credential rotated successfully. Previous credential is now invalid.",
        )
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        logger.error("Failed to rotate agent credential: %s", exc, exc_info=True)
        conn.rollback()
        raise HTTPException(status_code=500, detail="Failed to rotate credential")
    finally:
        if cursor:
            cursor.close()
        conn.close()


@router.post("/devices/batch")
async def receive_devices(
    devices: list = Body(...),
    request: Request = None,
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    """Receive ARP-discovered devices from an agent and upsert them into the devices table."""
    if not devices:
        return _collect_response(auth_context=auth_context, count=0)

    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    for index, dev in enumerate(devices):
        _require_authenticated_agent_id(
            auth_context,
            dev.get("agent_id"),
            source=f"device at index {index}",
        )

    max_retries = 3
    for attempt in range(max_retries):
        conn = get_db_connection()
        cursor = None
        try:
            from ..main import p_sio

            cursor = conn.cursor(dictionary=True)
            requested_org_id = None
            if devices and isinstance(devices[0], dict):
                requested_org_id = devices[0].get("organization_id")
            org_id = _resolve_org_id(cursor, requested_org_id)
            cursor.close()
            cursor = None

            source_ip = _resolve_source_ip(request)
            count = 0
            for dev in devices:
                logger.debug("Upserting device: %s for org %s", dev.get("ip"), dev.get("organization_id"))
                dev_ip = dev.get("ip")
                dev_agent_id = authenticated_agent_id if dev_ip and dev_ip == source_ip else None
                if device_service.touch_device_seen(
                    conn,
                    ip=dev_ip,
                    organization_id=org_id,
                    seen_at=dev.get("last_seen"),
                    agent_id=dev_agent_id,
                    hostname=dev.get("hostname"),
                    mac=dev.get("mac"),
                    vendor=dev.get("vendor"),
                    device_type=dev.get("device_type"),
                    os_family=dev.get("os_family"),
                    create_if_missing=True,
                ):
                    count += 1

            conn.commit()
            for dev in devices:
                await p_sio.emit("device_event", {"data": dev})

            logger.info("Upserted %s device(s) from agent scan.", count)
            return _collect_response(auth_context=auth_context, count=count)
        except mysql.connector.Error as exc:
            conn.rollback()
            if exc.errno == 1213 and attempt < max_retries - 1:
                logger.warning("Deadlock encountered while upserting devices, retrying (attempt %s/%s)...", attempt + 1, max_retries)
                await asyncio.sleep(0.1 * (attempt + 1))
                continue
            logger.error("Failed to upsert devices: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to store devices")
        except Exception as exc:
            conn.rollback()
            logger.error("Failed to upsert devices: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to store devices")
        finally:
            if cursor:
                cursor.close()
            conn.close()


# ---------------------------------------------------------------------------
# mTLS Certificate Enrollment
# ---------------------------------------------------------------------------


@router.get("/certificate/ca")
async def get_ca_certificate():
    """Public endpoint: retrieve the CA certificate for trust anchoring."""
    from ..services.ca import CertificateAuthority

    ca = CertificateAuthority(settings.MTLS_CA_DIR)
    ca.ensure_ca()
    return {
        "ca_cert_pem": ca.get_ca_cert_pem().decode("utf-8"),
        "ca_fingerprint": ca.get_ca_cert_fingerprint(),
    }


@router.post("/certificate/enroll")
async def enroll_certificate(request: Request):
    """Issue a client certificate to an enrolled agent.

    Requires a valid HMAC-signed request (enrolled agent).
    The agent sends a PEM-encoded CSR in the request body.
    """
    from ..services.ca import CertificateAuthority

    conn = get_db_connection()
    try:
        body_bytes = await request.body()
        auth_context = agent_auth_service.authenticate_request(conn, request, body_bytes)
    except AgentAuthenticationError as exc:
        conn.close()
        raise HTTPException(status_code=401, detail=str(exc))

    try:
        import json

        body = json.loads(body_bytes.decode("utf-8") or "{}")
        csr_pem = body.get("csr_pem", "")
        if not csr_pem:
            raise HTTPException(status_code=400, detail="csr_pem is required")

        authenticated_agent_id = auth_context.get("agent_id", "")
        role = "agent"

        ca = CertificateAuthority(settings.MTLS_CA_DIR)
        cert_pem, metadata = ca.issue_client_cert(
            csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem,
            agent_id=authenticated_agent_id,
            role=role,
            validity_days=settings.MTLS_CERT_VALIDITY_DAYS,
        )

        # Store certificate metadata in the agents table
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE agents
                SET cert_serial = %s,
                    cert_fingerprint = %s,
                    cert_issued_at = %s,
                    cert_expires_at = %s,
                    cert_status = 'active'
                WHERE id = %s
                """,
                (
                    metadata["serial"],
                    metadata["fingerprint"],
                    metadata["issued_at"],
                    metadata["expires_at"],
                    authenticated_agent_id,
                ),
            )
            conn.commit()
        finally:
            cursor.close()

        logger.info(
            "Certificate enrolled: agent_id=%s serial=%s",
            authenticated_agent_id,
            metadata["serial"],
        )

        return {
            "certificate_pem": cert_pem.decode("utf-8"),
            "ca_cert_pem": ca.get_ca_cert_pem().decode("utf-8"),
            "expires_at": metadata["expires_at"],
            "serial": metadata["serial"],
            "fingerprint": metadata["fingerprint"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Certificate enrollment failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Certificate enrollment failed")
    finally:
        conn.close()


@router.post("/certificate/renew")
async def renew_certificate(request: Request):
    """Renew an agent's client certificate.

    Requires a valid HMAC-signed request. Issues a new certificate with
    a fresh serial and validity period, revoking the old one.
    """
    from ..services.ca import CertificateAuthority

    conn = get_db_connection()
    try:
        body_bytes = await request.body()
        auth_context = agent_auth_service.authenticate_request(conn, request, body_bytes)
    except AgentAuthenticationError as exc:
        conn.close()
        raise HTTPException(status_code=401, detail=str(exc))

    try:
        import json

        body = json.loads(body_bytes.decode("utf-8") or "{}")
        csr_pem = body.get("csr_pem", "")
        if not csr_pem:
            raise HTTPException(status_code=400, detail="csr_pem is required")

        authenticated_agent_id = auth_context.get("agent_id", "")
        role = "agent"

        ca = CertificateAuthority(settings.MTLS_CA_DIR)

        # Revoke the previous certificate if one exists
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT cert_serial FROM agents WHERE id = %s",
                (authenticated_agent_id,),
            )
            existing = cursor.fetchone()
            old_serial = (existing or {}).get("cert_serial")
            if old_serial:
                ca.revoke_cert(
                    conn,
                    serial_number=old_serial,
                    agent_id=authenticated_agent_id,
                    revoked_by="system",
                    reason="certificate_renewal",
                )
        finally:
            cursor.close()

        # Issue new certificate
        cert_pem, metadata = ca.issue_client_cert(
            csr_pem.encode("utf-8") if isinstance(csr_pem, str) else csr_pem,
            agent_id=authenticated_agent_id,
            role=role,
            validity_days=settings.MTLS_CERT_VALIDITY_DAYS,
        )

        # Update metadata
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE agents
                SET cert_serial = %s,
                    cert_fingerprint = %s,
                    cert_issued_at = %s,
                    cert_expires_at = %s,
                    cert_status = 'active'
                WHERE id = %s
                """,
                (
                    metadata["serial"],
                    metadata["fingerprint"],
                    metadata["issued_at"],
                    metadata["expires_at"],
                    authenticated_agent_id,
                ),
            )
            conn.commit()
        finally:
            cursor.close()

        logger.info(
            "Certificate renewed: agent_id=%s new_serial=%s old_serial=%s",
            authenticated_agent_id,
            metadata["serial"],
            old_serial,
        )

        return {
            "certificate_pem": cert_pem.decode("utf-8"),
            "ca_cert_pem": ca.get_ca_cert_pem().decode("utf-8"),
            "expires_at": metadata["expires_at"],
            "serial": metadata["serial"],
            "fingerprint": metadata["fingerprint"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Certificate renewal failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Certificate renewal failed")
    finally:
        conn.close()


@router.post("/batch", status_code=status.HTTP_202_ACCEPTED, response_model=GenericResponse)
async def ingest_collect_batch(
    payload: dict = Body(...),
    _rate_limited: bool = Depends(agent_control_rate_limit),
    auth_context: dict = Depends(validate_agent_key),
):
    """
    Consolidated ingestion endpoint. Accepts telemetry batch, authenticates,
    and forwards to Event Bus asynchronously.
    """
    from ..schemas.flow_schema import FlowBase
    from ..schemas.user_schema import GenericResponse
    from ..services.event_dispatcher import flow_ingestion_queue

    authenticated_agent_id = str(auth_context.get("agent_id") or "").strip()
    if not authenticated_agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required in authentication")

    # Extract organization ID
    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        org_id = _resolve_org_id(cursor, payload.get("organization_id"))
    finally:
        if cursor:
            cursor.close()
        conn.close()

    # Basic schema check (validate flows) and enforce tenant constraints
    flows_raw = payload.get("flows", [])
    flows_validated = []
    for flow in flows_raw:
        try:
            flow_data = dict(flow)
            flow_data["agent_id"] = authenticated_agent_id
            flow_data["organization_id"] = org_id
            flow_validated = FlowBase(**flow_data)
            flows_validated.append(flow_validated)
        except Exception as e:
            logger.warning("Invalid flow payload in consolidated batch: %s", e)
            raise HTTPException(status_code=400, detail=f"Flow validation failed: {e}")

    # Buffer the validated flows through the main pipeline
    if flows_validated:
        from ..services.flow_service import flow_service
        success = await flow_service.buffer_flows(flows_validated)
        if not success:
            raise HTTPException(status_code=503, detail="Ingestion queue is full")

    return _collect_response(
        auth_context=auth_context,
        message=f"Queued {len(flows_validated)} flows",
        count=len(flows_validated),
    )

