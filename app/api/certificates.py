"""Admin API for certificate lifecycle management."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..core.config import settings
from ..core.dependencies import get_current_user
from ..db.session import get_db
from ..services.ca import CertificateAuthority

logger = logging.getLogger("netvisor.api.certificates")

router = APIRouter()


class RevokeRequest(BaseModel):
    serial_number: str
    agent_id: Optional[str] = None
    reason: str = "administrative_revocation"


def _get_ca() -> CertificateAuthority:
    ca = CertificateAuthority(settings.MTLS_CA_DIR)
    ca.ensure_ca()
    return ca


@router.get("/certificates")
def list_certificates(
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
):
    """List all issued certificate metadata from the agents table."""
    if user.get("role") not in ("org_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id AS agent_id, hostname, cert_serial, cert_fingerprint,
                   cert_issued_at, cert_expires_at, cert_status
            FROM agents
            WHERE cert_serial IS NOT NULL
            ORDER BY cert_issued_at DESC
            """
        )
        rows = cursor.fetchall()
        result = []
        for row in rows:
            for ts_field in ("cert_issued_at", "cert_expires_at"):
                val = row.get(ts_field)
                if val and hasattr(val, "strftime"):
                    row[ts_field] = val.strftime("%Y-%m-%d %H:%M:%S")
            result.append(row)
        return {"certificates": result}
    finally:
        cursor.close()


@router.get("/certificates/ca")
def get_ca_certificate(
    request: Request,
    user=Depends(get_current_user),
):
    """Download the CA certificate (admin access)."""
    if user.get("role") not in ("org_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    ca = _get_ca()
    return {
        "ca_cert_pem": ca.get_ca_cert_pem().decode("utf-8"),
        "ca_fingerprint": ca.get_ca_cert_fingerprint(),
    }


@router.get("/certificates/revocations")
def list_revocations(
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
):
    """List all certificate revocations."""
    if user.get("role") not in ("org_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    ca = _get_ca()
    return {"revocations": ca.list_revocations(db)}


@router.post("/certificates/revoke")
def revoke_certificate(
    request: Request,
    body: RevokeRequest,
    db=Depends(get_db),
    user=Depends(get_current_user),
):
    """Revoke a certificate by serial number."""
    if user.get("role") not in ("org_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    ca = _get_ca()

    # Check if already revoked
    if ca.is_revoked(db, body.serial_number):
        raise HTTPException(status_code=409, detail="Certificate already revoked")

    ca.revoke_cert(
        db,
        serial_number=body.serial_number,
        agent_id=body.agent_id,
        revoked_by=user.get("username", "admin"),
        reason=body.reason,
    )

    # Update agent cert_status if agent_id provided
    if body.agent_id:
        cursor = db.cursor()
        try:
            cursor.execute(
                """
                UPDATE agents SET cert_status = 'revoked'
                WHERE id = %s AND cert_serial = %s
                """,
                (body.agent_id, body.serial_number.upper()),
            )
            db.commit()
        finally:
            cursor.close()

    logger.info(
        "Certificate revoked via admin API: serial=%s agent=%s by=%s",
        body.serial_number,
        body.agent_id,
        user.get("username"),
    )

    return {"status": "revoked", "serial_number": body.serial_number.upper()}
