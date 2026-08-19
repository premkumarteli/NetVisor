"""Admin API for certificate lifecycle management."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..core.config import settings
from ..core.dependencies import require_org_scoped_role
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
    user=Depends(require_org_scoped_role("org_admin", "super_admin")),
):
    """List all issued certificate metadata from the agents table."""
    is_super_admin = user.get("role") == "super_admin"
    org_id = None if is_super_admin else user.get("organization_id")
    if not org_id and not is_super_admin:
        return {"certificates": []}

    cursor = db.cursor(dictionary=True)
    try:
        if org_id:
            cursor.execute(
                """
                SELECT id AS agent_id, hostname, cert_serial, cert_fingerprint,
                       cert_issued_at, cert_expires_at, cert_status
                FROM agents
                WHERE cert_serial IS NOT NULL AND organization_id = %s
                ORDER BY cert_issued_at DESC
                """,
                (org_id,),
            )
        else:
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
    user=Depends(require_org_scoped_role("org_admin", "super_admin")),
):
    """Download the CA certificate (admin access)."""
    ca = _get_ca()
    return {
        "ca_cert_pem": ca.get_ca_cert_pem().decode("utf-8"),
        "ca_fingerprint": ca.get_ca_cert_fingerprint(),
    }


@router.get("/certificates/revocations")
def list_revocations(
    request: Request,
    db=Depends(get_db),
    user=Depends(require_org_scoped_role("org_admin", "super_admin")),
):
    """List all certificate revocations."""
    ca = _get_ca()
    is_super_admin = user.get("role") == "super_admin"
    org_id = None if is_super_admin else user.get("organization_id")
    if not org_id and not is_super_admin:
        return {"revocations": []}
    return {"revocations": ca.list_revocations(db, organization_id=org_id)}


@router.post("/certificates/revoke")
def revoke_certificate(
    request: Request,
    body: RevokeRequest,
    db=Depends(get_db),
    user=Depends(require_org_scoped_role("org_admin", "super_admin")),
):
    """Revoke a certificate by serial number."""
    is_super_admin = user.get("role") == "super_admin"
    org_id = None if is_super_admin else user.get("organization_id")
    if not org_id and not is_super_admin:
        raise HTTPException(status_code=403, detail="Organization context required")

    serial = body.serial_number.upper().strip()
    if not serial:
        raise HTTPException(status_code=400, detail="Serial number cannot be empty")

    agent_id = body.agent_id.strip() if body.agent_id else None
    target_agent_id = agent_id

    cursor = db.cursor(dictionary=True)
    try:
        if agent_id:
            if org_id:
                cursor.execute(
                    """
                    SELECT id, organization_id, cert_serial
                    FROM agents
                    WHERE id = %s AND organization_id = %s
                    """,
                    (agent_id, org_id),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, organization_id, cert_serial
                    FROM agents
                    WHERE id = %s
                    """,
                    (agent_id,),
                )
            agent_row = cursor.fetchone()
            if not agent_row:
                raise HTTPException(
                    status_code=403,
                    detail="Agent does not belong to your organization",
                )

            # Check if serial number belongs to another organization in agents table
            cursor.execute(
                """
                SELECT id, organization_id, cert_serial
                FROM agents
                WHERE cert_serial = %s
                """,
                (serial,),
            )
            cert_owner = cursor.fetchone()
            if cert_owner:
                if org_id and cert_owner.get("organization_id") != org_id:
                    raise HTTPException(
                        status_code=403,
                        detail="Certificate does not belong to your organization",
                    )
                target_agent_id = cert_owner.get("id")
            else:
                target_agent_id = agent_id
        else:
            cursor.execute(
                """
                SELECT id, organization_id, cert_serial
                FROM agents
                WHERE cert_serial = %s
                """,
                (serial,),
            )
            agent_row = cursor.fetchone()
            if not agent_row or (org_id and agent_row.get("organization_id") != org_id):
                raise HTTPException(
                    status_code=403,
                    detail="Certificate does not belong to your organization",
                )
            target_agent_id = agent_row.get("id")
    finally:
        cursor.close()

    ca = _get_ca()

    # Check if already revoked
    if ca.is_revoked(db, serial):
        raise HTTPException(status_code=409, detail="Certificate already revoked")

    ca.revoke_cert(
        db,
        serial_number=serial,
        agent_id=target_agent_id,
        revoked_by=user.get("username", "admin"),
        reason=body.reason,
    )

    # Update agent cert_status if target_agent_id resolved
    if target_agent_id:
        cursor = db.cursor()
        try:
            cursor.execute(
                """
                UPDATE agents SET cert_status = 'revoked'
                WHERE id = %s AND (cert_serial = %s OR UPPER(cert_serial) = %s)
                """,
                (target_agent_id, serial, serial),
            )
            db.commit()
        finally:
            cursor.close()

    logger.info(
        "Certificate revoked via admin API: serial=%s agent=%s by=%s",
        serial,
        target_agent_id,
        user.get("username"),
    )

    return {"status": "revoked", "serial_number": serial}
