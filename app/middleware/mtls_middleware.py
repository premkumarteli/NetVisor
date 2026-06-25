"""mTLS validation middleware for NetVisor.

Reads X-Client-Cert-* headers injected by the Caddy reverse proxy and enforces
certificate-based identity for agent/gateway API routes based on the configured
MTLS_MODE (disabled | optional | required).
"""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from ..core.config import settings

logger = logging.getLogger("netvisor.mtls")

# Paths that require mTLS when mode is "required"
_MTLS_PROTECTED_PREFIXES = (
    "/api/v1/collect/",
    "/api/v1/gateway/",
)

# Paths exempt from mTLS even in "required" mode (bootstrap / enrollment / CA retrieval)
_MTLS_EXEMPT_SUFFIXES = (
    "/bootstrap",
    "/register",
    "/enroll",
    "/certificate/enroll",
    "/certificate/renew",
    "/certificate/ca",
)


class MTLSMiddleware(BaseHTTPMiddleware):
    """Validates client certificate headers forwarded by the reverse proxy."""

    async def dispatch(self, request: Request, call_next):
        mode = str(getattr(settings, "MTLS_MODE", "disabled")).strip().lower()
        if mode == "disabled":
            return await call_next(request)

        path = request.url.path

        # Only apply to agent/gateway API routes
        is_protected = any(path.startswith(prefix) for prefix in _MTLS_PROTECTED_PREFIXES)
        if not is_protected:
            return await call_next(request)

        # Exempt bootstrap and certificate enrollment endpoints
        is_exempt = any(path.endswith(suffix) for suffix in _MTLS_EXEMPT_SUFFIXES)
        if is_exempt:
            return await call_next(request)

        # Read headers injected by Caddy
        cert_subject = request.headers.get("X-Client-Cert-Subject", "").strip()
        cert_serial = request.headers.get("X-Client-Cert-Serial", "").strip()
        cert_fingerprint = request.headers.get("X-Client-Cert-Fingerprint", "").strip()
        cert_count_str = request.headers.get("X-Client-Cert-Verified", "0").strip()

        try:
            cert_count = int(cert_count_str)
        except (ValueError, TypeError):
            cert_count = 0

        has_valid_cert = cert_count > 0 and bool(cert_serial)

        if has_valid_cert:
            # Check revocation in the database
            try:
                from ..db.session import get_db_connection
                from ..services.ca import CertificateAuthority

                conn = get_db_connection()
                try:
                    ca = CertificateAuthority(settings.MTLS_CA_DIR)
                    if ca.is_revoked(conn, cert_serial):
                        logger.warning(
                            "mTLS: Revoked certificate used: serial=%s subject=%s path=%s",
                            cert_serial,
                            cert_subject,
                            path,
                        )
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "Client certificate has been revoked."},
                        )
                finally:
                    conn.close()
            except Exception as exc:
                logger.error("mTLS: Revocation check failed: %s", exc)
                # In optional mode, allow through on check failure
                if mode == "required":
                    return JSONResponse(
                        status_code=500,
                        content={"detail": "Certificate revocation check failed."},
                    )

            # Attach certificate identity to request state for downstream use
            request.state.mtls_subject = cert_subject
            request.state.mtls_serial = cert_serial
            request.state.mtls_fingerprint = cert_fingerprint
            request.state.mtls_verified = True
        else:
            request.state.mtls_verified = False

            if mode == "required":
                logger.warning(
                    "mTLS: No valid client certificate for protected path: %s",
                    path,
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "A valid client certificate is required for this endpoint."},
                )
            elif mode == "optional":
                logger.info(
                    "mTLS: No client certificate presented (optional mode): %s",
                    path,
                )

        return await call_next(request)
