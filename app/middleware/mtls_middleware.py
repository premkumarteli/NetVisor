"""mTLS validation middleware for NetVisor.

Reads X-Client-Cert-* headers injected by the Caddy reverse proxy and enforces
certificate-based identity for agent/gateway API routes based on the configured
MTLS_MODE (disabled | optional | required).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional

import anyio
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

# Cache for revocation checks (TTL: 5 minutes)
_REVOCATION_CACHE: dict[str, tuple[bool, float]] = {}
_REVOCATION_CACHE_TTL = 300.0  # 5 minutes


class MTLSMiddleware(BaseHTTPMiddleware):
    """Validates client certificate headers forwarded by the reverse proxy."""

    async def dispatch(self, request: Request, call_next):
        mode = str(getattr(settings, "MTLS_MODE", "disabled")).strip().lower()
        path = request.url.path

        # Only apply to agent/gateway API routes
        is_protected = any(path.startswith(prefix) for prefix in _MTLS_PROTECTED_PREFIXES)
        is_exempt = any(path.endswith(suffix) for suffix in _MTLS_EXEMPT_SUFFIXES)

        # Validate API Version / Protocol Version compatibility (Milestone 0)
        if is_protected and not is_exempt:
            protocol_version = request.headers.get("X-Protocol-Version", "").strip()
            if not protocol_version:
                logger.warning("Protocol version missing on protected path: %s", path)
                return JSONResponse(
                    status_code=400,
                    content={"detail": "X-Protocol-Version header is required."},
                )
            
            # SemVer compatibility check (Major version mismatch check)
            try:
                major_version = int(protocol_version.split(".")[0])
                if major_version != 1:
                    logger.warning("Protocol version mismatch: client=%s server=1.x", protocol_version)
                    return JSONResponse(
                        status_code=460, # 460 is our custom capability mismatch status code
                        content={"detail": f"Protocol version {protocol_version} is incompatible. Server requires version 1.x."},
                    )
            except (ValueError, IndexError):
                logger.warning("Invalid protocol version format: %s", protocol_version)
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid X-Protocol-Version format. Expected SemVer (e.g., 1.0.0)."},
                )

        if mode == "disabled":
            return await call_next(request)

        if not is_protected:
            return await call_next(request)

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
            # Check revocation in the database (async, cached, non-blocking)
            try:
                is_revoked = await self._check_revocation_async(cert_serial)
                if is_revoked:
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

    async def _check_revocation_async(self, cert_serial: str) -> bool:
        """Check certificate revocation asynchronously with caching."""
        import time
        
        # Check cache first
        now = time.monotonic()
        if cert_serial in _REVOCATION_CACHE:
            cached_result, cached_time = _REVOCATION_CACHE[cert_serial]
            if now - cached_time < _REVOCATION_CACHE_TTL:
                return cached_result
        
        # Run sync DB check in thread pool to avoid blocking event loop
        def _sync_revocation_check() -> bool:
            from ..db.session import get_db_connection
            from ..services.ca import CertificateAuthority
            
            conn = get_db_connection()
            try:
                ca = CertificateAuthority(settings.MTLS_CA_DIR)
                return ca.is_revoked(conn, cert_serial)
            finally:
                conn.close()
        
        result = await anyio.to_thread.run_sync(_sync_revocation_check)
        
        # Update cache
        _REVOCATION_CACHE[cert_serial] = (result, now)
        
        # Simple cache cleanup (remove expired entries)
        if len(_REVOCATION_CACHE) > 1000:
            expired = [k for k, (_, t) in _REVOCATION_CACHE.items() if now - t > _REVOCATION_CACHE_TTL]
            for k in expired:
                _REVOCATION_CACHE.pop(k, None)
        
        return result
