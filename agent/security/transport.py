from __future__ import annotations

import ipaddress
import os
import hashlib
import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from security import (
    AGENT_ID_HEADER,
    KEY_VERSION_HEADER,
    LEGACY_API_KEY_HEADER,
    NONCE_HEADER,
    REENROLL_REQUEST_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign_request,
)

from .dpapi import DataProtector, WindowsCurrentUserProtector
from .state import ProtectedStateStore
from .integrity import verify_agent_code_integrity
from .mtls import AgentMTLS

logger = logging.getLogger(__name__)

_PIN_SHA256_RE = re.compile(r"^[0-9A-F]{64}$")


class AgentApiClient:
    def __init__(
        self,
        *,
        state_path: Path,
        bootstrap_api_key: str,
        protector: DataProtector | None = None,
        initial_pins: list[dict] | None = None,
        agent_id: str = "",
        mtls_renewal_days: int = 30,
    ) -> None:
        self.session = requests.Session()
        self.bootstrap_api_key = str(bootstrap_api_key or "")
        self.allow_lan_http = str(os.getenv("NETVISOR_ALLOW_LAN_HTTP", "false")).strip().lower() in {"1", "true", "yes", "on"}
        self.store = ProtectedStateStore(
            state_path,
            protector=protector or WindowsCurrentUserProtector(),
            description="netvisor-agent-transport-state",
        )
        self._state = self.store.load(
            {
                "agent_credentials": None,
                "backend_tls_pins": self._normalize_pinset(initial_pins or []),
            }
        )
        self._state["agent_credentials"] = self._normalize_credentials(self._state.get("agent_credentials"))
        self._state["backend_tls_pins"] = self._normalize_pinset(self._state.get("backend_tls_pins"))
        if initial_pins and not self._state.get("backend_tls_pins"):
            self._state["backend_tls_pins"] = self._normalize_pinset(initial_pins)
            self._persist()

        # mTLS client certificate management
        self._agent_id = agent_id or os.getenv("NETVISOR_AGENT_ID", "")
        self._mtls_renewal_days = mtls_renewal_days
        mtls_state_dir = state_path.parent / "mtls" if state_path.is_file() else state_path / "mtls"
        self._mtls = AgentMTLS(mtls_state_dir, self._agent_id)
        # Attach client cert to session if available
        self._mtls.configure_session(self.session)

    def _persist(self) -> None:
        self.store.save(self._state)

    def _normalize_pin(self, pin: dict[str, Any]) -> dict[str, str] | None:
        pin_type = str(pin.get("pin_type") or "spki_sha256").strip().lower()
        status = str(pin.get("status") or "active").strip().lower()
        pin_sha256 = str(pin.get("pin_sha256") or "").strip().upper()

        if pin_type not in {"spki_sha256", "cert_sha256"}:
            return None
        if status not in {"active", "next"}:
            return None
        if not _PIN_SHA256_RE.fullmatch(pin_sha256):
            return None

        normalized = {
            "pin_type": pin_type,
            "pin_sha256": pin_sha256,
            "status": status,
        }
        subject = str(pin.get("subject") or "").strip()
        if subject:
            normalized["subject"] = subject
        return normalized

    def _normalize_pinset(self, pins: Any) -> list[dict[str, str]]:
        if not isinstance(pins, list):
            return []
        normalized: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            normalized_pin = self._normalize_pin(pin)
            if not normalized_pin:
                logger.warning("Ignoring invalid backend TLS pin entry in agent transport state.")
                continue
            key = (
                normalized_pin["pin_type"],
                normalized_pin["pin_sha256"],
                normalized_pin["status"],
            )
            if key in seen:
                continue
            seen.add(key)
            normalized.append(normalized_pin)
        return normalized

    def _normalize_credentials(self, credentials: Any) -> dict[str, Any] | None:
        if not isinstance(credentials, dict):
            return None
        agent_id = str(credentials.get("agent_id") or "").strip()
        secret = str(credentials.get("secret") or "").strip()
        try:
            key_version = int(credentials.get("key_version") or 0)
        except (TypeError, ValueError):
            return None
        if not agent_id or not secret or key_version < 1:
            return None
        return {
            "agent_id": agent_id,
            "key_version": key_version,
            "secret": secret,
            "issued_at": credentials.get("issued_at"),
        }

    def seed_pins(self, pins: list[dict] | None) -> None:
        normalized = self._normalize_pinset(pins)
        if not normalized:
            return
        self._state["backend_tls_pins"] = normalized
        self._persist()

    def _credentials(self) -> dict | None:
        credentials = self._state.get("agent_credentials")
        return credentials if isinstance(credentials, dict) else None

    def has_credentials(self) -> bool:
        credentials = self._credentials()
        return bool(credentials and credentials.get("secret"))

    def status_snapshot(self) -> dict:
        credentials = self._credentials() or {}
        pinset = self._pinset()
        findings: list[dict[str, str]] = []
        if not self.bootstrap_api_key:
            findings.append(
                {
                    "severity": "critical",
                    "code": "missing_bootstrap_key",
                    "message": "Agent API bootstrap key is not configured.",
                }
            )
        if not pinset:
            findings.append(
                {
                    "severity": "critical",
                    "code": "missing_tls_pins",
                    "message": "No backend TLS pins are configured.",
                }
            )
        
        # Code Integrity Check
        bundle_root = Path(__file__).resolve().parent.parent.parent
        integrity = verify_agent_code_integrity(bundle_root)
        for finding in integrity.get("findings", []):
            if finding.get("severity") == "critical":
                findings.append(finding)

        return {
            "bootstrap_api_key_configured": bool(self.bootstrap_api_key),
            "has_credentials": self.has_credentials(),
            "credential_agent_id": credentials.get("agent_id"),
            "credential_key_version": credentials.get("key_version"),
            "backend_tls_pin_count": len(pinset),
            "state_path": str(self.store.path),
            "integrity_status": integrity["status"],
            "manifest_hash": integrity.get("manifest_hash"),
            "integrity_metadata": integrity.get("metadata", {}),
            **self._mtls.status_info(),
            "hardening": {
                "ready": not any(finding["severity"] == "critical" for finding in findings),
                "finding_count": len(findings),
                "findings": findings,
            },
        }

    def reset_enrollment(self, *, preserve_pins: bool = True) -> None:
        self._state["agent_credentials"] = None
        if not preserve_pins:
            self._state["backend_tls_pins"] = []
        self._persist()

    def _pinset(self) -> list[dict]:
        pins = self._state.get("backend_tls_pins")
        return self._normalize_pinset(pins)

    def _is_local_url(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def _is_private_lan_url(self, url: str) -> bool:
        if not self.allow_lan_http:
            return False
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False
        try:
            return ipaddress.ip_address(hostname).is_private
        except ValueError:
            return False

    def _enforce_transport_policy(self, url: str) -> None:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if self._is_local_url(url):
            return
        if scheme != "https" and self._is_private_lan_url(url):
            return
        if scheme != "https":
            raise requests.exceptions.SSLError("Remote backend connections must use HTTPS.")
        if not self._pinset():
            raise requests.exceptions.SSLError(
                "Remote backend connections require configured TLS pins before first contact."
            )

    def bootstrap_post(
        self,
        url: str,
        *,
        json_body: Any,
        timeout: float = 10.0,
        reenroll: bool = False,
    ) -> requests.Response:
        self._enforce_transport_policy(url)
        headers = {LEGACY_API_KEY_HEADER: self.bootstrap_api_key}
        if reenroll:
            headers[REENROLL_REQUEST_HEADER] = "1"
        response = self.session.post(url, json=json_body, headers=headers, timeout=timeout, stream=True)
        self._enforce_tls_pins(url, response)
        response.content
        self._consume_security_metadata(response)
        return response

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        params: dict | None = None,
        timeout: float = 10.0,
    ) -> requests.Response:
        body_bytes = b""
        headers: dict[str, str] = {"X-Protocol-Version": "1.0.0"}
        if json_body is not None:
            body_bytes = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"

        credentials = self._credentials()
        if credentials:
            timestamp = str(int(time.time()))
            nonce = uuid.uuid4().hex
            request_obj = requests.Request(
                method=method.upper(),
                url=url,
                params=params,
                data=body_bytes or None,
                headers=headers,
            )
            prepared = self.session.prepare_request(request_obj)
            signature = sign_request(
                secret=str(credentials.get("secret") or ""),
                method=prepared.method or method,
                path=prepared.path_url or "/",
                timestamp=timestamp,
                nonce=nonce,
                body=body_bytes,
            )
            prepared.headers[AGENT_ID_HEADER] = str(credentials.get("agent_id") or "")
            prepared.headers[KEY_VERSION_HEADER] = str(credentials.get("key_version") or "")
            prepared.headers[TIMESTAMP_HEADER] = timestamp
            prepared.headers[NONCE_HEADER] = nonce
            prepared.headers[SIGNATURE_HEADER] = signature
        else:
            prepared = self.session.prepare_request(
                requests.Request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=body_bytes or None,
                    headers={**headers, LEGACY_API_KEY_HEADER: self.bootstrap_api_key},
                )
            )

        self._enforce_transport_policy(prepared.url or url)
        response = self.session.send(prepared, timeout=timeout, stream=True)
        self._enforce_tls_pins(prepared.url or url, response)
        response.content
        self._consume_security_metadata(response)
        return response

    def _consume_security_metadata(self, response: requests.Response) -> None:
        content_type = str(response.headers.get("Content-Type") or "").lower()
        if "json" not in content_type:
            return
        try:
            payload = response.json()
        except ValueError:
            return
        if not isinstance(payload, dict):
            return
        credentials = self._normalize_credentials(payload.get("agent_credentials"))
        if credentials:
            self._state["agent_credentials"] = credentials
        pins = payload.get("backend_tls_pins")
        if isinstance(pins, list):
            self._state["backend_tls_pins"] = self._normalize_pinset(pins)
        if credentials or isinstance(pins, list):
            self._persist()

    # ------------------------------------------------------------------
    # mTLS certificate lifecycle
    # ------------------------------------------------------------------

    def enroll_certificate(self, server_url: str) -> bool:
        """Request a client certificate from the server after agent enrollment."""
        if self._mtls.has_certificate() and not self._mtls.needs_renewal(self._mtls_renewal_days):
            return True  # Already have a valid, non-expiring-soon cert

        if not self.has_credentials():
            return False  # Need enrolled HMAC credentials first

        try:
            csr_pem = self._mtls.generate_csr()

            endpoint = "certificate/renew" if self._mtls.has_certificate() else "certificate/enroll"
            url = f"{server_url.rstrip('/')}/api/v1/collect/{endpoint}"

            response = self.request(
                "POST",
                url,
                json_body={"csr_pem": csr_pem.decode("utf-8")},
                timeout=30.0,
            )

            if response.status_code != 200:
                logger.warning(
                    "Certificate enrollment failed: HTTP %s: %s",
                    response.status_code,
                    response.text[:200],
                )
                return False

            payload = response.json()
            cert_pem = payload.get("certificate_pem", "")
            ca_cert_pem = payload.get("ca_cert_pem", "")

            if not cert_pem or not ca_cert_pem:
                logger.warning("Certificate enrollment returned empty certificate.")
                return False

            self._mtls.store_certificate(
                cert_pem.encode("utf-8"),
                ca_cert_pem.encode("utf-8"),
            )
            # Reconfigure the session with the new cert
            self._mtls.configure_session(self.session)

            logger.info(
                "mTLS certificate %s: serial=%s expires=%s",
                endpoint.split("/")[-1],
                payload.get("serial"),
                payload.get("expires_at"),
            )
            return True
        except Exception as exc:
            logger.warning("Certificate enrollment error: %s", exc)
            return False

    def check_certificate_renewal(self, server_url: str) -> None:
        """Check if the client certificate needs renewal and renew if so."""
        if not self._mtls.needs_renewal(self._mtls_renewal_days):
            return
        logger.info("Client certificate nearing expiry, requesting renewal...")
        self.enroll_certificate(server_url)

    def _extract_peer_certificate(self, response: requests.Response) -> bytes | None:
        connection = getattr(response.raw, "connection", None) or getattr(response.raw, "_connection", None)
        sock = getattr(connection, "sock", None)
        if sock is None:
            return None
        try:
            return sock.getpeercert(binary_form=True)
        except Exception:
            return None

    def _pin_fingerprint(self, pin_type: str, certificate_der: bytes) -> str:
        if pin_type == "cert_sha256":
            return hashlib.sha256(certificate_der).hexdigest().upper()
        certificate = x509.load_der_x509_certificate(certificate_der)
        public_key_bytes = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(public_key_bytes).hexdigest().upper()

    def _enforce_tls_pins(self, url: str, response: requests.Response) -> None:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return
        pinset = [pin for pin in self._pinset() if str(pin.get("status") or "active") in {"active", "next"}]
        if not pinset:
            return
        certificate_der = self._extract_peer_certificate(response)
        if not certificate_der:
            response.close()
            raise requests.exceptions.SSLError("Backend TLS certificate could not be inspected for pinning.")
        matched = False
        for pin in pinset:
            expected = str(pin.get("pin_sha256") or "").upper()
            if not expected:
                continue
            actual = self._pin_fingerprint(str(pin.get("pin_type") or "spki_sha256"), certificate_der)
            if actual == expected:
                matched = True
                break
        if not matched:
            response.close()
            raise requests.exceptions.SSLError("Backend TLS pin mismatch.")
