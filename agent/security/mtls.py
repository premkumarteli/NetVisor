"""Agent-side mTLS certificate management.

Generates a local ECDSA key pair, creates a CSR, stores the issued certificate
and CA cert, and configures requests.Session for client certificate authentication.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import requests

logger = logging.getLogger("netvisor.agent.mtls")


class AgentMTLS:
    """Manages the agent's mTLS client certificate lifecycle."""

    def __init__(
        self,
        state_dir: Path,
        agent_id: str,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.agent_id = agent_id

        self._key_path = self.state_dir / "mtls_client.key"
        self._cert_path = self.state_dir / "mtls_client.crt"
        self._ca_cert_path = self.state_dir / "mtls_ca.crt"

        self._private_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._certificate: Optional[x509.Certificate] = None
        self._ca_certificate: Optional[x509.Certificate] = None

        self._load_existing()

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    def has_certificate(self) -> bool:
        """True if we have a valid (non-expired) client certificate."""
        if self._certificate is None:
            return False
        now = datetime.now(timezone.utc)
        return now < self._certificate.not_valid_after_utc

    def needs_renewal(self, days_before: int = 30) -> bool:
        """True if the certificate expires within ``days_before`` days."""
        if self._certificate is None:
            return True
        now = datetime.now(timezone.utc)
        remaining = (self._certificate.not_valid_after_utc - now).total_seconds()
        return remaining < (days_before * 86400)

    def cert_fingerprint(self) -> Optional[str]:
        if self._certificate is None:
            return None
        return hashlib.sha256(
            self._certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest().upper()

    def cert_serial(self) -> Optional[str]:
        if self._certificate is None:
            return None
        return format(self._certificate.serial_number, "X")

    def cert_expires_at(self) -> Optional[str]:
        if self._certificate is None:
            return None
        return self._certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")

    def status_info(self) -> dict:
        """Return mTLS status for inclusion in heartbeat / status snapshots."""
        return {
            "mtls_has_certificate": self.has_certificate(),
            "mtls_needs_renewal": self.needs_renewal(),
            "mtls_cert_serial": self.cert_serial(),
            "mtls_cert_fingerprint": self.cert_fingerprint(),
            "mtls_cert_expires_at": self.cert_expires_at(),
        }

    # ------------------------------------------------------------------
    # CSR generation
    # ------------------------------------------------------------------

    def generate_csr(self) -> bytes:
        """Generate a new ECDSA key pair and return a PEM-encoded CSR.

        The private key never leaves this machine.
        """
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self._private_key = ec.generate_private_key(ec.SECP256R1())

        # Persist the private key immediately
        key_pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._key_path.write_bytes(key_pem)
        try:
            os.chmod(self._key_path, 0o600)
        except OSError:
            pass  # Windows

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.agent_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVisor"),
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(self._private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        logger.info("Generated CSR for agent_id=%s", self.agent_id)
        return csr_pem

    # ------------------------------------------------------------------
    # Certificate storage
    # ------------------------------------------------------------------

    def store_certificate(self, cert_pem: bytes, ca_cert_pem: bytes) -> None:
        """Store the signed client certificate and CA certificate."""
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self._cert_path.write_bytes(cert_pem)
        self._ca_cert_path.write_bytes(ca_cert_pem)

        self._certificate = x509.load_pem_x509_certificate(cert_pem)
        self._ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem)

        logger.info(
            "Stored client certificate: serial=%s expires=%s",
            self.cert_serial(),
            self.cert_expires_at(),
        )

    # ------------------------------------------------------------------
    # Session configuration
    # ------------------------------------------------------------------

    def configure_session(self, session: requests.Session) -> None:
        """Attach the client cert + key to a requests.Session.

        This causes the session to present the client certificate during
        the TLS handshake for mTLS authentication.
        """
        if not self.has_certificate():
            return
        if not self._key_path.exists() or not self._cert_path.exists():
            return

        session.cert = (str(self._cert_path), str(self._key_path))

        if self._ca_cert_path.exists():
            session.verify = str(self._ca_cert_path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_existing(self) -> None:
        """Load existing key, cert, and CA cert from disk."""
        try:
            if self._key_path.exists():
                self._private_key = serialization.load_pem_private_key(
                    self._key_path.read_bytes(),
                    password=None,
                )
            if self._cert_path.exists():
                self._certificate = x509.load_pem_x509_certificate(
                    self._cert_path.read_bytes()
                )
            if self._ca_cert_path.exists():
                self._ca_certificate = x509.load_pem_x509_certificate(
                    self._ca_cert_path.read_bytes()
                )
        except Exception as exc:
            logger.warning("Failed to load existing mTLS state: %s", exc)
            self._private_key = None
            self._certificate = None
            self._ca_certificate = None
