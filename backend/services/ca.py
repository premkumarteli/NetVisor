"""NetVisor Private Certificate Authority for mTLS client certificate issuance."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("netvisor.ca")

# Use ECDSA P-256 for the CA key – widely supported, fast, compact signatures.
_CA_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "NetVisor Internal CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVisor"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
])

_CA_VALIDITY_DAYS = 3650  # 10-year CA certificate


class CertificateAuthority:
    """Lightweight internal CA for issuing mTLS client certificates."""

    def __init__(self, ca_dir: str | Path) -> None:
        self.ca_dir = Path(ca_dir)
        self._ca_key: Optional[ec.EllipticCurvePrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    def ensure_ca(self) -> None:
        """Create CA key + self-signed cert if they don't already exist."""
        if self._ca_key and self._ca_cert:
            return

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        key_path = self.ca_dir / "ca.key"
        cert_path = self.ca_dir / "ca.crt"

        if key_path.exists() and cert_path.exists():
            self._load_existing(key_path, cert_path)
            return

        logger.info("Generating new NetVisor CA key pair in %s", self.ca_dir)
        self._ca_key = ec.generate_private_key(ec.SECP256R1())

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(_CA_SUBJECT)
            .issuer_name(_CA_SUBJECT)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=_CA_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                critical=False,
            )
        )
        self._ca_cert = builder.sign(self._ca_key, hashes.SHA256())

        # Write with restrictive permissions
        key_pem = self._ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key_path.write_bytes(key_pem)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass  # Windows may not support chmod

        cert_path.write_bytes(
            self._ca_cert.public_bytes(serialization.Encoding.PEM)
        )
        logger.info("CA certificate created: serial=%s", format(self._ca_cert.serial_number, "X"))

    def _load_existing(self, key_path: Path, cert_path: Path) -> None:
        self._ca_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None,
        )
        self._ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        logger.info(
            "Loaded existing CA certificate: serial=%s, expires=%s",
            format(self._ca_cert.serial_number, "X"),
            self._ca_cert.not_valid_after_utc.isoformat(),
        )

    # ------------------------------------------------------------------
    # Certificate Issuance
    # ------------------------------------------------------------------

    def issue_client_cert(
        self,
        csr_pem: bytes,
        *,
        agent_id: str,
        role: str = "agent",
        validity_days: int = 90,
    ) -> tuple[bytes, dict]:
        """Sign a CSR and return (cert_pem, metadata).

        ``metadata`` includes serial, fingerprint, issued_at, expires_at.
        """
        self.ensure_ca()
        assert self._ca_key is not None
        assert self._ca_cert is not None

        csr = x509.load_pem_x509_csr(csr_pem)

        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_days)
        serial = x509.random_serial_number()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVisor"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                critical=False,
            )
        )

        cert = builder.sign(self._ca_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        fingerprint = hashlib.sha256(
            cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest().upper()

        metadata = {
            "serial": format(serial, "X"),
            "fingerprint": fingerprint,
            "issued_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": expires.strftime("%Y-%m-%d %H:%M:%S"),
            "subject_cn": agent_id,
            "subject_ou": role,
        }

        logger.info(
            "Issued client certificate: agent_id=%s role=%s serial=%s expires=%s",
            agent_id,
            role,
            metadata["serial"],
            metadata["expires_at"],
        )
        return cert_pem, metadata

    # ------------------------------------------------------------------
    # Revocation (in-database, checked by middleware)
    # ------------------------------------------------------------------

    def revoke_cert(
        self,
        db_conn,
        *,
        serial_number: str,
        agent_id: Optional[str] = None,
        revoked_by: str = "system",
        reason: str = "administrative_revocation",
    ) -> None:
        """Record a certificate revocation in the database."""
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO certificate_revocations
                    (serial_number, agent_id, revoked_by, reason, revoked_at)
                VALUES (%s, %s, %s, %s, UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    revoked_by = VALUES(revoked_by),
                    reason = VALUES(reason),
                    revoked_at = UTC_TIMESTAMP()
                """,
                (serial_number.upper(), agent_id, revoked_by, reason),
            )
            db_conn.commit()
            logger.warning(
                "Certificate revoked: serial=%s agent_id=%s by=%s reason=%s",
                serial_number,
                agent_id,
                revoked_by,
                reason,
            )
        finally:
            cursor.close()

    def is_revoked(self, db_conn, serial_number: str) -> bool:
        """Check if a certificate serial number has been revoked."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT 1
                FROM certificate_revocations
                WHERE serial_number = %s
                LIMIT 1
                """,
                (serial_number.upper(),),
            )
            return cursor.fetchone() is not None
        finally:
            cursor.close()

    def list_revocations(self, db_conn, organization_id: Optional[str] = None) -> list[dict]:
        """List all certificate revocations, optionally scoped to an organization."""
        cursor = db_conn.cursor(dictionary=True)
        try:
            if organization_id:
                cursor.execute(
                    """
                    SELECT cr.serial_number, cr.agent_id, cr.revoked_at, cr.revoked_by, cr.reason
                    FROM certificate_revocations cr
                    JOIN agents a ON cr.agent_id = a.id
                    WHERE a.organization_id = %s
                    ORDER BY cr.revoked_at DESC
                    """,
                    (organization_id,),
                )
            else:
                cursor.execute(
                    """
                    SELECT serial_number, agent_id, revoked_at, revoked_by, reason
                    FROM certificate_revocations
                    ORDER BY revoked_at DESC
                    """
                )
            rows = cursor.fetchall()
            result = []
            for row in rows:
                revoked_at = row.get("revoked_at")
                if hasattr(revoked_at, "strftime"):
                    revoked_at = revoked_at.strftime("%Y-%m-%d %H:%M:%S")
                result.append({
                    "serial_number": row.get("serial_number"),
                    "agent_id": row.get("agent_id"),
                    "revoked_at": str(revoked_at or ""),
                    "revoked_by": row.get("revoked_by"),
                    "reason": row.get("reason"),
                })
            return result
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # CA Certificate Retrieval
    # ------------------------------------------------------------------

    def get_ca_cert_pem(self) -> bytes:
        """Return the CA certificate PEM bytes."""
        self.ensure_ca()
        assert self._ca_cert is not None
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    def get_ca_cert_fingerprint(self) -> str:
        """Return the SHA-256 fingerprint of the CA certificate."""
        self.ensure_ca()
        assert self._ca_cert is not None
        return hashlib.sha256(
            self._ca_cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest().upper()
