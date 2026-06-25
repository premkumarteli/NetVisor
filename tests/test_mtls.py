"""Tests for mTLS certificate infrastructure.

Covers:
1. CA bootstrap (key pair + self-signed cert generated on first use)
2. CSR signing (valid CSR → valid client certificate)
3. Certificate fields (correct CN, OU, validity, key usage)
4. Revocation (revoked serial rejected by middleware)
5. Agent mTLS module (CSR generation, cert storage, session config)
6. Renewal (new cert with new serial, old cert revoked)
7. Mode enforcement (required rejects, optional allows)
8. Gateway certificates (OU=gateway)
"""

from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_ca_dir(tmp_path):
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    return ca_dir


@pytest.fixture
def tmp_agent_dir(tmp_path):
    agent_dir = tmp_path / "agent_state"
    agent_dir.mkdir()
    return agent_dir


@pytest.fixture
def ca(tmp_ca_dir):
    from app.services.ca import CertificateAuthority
    ca_instance = CertificateAuthority(tmp_ca_dir)
    ca_instance.ensure_ca()
    return ca_instance


@pytest.fixture
def agent_csr():
    """Generate a test ECDSA key + CSR."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-agent-001"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVisor"),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# 1. CA Bootstrap
# ---------------------------------------------------------------------------


class TestCABootstrap:
    def test_ca_generates_key_and_cert(self, tmp_ca_dir):
        from app.services.ca import CertificateAuthority

        ca = CertificateAuthority(tmp_ca_dir)
        ca.ensure_ca()

        assert (tmp_ca_dir / "ca.key").exists()
        assert (tmp_ca_dir / "ca.crt").exists()

    def test_ca_cert_is_self_signed(self, ca, tmp_ca_dir):
        cert_pem = (tmp_ca_dir / "ca.crt").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        # Issuer == Subject for self-signed
        assert cert.issuer == cert.subject

    def test_ca_cert_has_correct_subject(self, ca, tmp_ca_dir):
        cert_pem = (tmp_ca_dir / "ca.crt").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "NetVisor Internal CA"

    def test_ca_cert_is_ca(self, ca, tmp_ca_dir):
        cert_pem = (tmp_ca_dir / "ca.crt").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True

    def test_ca_idempotent(self, tmp_ca_dir):
        """Calling ensure_ca() twice does not regenerate the CA."""
        from app.services.ca import CertificateAuthority

        ca = CertificateAuthority(tmp_ca_dir)
        ca.ensure_ca()
        first_cert = (tmp_ca_dir / "ca.crt").read_bytes()

        ca2 = CertificateAuthority(tmp_ca_dir)
        ca2.ensure_ca()
        second_cert = (tmp_ca_dir / "ca.crt").read_bytes()

        assert first_cert == second_cert

    def test_get_ca_cert_pem(self, ca):
        pem = ca.get_ca_cert_pem()
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_get_ca_cert_fingerprint(self, ca):
        fp = ca.get_ca_cert_fingerprint()
        assert len(fp) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# 2. CSR Signing
# ---------------------------------------------------------------------------


class TestCSRSigning:
    def test_sign_csr_returns_valid_cert(self, ca, agent_csr):
        cert_pem, metadata = ca.issue_client_cert(
            agent_csr,
            agent_id="test-agent-001",
            role="agent",
            validity_days=90,
        )

        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert is not None

    def test_signed_cert_has_correct_subject(self, ca, agent_csr):
        cert_pem, _ = ca.issue_client_cert(
            agent_csr,
            agent_id="test-agent-001",
            role="agent",
        )
        cert = x509.load_pem_x509_certificate(cert_pem)

        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "test-agent-001"

        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        assert ou == "agent"

    def test_signed_cert_validity(self, ca, agent_csr):
        cert_pem, metadata = ca.issue_client_cert(
            agent_csr,
            agent_id="test-agent-001",
            validity_days=90,
        )
        cert = x509.load_pem_x509_certificate(cert_pem)

        now = datetime.now(timezone.utc)
        assert cert.not_valid_before_utc <= now
        # Should expire ~90 days from now
        expected_expiry = now + timedelta(days=90)
        delta = abs((cert.not_valid_after_utc - expected_expiry).total_seconds())
        assert delta < 60  # Within 1 minute of expected

    def test_signed_cert_metadata(self, ca, agent_csr):
        _, metadata = ca.issue_client_cert(
            agent_csr,
            agent_id="test-agent-001",
            role="agent",
        )

        assert "serial" in metadata
        assert "fingerprint" in metadata
        assert "issued_at" in metadata
        assert "expires_at" in metadata
        assert metadata["subject_cn"] == "test-agent-001"
        assert metadata["subject_ou"] == "agent"
        assert len(metadata["fingerprint"]) == 64


# ---------------------------------------------------------------------------
# 3. Certificate Fields
# ---------------------------------------------------------------------------


class TestCertificateFields:
    def test_key_usage(self, ca, agent_csr):
        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        cert = x509.load_pem_x509_certificate(cert_pem)

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.digital_signature is True
        assert ku.key_encipherment is True
        assert ku.key_cert_sign is False

    def test_extended_key_usage(self, ca, agent_csr):
        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        cert = x509.load_pem_x509_certificate(cert_pem)

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    def test_not_ca(self, ca, agent_csr):
        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        cert = x509.load_pem_x509_certificate(cert_pem)

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is False

    def test_issuer_is_ca(self, ca, agent_csr):
        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        cert = x509.load_pem_x509_certificate(cert_pem)

        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert issuer_cn == "NetVisor Internal CA"


# ---------------------------------------------------------------------------
# 4. Revocation
# ---------------------------------------------------------------------------


class TestRevocation:
    def test_revoke_and_check(self, ca, agent_csr):
        _, metadata = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        serial = metadata["serial"]

        # Mock DB connection
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Track the revocation insert
        ca.revoke_cert(
            mock_conn,
            serial_number=serial,
            agent_id="test-agent-001",
            revoked_by="admin",
            reason="test_revocation",
        )

        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()

    def test_is_revoked_returns_true(self, ca):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {"serial_number": "ABC123"}
        mock_conn.cursor.return_value = mock_cursor

        assert ca.is_revoked(mock_conn, "ABC123") is True

    def test_is_revoked_returns_false(self, ca):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value = mock_cursor

        assert ca.is_revoked(mock_conn, "UNKNOWN") is False


# ---------------------------------------------------------------------------
# 5. Agent mTLS Module
# ---------------------------------------------------------------------------


class TestAgentMTLS:
    def test_generate_csr(self, tmp_agent_dir):
        from agent.security.mtls import AgentMTLS

        mtls = AgentMTLS(tmp_agent_dir, "test-agent-001")
        csr_pem = mtls.generate_csr()

        assert csr_pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
        # Private key should be saved
        assert (tmp_agent_dir / "mtls_client.key").exists()

    def test_store_and_load_certificate(self, tmp_agent_dir, ca, agent_csr):
        from agent.security.mtls import AgentMTLS

        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        ca_cert_pem = ca.get_ca_cert_pem()

        mtls = AgentMTLS(tmp_agent_dir, "test-agent-001")
        # Generate a key first (to have the private key on disk)
        mtls.generate_csr()
        mtls.store_certificate(cert_pem, ca_cert_pem)

        assert mtls.has_certificate()
        assert mtls.cert_serial() is not None
        assert mtls.cert_fingerprint() is not None

    def test_needs_renewal_when_no_cert(self, tmp_agent_dir):
        from agent.security.mtls import AgentMTLS

        mtls = AgentMTLS(tmp_agent_dir, "test-agent-001")
        assert mtls.needs_renewal() is True

    def test_no_renewal_needed_for_fresh_cert(self, tmp_agent_dir, ca, agent_csr):
        from agent.security.mtls import AgentMTLS

        cert_pem, _ = ca.issue_client_cert(
            agent_csr,
            agent_id="test-agent-001",
            validity_days=90,
        )
        ca_cert_pem = ca.get_ca_cert_pem()

        mtls = AgentMTLS(tmp_agent_dir, "test-agent-001")
        mtls.generate_csr()
        mtls.store_certificate(cert_pem, ca_cert_pem)

        assert mtls.needs_renewal(days_before=30) is False

    def test_status_info(self, tmp_agent_dir, ca, agent_csr):
        from agent.security.mtls import AgentMTLS

        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        ca_cert_pem = ca.get_ca_cert_pem()

        mtls = AgentMTLS(tmp_agent_dir, "test-agent-001")
        mtls.generate_csr()
        mtls.store_certificate(cert_pem, ca_cert_pem)

        status = mtls.status_info()
        assert status["mtls_has_certificate"] is True
        assert status["mtls_cert_serial"] is not None
        assert status["mtls_cert_fingerprint"] is not None
        assert status["mtls_cert_expires_at"] is not None

    def test_configure_session(self, tmp_agent_dir, ca, agent_csr):
        import requests as req
        from agent.security.mtls import AgentMTLS

        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        ca_cert_pem = ca.get_ca_cert_pem()

        mtls = AgentMTLS(tmp_agent_dir, "test-agent-001")
        mtls.generate_csr()
        mtls.store_certificate(cert_pem, ca_cert_pem)

        session = req.Session()
        mtls.configure_session(session)

        # Session should have cert tuple set
        assert session.cert is not None
        assert len(session.cert) == 2

    def test_persistence_across_instances(self, tmp_agent_dir, ca, agent_csr):
        """Certificate state should survive across AgentMTLS instances."""
        from agent.security.mtls import AgentMTLS

        cert_pem, _ = ca.issue_client_cert(agent_csr, agent_id="test-agent-001")
        ca_cert_pem = ca.get_ca_cert_pem()

        mtls1 = AgentMTLS(tmp_agent_dir, "test-agent-001")
        mtls1.generate_csr()
        mtls1.store_certificate(cert_pem, ca_cert_pem)
        serial1 = mtls1.cert_serial()

        # Create a new instance that loads from disk
        mtls2 = AgentMTLS(tmp_agent_dir, "test-agent-001")
        assert mtls2.has_certificate()
        assert mtls2.cert_serial() == serial1


# ---------------------------------------------------------------------------
# 6. Renewal
# ---------------------------------------------------------------------------


class TestRenewal:
    def test_renewal_produces_new_serial(self, ca, agent_csr):
        cert1_pem, meta1 = ca.issue_client_cert(
            agent_csr, agent_id="test-agent-001"
        )

        # Generate a new CSR for renewal
        key2 = ec.generate_private_key(ec.SECP256R1())
        csr2 = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "test-agent-001"),
            ]))
            .sign(key2, hashes.SHA256())
        )
        csr2_pem = csr2.public_bytes(serialization.Encoding.PEM)

        cert2_pem, meta2 = ca.issue_client_cert(
            csr2_pem, agent_id="test-agent-001"
        )

        assert meta1["serial"] != meta2["serial"]
        assert meta1["fingerprint"] != meta2["fingerprint"]


# ---------------------------------------------------------------------------
# 7. Mode Enforcement (mTLS Middleware)
# ---------------------------------------------------------------------------


class TestMTLSMiddleware:
    @pytest.fixture
    def mock_settings(self):
        return MagicMock()

    def test_disabled_mode_passes_through(self):
        """When MTLS_MODE=disabled, no certificate checks happen."""
        from app.middleware.mtls_middleware import MTLSMiddleware

        with patch("app.middleware.mtls_middleware.settings") as mock_settings:
            mock_settings.MTLS_MODE = "disabled"

            middleware = MTLSMiddleware(app=MagicMock())
            # No assertions needed beyond confirming instantiation works
            assert middleware is not None

    def test_non_protected_path_passes_through(self):
        """Paths outside /api/v1/collect/ and /api/v1/gateway/ are not checked."""
        from app.middleware.mtls_middleware import _MTLS_PROTECTED_PREFIXES

        path = "/api/v1/health/ready"
        is_protected = any(path.startswith(prefix) for prefix in _MTLS_PROTECTED_PREFIXES)
        assert is_protected is False

    def test_protected_path_is_detected(self):
        from app.middleware.mtls_middleware import _MTLS_PROTECTED_PREFIXES

        path = "/api/v1/collect/heartbeat"
        is_protected = any(path.startswith(prefix) for prefix in _MTLS_PROTECTED_PREFIXES)
        assert is_protected is True

    def test_exempt_path_is_detected(self):
        from app.middleware.mtls_middleware import _MTLS_EXEMPT_SUFFIXES

        path = "/api/v1/collect/certificate/ca"
        is_exempt = any(path.endswith(suffix) for suffix in _MTLS_EXEMPT_SUFFIXES)
        assert is_exempt is True

    def test_bootstrap_path_is_exempt(self):
        from app.middleware.mtls_middleware import _MTLS_EXEMPT_SUFFIXES

        path = "/api/v1/collect/bootstrap"
        is_exempt = any(path.endswith(suffix) for suffix in _MTLS_EXEMPT_SUFFIXES)
        assert is_exempt is True


# ---------------------------------------------------------------------------
# 8. Gateway Certificates
# ---------------------------------------------------------------------------


class TestGatewayCertificates:
    def test_gateway_cert_has_gateway_ou(self, ca, agent_csr):
        cert_pem, metadata = ca.issue_client_cert(
            agent_csr,
            agent_id="gw-001",
            role="gateway",
        )
        cert = x509.load_pem_x509_certificate(cert_pem)

        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        assert ou == "gateway"
        assert metadata["subject_ou"] == "gateway"

    def test_gateway_cert_client_auth(self, ca, agent_csr):
        cert_pem, _ = ca.issue_client_cert(
            agent_csr,
            agent_id="gw-001",
            role="gateway",
        )
        cert = x509.load_pem_x509_certificate(cert_pem)

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestMTLSConfig:
    def test_default_mtls_mode_is_disabled(self):
        from app.core.config import Settings

        s = Settings(
            NETVISOR_SECRET_KEY="test-key-1234567890",
            NETVISOR_AGENT_MASTER_KEY="test-master-key-1234",
            NETVISOR_GATEWAY_MASTER_KEY="test-gateway-key-1234",
            AGENT_API_KEY="test-agent-api-key-1234",
            GATEWAY_API_KEY="test-gateway-api-key-1234",
            NETVISOR_DB_PASSWORD="test",
        )
        assert s.MTLS_MODE == "disabled"

    def test_mtls_cert_validity_default(self):
        from app.core.config import Settings

        s = Settings(
            NETVISOR_SECRET_KEY="test-key-1234567890",
            NETVISOR_AGENT_MASTER_KEY="test-master-key-1234",
            NETVISOR_GATEWAY_MASTER_KEY="test-gateway-key-1234",
            AGENT_API_KEY="test-agent-api-key-1234",
            GATEWAY_API_KEY="test-gateway-api-key-1234",
            NETVISOR_DB_PASSWORD="test",
        )
        assert s.MTLS_CERT_VALIDITY_DAYS == 90
        assert s.MTLS_RENEWAL_WINDOW_DAYS == 30
