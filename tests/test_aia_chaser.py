import datetime
import os
import time
from unittest.mock import MagicMock, patch
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from agent.dpi.aia_chaser import AiaChaser
from agent.dpi.mitm_addon import NetVisorDpiAddon


def _generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _create_cert(subject_name, issuer_name, issuer_key, subject_key, is_ca=False, aia_uri=None):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
    builder = builder.public_key(subject_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now - datetime.timedelta(days=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=365))

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

    if aia_uri:
        desc = x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(aia_uri),
        )
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([desc]),
            critical=False,
        )

    return builder.sign(issuer_key, hashes.SHA256())


class TestAiaChaser:
    @pytest.fixture
    def cert_chain(self, tmp_path):
        root_key = _generate_rsa_key()
        root_cert = _create_cert("Test Trusted Root CA", "Test Trusted Root CA", root_key, root_key, is_ca=True)

        inter_key = _generate_rsa_key()
        inter_cert = _create_cert("Test Intermediate CA", "Test Trusted Root CA", root_key, inter_key, is_ca=True)

        leaf_key = _generate_rsa_key()
        leaf_cert = _create_cert(
            "test.example.gov",
            "Test Intermediate CA",
            inter_key,
            leaf_key,
            is_ca=False,
            aia_uri="http://pki.example.gov/certs/inter.crt",
        )

        bundle_path = tmp_path / "trusted_roots.pem"
        bundle_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

        return {
            "root_cert": root_cert,
            "inter_cert": inter_cert,
            "leaf_cert": leaf_cert,
            "root_key": root_key,
            "inter_key": inter_key,
            "leaf_key": leaf_key,
            "bundle_path": str(bundle_path),
        }

    def test_extract_ca_issuers_uri(self, cert_chain):
        chaser = AiaChaser(trusted_ca_bundle_path=cert_chain["bundle_path"])
        uri = chaser.extract_ca_issuers_uri(cert_chain["leaf_cert"])
        assert uri == "http://pki.example.gov/certs/inter.crt"

        no_aia_cert = cert_chain["inter_cert"]
        assert chaser.extract_ca_issuers_uri(no_aia_cert) is None

    def test_verify_intermediate_for_leaf_success(self, cert_chain):
        chaser = AiaChaser(trusted_ca_bundle_path=cert_chain["bundle_path"])
        valid, err = chaser.verify_intermediate_for_leaf(cert_chain["leaf_cert"], cert_chain["inter_cert"])
        assert valid is True
        assert err is None

    def test_verify_intermediate_rejects_unrelated_cert(self, cert_chain):
        # Generate an unrelated certificate (e.g. valid cert for another domain/CA)
        unrelated_key = _generate_rsa_key()
        unrelated_cert = _create_cert("Unrelated CA", "Unrelated CA", unrelated_key, unrelated_key, is_ca=True)

        chaser = AiaChaser(trusted_ca_bundle_path=cert_chain["bundle_path"])
        valid, err = chaser.verify_intermediate_for_leaf(cert_chain["leaf_cert"], unrelated_cert)
        assert valid is False
        assert "Issuer mismatch" in str(err) or "Cryptographic signature validation failed" in str(err)

    def test_verify_intermediate_rejects_tampered_signature(self, cert_chain):
        # Intermediate has matching Subject DN but wrong key (cannot verify leaf signature)
        fake_inter_key = _generate_rsa_key()
        fake_inter_cert = _create_cert("Test Intermediate CA", "Test Trusted Root CA", cert_chain["root_key"], fake_inter_key, is_ca=True)

        chaser = AiaChaser(trusted_ca_bundle_path=cert_chain["bundle_path"])
        valid, err = chaser.verify_intermediate_for_leaf(cert_chain["leaf_cert"], fake_inter_cert)
        assert valid is False
        assert "signature validation failed" in str(err)

    def test_verify_intermediate_rejects_untrusted_root_chain(self, cert_chain, tmp_path):
        # Intermediate signed the leaf, but intermediate chains to a rogue untrusted root
        rogue_root_key = _generate_rsa_key()
        rogue_root_cert = _create_cert("Rogue Root CA", "Rogue Root CA", rogue_root_key, rogue_root_key, is_ca=True)

        rogue_inter_key = _generate_rsa_key()
        rogue_inter_cert = _create_cert("Test Intermediate CA", "Rogue Root CA", rogue_root_key, rogue_inter_key, is_ca=True)

        leaf_key = _generate_rsa_key()
        rogue_leaf = _create_cert("test.example.gov", "Test Intermediate CA", rogue_inter_key, leaf_key, is_ca=False)

        # chaser only trusts cert_chain["bundle_path"] (which does not have Rogue Root CA)
        chaser = AiaChaser(trusted_ca_bundle_path=cert_chain["bundle_path"])
        valid, err = chaser.verify_intermediate_for_leaf(rogue_leaf, rogue_inter_cert)
        assert valid is False
        assert "No trusted root found" in str(err) or "Intermediate does not chain to a trusted root" in str(err)

    def test_resolve_and_cache_for_domain_scoped_strictly(self, cert_chain):
        chaser = AiaChaser(trusted_ca_bundle_path=cert_chain["bundle_path"])
        inter_der = cert_chain["inter_cert"].public_bytes(serialization.Encoding.DER)

        with patch.object(chaser, "fetch_intermediate_cert", return_value=(cert_chain["inter_cert"], cert_chain["inter_cert"].public_bytes(serialization.Encoding.PEM), None)):
            res = chaser.resolve_and_cache_for_domain("test.example.gov", cert_chain["leaf_cert"])
            assert res.success is True
            assert chaser.get_cached_domains() == ["test.example.gov"]
            assert chaser.get_cached_intermediate_pem("test.example.gov") is not None
            # Other domains do not inherit this intermediate
            assert chaser.get_cached_intermediate_pem("other.example.com") is None


class TestNetVisorDpiAddonFailOpenTracker:
    def test_tls_failed_server_sets_fail_open_ttl_and_backoff(self):
        addon = NetVisorDpiAddon()
        tls_data = MagicMock()
        tls_data.conn.sni = "broken.example.gov"
        tls_data.conn.error = "certificate verify failed: unable to get local issuer certificate"

        # Failure 1: 300s TTL (5m)
        addon.tls_failed_server(tls_data)
        tracker = addon._upstream_fail_open_tracker["broken.example.gov"]
        assert tracker["consecutive_failures"] == 1
        assert tracker["status"] == "recovering"
        assert tracker["expires_at"] > time.time() + 290

        # Failure 2: 900s TTL (15m)
        addon.tls_failed_server(tls_data)
        tracker = addon._upstream_fail_open_tracker["broken.example.gov"]
        assert tracker["consecutive_failures"] == 2
        assert tracker["status"] == "recovering"

        # Failure 3: 1800s TTL (30m) -> Escalates to persistently_failing
        addon.tls_failed_server(tls_data)
        tracker = addon._upstream_fail_open_tracker["broken.example.gov"]
        assert tracker["consecutive_failures"] == 3
        assert tracker["status"] == "persistently_failing"

    def test_tls_clienthello_ignores_connection_during_active_ttl(self):
        addon = NetVisorDpiAddon()
        addon._upstream_fail_open_tracker["broken.example.gov"] = {
            "error": "unable to get local issuer certificate",
            "failed_at": time.time(),
            "expires_at": time.time() + 300,
            "consecutive_failures": 1,
            "status": "recovering",
        }

        hello_data = MagicMock()
        hello_data.client_hello.sni = "broken.example.gov"
        hello_data.ignore_connection = False

        addon.tls_clienthello(hello_data)
        assert hello_data.ignore_connection is True

    def test_tls_clienthello_evicts_expired_entry_for_reverification(self):
        addon = NetVisorDpiAddon()
        # Expired TTL entry
        addon._upstream_fail_open_tracker["broken.example.gov"] = {
            "error": "unable to get local issuer certificate",
            "failed_at": time.time() - 400,
            "expires_at": time.time() - 10,
            "consecutive_failures": 1,
            "status": "recovering",
        }

        hello_data = MagicMock()
        hello_data.client_hello.sni = "broken.example.gov"
        hello_data.ignore_connection = False

        addon.tls_clienthello(hello_data)
        # Entry evicted, not ignored -> triggers full upstream verification retry
        assert hello_data.ignore_connection is False
        assert "broken.example.gov" not in addon._upstream_fail_open_tracker

    def test_server_connect_error_records_in_fail_open_tracker(self):
        addon = NetVisorDpiAddon()
        connect_data = MagicMock()
        connect_data.server.address = ("timeout.example.com", 443)
        connect_data.server.error = "Connection timed out"

        addon.server_connect_error(connect_data)
        assert "timeout.example.com" in addon._upstream_fail_open_tracker
        tracker = addon._upstream_fail_open_tracker["timeout.example.com"]
        assert tracker["error"] == "Connection timed out"
        assert tracker["consecutive_failures"] == 1
