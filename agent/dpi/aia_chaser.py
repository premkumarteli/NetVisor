from __future__ import annotations

import logging
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

logger = logging.getLogger(__name__)

# Default timeout for fetching AIA intermediate certificates
DEFAULT_AIA_TIMEOUT_SECONDS = 10.0


@dataclass
class AiaResolutionResult:
    success: bool
    intermediate_cert: Optional[x509.Certificate] = None
    intermediate_pem: Optional[bytes] = None
    ca_issuers_uri: Optional[str] = None
    error: Optional[str] = None


class AiaChaser:
    """Fetches and cryptographically validates missing intermediate CA certificates

    extracted from leaf certificates via Authority Information Access (AIA).
    """

    def __init__(self, trusted_ca_bundle_path: Optional[str] = None, timeout: float = DEFAULT_AIA_TIMEOUT_SECONDS):
        self.trusted_ca_bundle_path = trusted_ca_bundle_path or certifi.where()
        self.timeout = float(timeout)
        self._domain_intermediate_cache: dict[str, x509.Certificate] = {}
        self._intermediate_pem_cache: dict[str, bytes] = {}

    def extract_ca_issuers_uri(self, cert: x509.Certificate) -> Optional[str]:
        """Extract the caIssuers URI from a certificate's AIA extension."""
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            aia_val = ext.value
            for desc in aia_val:
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    uri = str(desc.access_location.value)
                    if uri.startswith("http://") or uri.startswith("https://"):
                        return uri
        except Exception:
            pass
        return None

    def fetch_intermediate_cert(self, uri: str) -> tuple[Optional[x509.Certificate], Optional[bytes], Optional[str]]:
        """Fetch certificate bytes from a caIssuers URI and parse as X.509 Certificate."""
        try:
            req = urllib.request.Request(
                uri,
                headers={"User-Agent": "NetVisor-AIA-Resolver/1.0", "Accept": "*/*"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()

            if not data:
                return None, None, "Empty response from AIA caIssuers URI"

            # Parse certificate (DER format is standard for AIA caIssuers; fallback to PEM)
            try:
                cert = x509.load_der_x509_certificate(data)
            except Exception:
                cert = x509.load_pem_x509_certificate(data)

            pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
            return cert, pem_bytes, None
        except Exception as exc:
            return None, None, f"Failed to fetch AIA certificate from {uri}: {exc}"

    def verify_intermediate_for_leaf(
        self,
        leaf_cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
    ) -> tuple[bool, Optional[str]]:
        """Cryptographically verifies:

        1. The intermediate certificate signed the leaf certificate.
        2. The intermediate certificate chains to a trusted root in the Mozilla root store.
        """
        # Step 1: Verify issuer/subject DN match
        if leaf_cert.issuer != intermediate_cert.subject:
            return False, f"Issuer mismatch: leaf issuer '{leaf_cert.issuer.rfc4514_string()}' != intermediate subject '{intermediate_cert.subject.rfc4514_string()}'"

        # Step 2: Verify cryptographic signature (intermediate public key -> leaf signature)
        public_key = intermediate_cert.public_key()
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    leaf_cert.signature,
                    leaf_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    leaf_cert.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    leaf_cert.signature,
                    leaf_cert.tbs_certificate_bytes,
                    ec.ECDSA(leaf_cert.signature_hash_algorithm),
                )
            else:
                return False, f"Unsupported public key algorithm: {type(public_key).__name__}"
        except InvalidSignature:
            return False, "Cryptographic signature validation failed: intermediate did not sign the leaf certificate"
        except Exception as exc:
            return False, f"Cryptographic verification error: {exc}"

        # Step 3: Verify intermediate chains to trusted root store
        valid_root, root_err = self._verify_intermediate_against_trusted_roots(intermediate_cert)
        if not valid_root:
            return False, f"Intermediate does not chain to a trusted root: {root_err}"

        return True, None

    def _verify_intermediate_against_trusted_roots(self, intermediate_cert: x509.Certificate) -> tuple[bool, Optional[str]]:
        """Verify that the intermediate certificate chains to a trusted root in certifi bundle."""
        try:
            # We can use cryptography / OpenSSL verification context
            # Load Mozilla CA bundle certificates
            with open(self.trusted_ca_bundle_path, "rb") as f:
                bundle_pem = f.read()

            # Split bundle into individual certificates
            root_certs = []
            for cert_bytes in bundle_pem.split(b"-----END CERTIFICATE-----"):
                if b"-----BEGIN CERTIFICATE-----" in cert_bytes:
                    raw_pem = cert_bytes + b"-----END CERTIFICATE-----\n"
                    try:
                        root_certs.append(x509.load_pem_x509_certificate(raw_pem))
                    except Exception:
                        pass

            # Check if intermediate is self-signed or signed by a root
            matched_root = None
            for root in root_certs:
                if intermediate_cert.issuer == root.subject:
                    # Found candidate issuer root
                    try:
                        root_pk = root.public_key()
                        if isinstance(root_pk, rsa.RSAPublicKey):
                            root_pk.verify(
                                intermediate_cert.signature,
                                intermediate_cert.tbs_certificate_bytes,
                                padding.PKCS1v15(),
                                intermediate_cert.signature_hash_algorithm,
                            )
                        elif isinstance(root_pk, ec.EllipticCurvePublicKey):
                            root_pk.verify(
                                intermediate_cert.signature,
                                intermediate_cert.tbs_certificate_bytes,
                                ec.ECDSA(intermediate_cert.signature_hash_algorithm),
                            )
                        matched_root = root
                        break
                    except Exception:
                        continue

            if matched_root is None:
                return False, f"No trusted root found in CA bundle for issuer '{intermediate_cert.issuer.rfc4514_string()}'"

            return True, None
        except Exception as exc:
            return False, f"Root chain verification failed: {exc}"

    def resolve_and_cache_for_domain(
        self,
        domain: str,
        leaf_cert: x509.Certificate,
    ) -> AiaResolutionResult:
        """Extract AIA, fetch intermediate, cryptographically verify, and cache strictly for domain."""
        domain_key = domain.strip().lower()
        uri = self.extract_ca_issuers_uri(leaf_cert)
        if not uri:
            return AiaResolutionResult(success=False, error=f"No AIA caIssuers URI found on leaf certificate for {domain}")

        intermediate_cert, pem_bytes, fetch_err = self.fetch_intermediate_cert(uri)
        if fetch_err or not intermediate_cert:
            return AiaResolutionResult(success=False, ca_issuers_uri=uri, error=fetch_err)

        is_valid, verify_err = self.verify_intermediate_for_leaf(leaf_cert, intermediate_cert)
        if not is_valid or not pem_bytes:
            logger.warning("[AIA Chaser] Verification failed for AIA cert from %s (domain: %s): %s", uri, domain, verify_err)
            return AiaResolutionResult(success=False, ca_issuers_uri=uri, error=verify_err)

        # Cache strictly scoped to this domain
        self._domain_intermediate_cache[domain_key] = intermediate_cert
        self._intermediate_pem_cache[domain_key] = pem_bytes
        logger.info("[AIA Chaser] Successfully resolved and cached intermediate for %s (AIA: %s)", domain, uri)

        return AiaResolutionResult(
            success=True,
            intermediate_cert=intermediate_cert,
            intermediate_pem=pem_bytes,
            ca_issuers_uri=uri,
        )

    def get_cached_intermediate_pem(self, domain: str) -> Optional[bytes]:
        """Get cached verified intermediate PEM for a specific domain."""
        return self._intermediate_pem_cache.get(domain.strip().lower())

    def get_cached_domains(self) -> list[str]:
        """Return list of domains with healed/cached intermediate chains."""
        return sorted(self._domain_intermediate_cache.keys())
