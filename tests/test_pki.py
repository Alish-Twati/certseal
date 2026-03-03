"""Tests for certseal.pki — CA generation, certificate issuance, validation, and revocation."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.asymmetric import rsa_generate_keypair  # noqa: E402
from certseal.pki import (  # noqa: E402
    generate_ca_certificate, issue_certificate,
    RevocationList, cert_to_pem, cert_from_pem
)


class TestPKI:
    """Tests for PKI certificate operations."""

    def setup_method(self):
        """Create a CA certificate and issue a certificate for Alice before each test."""
        self.ca_priv, self.ca_pub = rsa_generate_keypair(2048)
        self.ca_cert = generate_ca_certificate(self.ca_priv, "CertSeal Test CA")
        self.alice_priv, self.alice_pub = rsa_generate_keypair(2048)
        self.alice_cert = issue_certificate("Alice", self.alice_pub, self.ca_priv, self.ca_cert)

    def test_ca_certificate_created(self):
        """CA certificate should be created successfully."""
        assert self.ca_cert is not None

    def test_issued_certificate_subject(self):
        """Issued certificate should have the correct common name for Alice."""
        cn = self.alice_cert.subject.get_attributes_for_oid(
            __import__("cryptography.x509.oid", fromlist=["NameOID"]).NameOID.COMMON_NAME
        )[0].value
        assert cn == "Alice"

    def test_issued_certificate_issuer_matches_ca(self):
        """Issued certificate issuer should match the CA subject."""
        assert self.alice_cert.issuer == self.ca_cert.subject

    def test_certificate_serialization(self):
        """A certificate serialised to PEM and back should be equal to the original."""
        pem = cert_to_pem(self.alice_cert)
        loaded = cert_from_pem(pem)
        assert loaded.serial_number == self.alice_cert.serial_number

    def test_revocation(self):
        """A revoked certificate should be detected by the RevocationList."""
        crl = RevocationList()
        crl.revoke(self.alice_cert.serial_number)
        assert crl.is_revoked(self.alice_cert) is True
        assert self.alice_cert.serial_number in crl.list_revoked()
