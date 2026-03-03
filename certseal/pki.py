"""
PKI (Public Key Infrastructure) module for CertSeal.

Provides X.509 certificate generation (CA and end-entity), validation,
certificate revocation, and PEM serialization.
"""

import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_ca_certificate(ca_private_key, common_name: str = "CertSeal Root CA",
                            validity_days: int = 3650) -> x509.Certificate:
    """Generate a self-signed CA (Certificate Authority) certificate.

    Args:
        ca_private_key: Private key for the CA (RSA or ECC).
        common_name: Common name for the CA certificate. Defaults to 'CertSeal Root CA'.
        validity_days: Number of days the certificate is valid. Defaults to 3650 (10 years).

    Returns:
        A self-signed x509.Certificate object with CA:True BasicConstraints.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertSeal"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False
        )
        .sign(ca_private_key, hashes.SHA256(), backend=default_backend())
    )
    return cert


def issue_certificate(subject_name: str, subject_public_key, ca_private_key,
                      ca_cert, validity_days: int = 365) -> x509.Certificate:
    """Issue an end-entity certificate signed by the CA.

    Args:
        subject_name: Common name for the certificate subject.
        subject_public_key: Subject's public key object.
        ca_private_key: CA private key used to sign the certificate.
        ca_cert: CA certificate (used to set the issuer name).
        validity_days: Number of days the certificate is valid. Defaults to 365.

    Returns:
        A signed x509.Certificate object.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertSeal"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256(), backend=default_backend())
    )
    return cert


def validate_certificate(cert, ca_cert) -> dict:
    """Validate a certificate against a CA certificate.

    Checks certificate expiry, issuer match, and cryptographic signature.

    Args:
        cert: The x509.Certificate to validate.
        ca_cert: The CA x509.Certificate used to verify the signature.

    Returns:
        A dict with keys:
            'valid' (bool): Whether the certificate is valid.
            'reason' (str): Human-readable explanation of the result.
    """
    now = datetime.datetime.utcnow()
    if now > cert.not_valid_after:
        return {"valid": False, "reason": "Certificate has expired."}
    if now < cert.not_valid_before:
        return {"valid": False, "reason": "Certificate is not yet valid."}
    if cert.issuer != ca_cert.subject:
        return {"valid": False, "reason": "Issuer does not match CA subject."}
    try:
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except (InvalidSignature, Exception):
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            ca_pub = ca_cert.public_key()
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ECDSA(cert.signature_hash_algorithm)
            )
        except Exception:
            return {"valid": False, "reason": "Certificate signature is invalid."}
    return {"valid": True, "reason": "Certificate is valid."}


class RevocationList:
    """Simple in-memory Certificate Revocation List (CRL).

    Tracks revoked certificate serial numbers and supports checking
    whether a given certificate has been revoked.
    """

    def __init__(self):
        """Initialise an empty revocation list."""
        self._revoked = set()

    def revoke(self, serial_number: int) -> None:
        """Revoke a certificate by its serial number.

        Args:
            serial_number: The integer serial number of the certificate to revoke.
        """
        self._revoked.add(serial_number)

    def is_revoked(self, cert) -> bool:
        """Check whether a certificate has been revoked.

        Args:
            cert: An x509.Certificate object.

        Returns:
            True if the certificate's serial number is in the revocation list, False otherwise.
        """
        return cert.serial_number in self._revoked

    def list_revoked(self) -> list:
        """Return a list of all revoked serial numbers.

        Returns:
            List of integer serial numbers that have been revoked.
        """
        return list(self._revoked)


def cert_to_pem(cert) -> bytes:
    """Serialise a certificate to PEM format.

    Args:
        cert: An x509.Certificate object.

    Returns:
        PEM-encoded certificate bytes.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_from_pem(pem_data: bytes):
    """Deserialise a certificate from PEM format.

    Args:
        pem_data: PEM-encoded certificate bytes.

    Returns:
        An x509.Certificate object.
    """
    return x509.load_pem_x509_certificate(pem_data, backend=default_backend())
