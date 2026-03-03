"""
Keystore module for CertSeal.

Provides PKCS#12 keystore save/load and PEM key import/export utilities.
"""

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption, load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.backends import default_backend


def save_pkcs12(private_key, cert, password: bytes, filepath: str,
                name: bytes = b"certseal-key") -> None:
    """Save a private key and certificate to a PKCS#12 (.p12) file.

    Args:
        private_key: Private key object to store.
        cert: x509.Certificate object to store.
        password: Password bytes used to encrypt the PKCS#12 file.
        filepath: Path where the .p12 file will be written.
        name: Friendly name for the key entry. Defaults to b'certseal-key'.
    """
    p12_data = pkcs12.serialize_key_and_certificates(
        name=name,
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(password)
    )
    with open(filepath, "wb") as f:
        f.write(p12_data)


def load_pkcs12(filepath: str, password: bytes):
    """Load a private key and certificate from a PKCS#12 (.p12) file.

    Args:
        filepath: Path to the .p12 file.
        password: Password bytes used to decrypt the PKCS#12 file.

    Returns:
        Tuple of (private_key, cert) where cert is an x509.Certificate object.
    """
    with open(filepath, "rb") as f:
        p12_data = f.read()
    loaded = pkcs12.load_key_and_certificates(p12_data, password, backend=default_backend())
    private_key = loaded[0]
    cert = loaded[1]
    return private_key, cert


def export_private_key_pem(private_key, password: bytes = None) -> bytes:
    """Export a private key to PEM format (PKCS#8).

    Args:
        private_key: Private key object to export.
        password: Optional password to encrypt the PEM. If None, the key is unencrypted.

    Returns:
        PEM-encoded private key bytes.
    """
    if password:
        encryption = BestAvailableEncryption(password)
    else:
        encryption = NoEncryption()
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )


def export_public_key_pem(public_key) -> bytes:
    """Export a public key to PEM format (SubjectPublicKeyInfo).

    Args:
        public_key: Public key object to export.

    Returns:
        PEM-encoded public key bytes.
    """
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key_pem(pem_data: bytes, password: bytes = None):
    """Load a private key from PEM-encoded bytes.

    Args:
        pem_data: PEM-encoded private key bytes.
        password: Optional password if the PEM is encrypted.

    Returns:
        Private key object.
    """
    return load_pem_private_key(pem_data, password=password, backend=default_backend())


def load_public_key_pem(pem_data: bytes):
    """Load a public key from PEM-encoded bytes.

    Args:
        pem_data: PEM-encoded public key bytes.

    Returns:
        Public key object.
    """
    return load_pem_public_key(pem_data, backend=default_backend())
