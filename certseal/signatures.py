"""
Digital signatures module for CertSeal.

Provides RSA-PSS and ECDSA signing and verification, including file signing.
"""

import base64
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def rsa_sign(data: bytes, private_key) -> bytes:
    """Sign data using RSA-PSS with MGF1+SHA-256 and maximum salt length.

    RSA-PSS is preferred over PKCS1v15 for its probabilistic security properties
    and provable security under the RSA assumption.

    Args:
        data: Bytes to sign.
        private_key: RSA private key object.

    Returns:
        RSA-PSS signature bytes.
    """
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(data: bytes, signature: bytes, public_key) -> bool:
    """Verify an RSA-PSS signature.

    Args:
        data: Original data that was signed.
        signature: RSA-PSS signature bytes.
        public_key: RSA public key object.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def ecdsa_sign(data: bytes, private_key) -> bytes:
    """Sign data using ECDSA with SHA-256.

    Args:
        data: Bytes to sign.
        private_key: ECC private key object.

    Returns:
        ECDSA signature bytes (DER-encoded).
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(data: bytes, signature: bytes, public_key) -> bool:
    """Verify an ECDSA signature.

    Args:
        data: Original data that was signed.
        signature: ECDSA signature bytes (DER-encoded).
        public_key: ECC public key object.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def sign_file(filepath: str, private_key, algorithm: str = "rsa") -> str:
    """Sign the contents of a file.

    Args:
        filepath: Path to the file to sign.
        private_key: Private key object (RSA or ECC depending on algorithm).
        algorithm: Signing algorithm, 'rsa' for RSA-PSS or 'ecdsa' for ECDSA.

    Returns:
        Base64-encoded signature string.

    Raises:
        ValueError: If an unsupported algorithm is specified.
        FileNotFoundError: If the file does not exist.
    """
    with open(filepath, "rb") as f:
        data = f.read()
    if algorithm == "rsa":
        sig = rsa_sign(data, private_key)
    elif algorithm == "ecdsa":
        sig = ecdsa_sign(data, private_key)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'rsa' or 'ecdsa'.")
    return base64.b64encode(sig).decode("utf-8")


def verify_file_signature(filepath: str, signature_b64: str, public_key, algorithm: str = "rsa") -> bool:
    """Verify the signature of a file.

    Args:
        filepath: Path to the file whose signature is to be verified.
        signature_b64: Base64-encoded signature string.
        public_key: Public key object (RSA or ECC depending on algorithm).
        algorithm: Signing algorithm, 'rsa' for RSA-PSS or 'ecdsa' for ECDSA.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ValueError: If an unsupported algorithm is specified.
    """
    with open(filepath, "rb") as f:
        data = f.read()
    signature = base64.b64decode(signature_b64)
    if algorithm == "rsa":
        return rsa_verify(data, signature, public_key)
    elif algorithm == "ecdsa":
        return ecdsa_verify(data, signature, public_key)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'rsa' or 'ecdsa'.")
