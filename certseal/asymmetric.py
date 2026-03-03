"""
Asymmetric encryption module for CertSeal.

Provides RSA (OAEP + hybrid) and ECC (ECDH + HKDF hybrid) encryption/decryption.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from certseal.symmetric import aes_generate_key, aes_encrypt, aes_decrypt


def rsa_generate_keypair(key_size: int = 2048):
    """Generate an RSA key pair.

    Args:
        key_size: Key size in bits (e.g. 2048, 4096). Defaults to 2048.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def rsa_encrypt(plaintext: bytes, public_key) -> bytes:
    """Encrypt plaintext using RSA-OAEP with SHA-256.

    Args:
        plaintext: Data to encrypt. Must fit within RSA key size constraints.
        public_key: RSA public key object.

    Returns:
        Encrypted ciphertext bytes.
    """
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    """Decrypt RSA-OAEP ciphertext.

    Args:
        ciphertext: Encrypted data bytes.
        private_key: RSA private key object.

    Returns:
        Decrypted plaintext bytes.
    """
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_hybrid_encrypt(plaintext: bytes, public_key) -> dict:
    """Encrypt plaintext using RSA hybrid encryption (AES-256 + RSA-OAEP).

    Generates a random AES-256 key, encrypts the plaintext with AES-CBC,
    then encrypts the AES key with RSA-OAEP. This allows encrypting arbitrary
    amounts of data with RSA.

    Args:
        plaintext: Data to encrypt (any length).
        public_key: RSA public key object.

    Returns:
        A dict with keys:
            'encrypted_key' (bytes): AES key encrypted with RSA-OAEP.
            'iv' (bytes): AES initialization vector.
            'ciphertext' (bytes): AES-CBC encrypted data.
    """
    aes_key = aes_generate_key(256)
    aes_result = aes_encrypt(plaintext, aes_key)
    encrypted_key = rsa_encrypt(aes_key, public_key)
    return {
        "encrypted_key": encrypted_key,
        "iv": aes_result["iv"],
        "ciphertext": aes_result["ciphertext"]
    }


def rsa_hybrid_decrypt(encrypted_data: dict, private_key) -> bytes:
    """Decrypt data encrypted with rsa_hybrid_encrypt.

    Args:
        encrypted_data: Dict with 'encrypted_key', 'iv', and 'ciphertext'.
        private_key: RSA private key object.

    Returns:
        Decrypted plaintext bytes.
    """
    aes_key = rsa_decrypt(encrypted_data["encrypted_key"], private_key)
    return aes_decrypt(encrypted_data["ciphertext"], aes_key, encrypted_data["iv"])


def ecc_generate_keypair(curve=None):
    """Generate an ECC key pair.

    Args:
        curve: Elliptic curve instance. Defaults to SECP256R1 (P-256).

    Returns:
        Tuple of (private_key, public_key).
    """
    if curve is None:
        curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve, backend=default_backend())
    return private_key, private_key.public_key()


def ecc_hybrid_encrypt(plaintext: bytes, recipient_public_key) -> dict:
    """Encrypt plaintext using ECC hybrid encryption (ECDH + HKDF + AES-256-CBC).

    Generates an ephemeral ECC key pair, performs ECDH with the recipient's
    public key, derives an AES-256 key via HKDF, and encrypts the plaintext
    with AES-CBC. Each encryption uses a fresh ephemeral key, providing
    forward secrecy.

    Args:
        plaintext: Data to encrypt (any length).
        recipient_public_key: Recipient's ECC public key object.

    Returns:
        A dict with keys:
            'ephemeral_public_key_pem' (bytes): Ephemeral public key in PEM format.
            'iv' (bytes): AES initialization vector.
            'ciphertext' (bytes): AES-CBC encrypted data.
    """
    ephemeral_private_key = ec.generate_private_key(
        recipient_public_key.curve,
        backend=default_backend()
    )
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"certseal-ecc-encryption",
        backend=default_backend()
    ).derive(shared_secret)
    aes_result = aes_encrypt(plaintext, derived_key)
    ephemeral_pub_pem = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "ephemeral_public_key_pem": ephemeral_pub_pem,
        "iv": aes_result["iv"],
        "ciphertext": aes_result["ciphertext"]
    }


def ecc_hybrid_decrypt(encrypted_data: dict, recipient_private_key) -> bytes:
    """Decrypt data encrypted with ecc_hybrid_encrypt.

    Args:
        encrypted_data: Dict with 'ephemeral_public_key_pem', 'iv', and 'ciphertext'.
        recipient_private_key: Recipient's ECC private key object.

    Returns:
        Decrypted plaintext bytes.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    ephemeral_public_key = load_pem_public_key(
        encrypted_data["ephemeral_public_key_pem"],
        backend=default_backend()
    )
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"certseal-ecc-encryption",
        backend=default_backend()
    ).derive(shared_secret)
    return aes_decrypt(encrypted_data["ciphertext"], derived_key, encrypted_data["iv"])
