"""
Symmetric encryption module for CertSeal.

Provides AES-256-CBC and DES encryption/decryption using the cryptography library.
DES is included for educational purposes only to demonstrate legacy algorithm weaknesses.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def aes_generate_key(key_size: int = 256) -> bytes:
    """Generate a random AES key.

    Args:
        key_size: Key size in bits. Must be 128, 192, or 256.

    Returns:
        Random bytes of the appropriate length for the key size.

    Raises:
        ValueError: If key_size is not 128, 192, or 256.
    """
    if key_size not in (128, 192, 256):
        raise ValueError(f"Invalid AES key size: {key_size}. Must be 128, 192, or 256.")
    return os.urandom(key_size // 8)


def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """Encrypt plaintext using AES-CBC with PKCS7 padding.

    Args:
        plaintext: The data to encrypt.
        key: AES key (16, 24, or 32 bytes for AES-128/192/256).

    Returns:
        A dict with keys 'iv' (bytes) and 'ciphertext' (bytes).
    """
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {"iv": iv, "ciphertext": ciphertext}


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-CBC ciphertext with PKCS7 unpadding.

    Args:
        ciphertext: The encrypted data.
        key: AES key (16, 24, or 32 bytes).
        iv: Initialization vector (16 bytes).

    Returns:
        Decrypted plaintext bytes.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def des_generate_key() -> bytes:
    """Generate a random DES key (8 bytes).

    WARNING: DES is a broken legacy cipher with only 56-bit effective security.
    It is included here for EDUCATIONAL PURPOSES ONLY to demonstrate how outdated
    algorithms work and why they should never be used in modern applications.
    Use AES-256 for any real security requirement.

    Returns:
        8 random bytes representing the DES key.
    """
    return os.urandom(8)


def des_encrypt(plaintext: bytes, key: bytes) -> dict:
    """Encrypt plaintext simulating DES using Triple DES API (key * 3) in CBC mode.

    WARNING: DES is broken. This function is for EDUCATIONAL USE ONLY.
    The TripleDES cipher is used with the same 8-byte key repeated three times
    to simulate single-DES behaviour through the Triple DES API.

    Args:
        plaintext: The data to encrypt.
        key: 8-byte DES key.

    Returns:
        A dict with keys 'iv' (bytes) and 'ciphertext' (bytes).
    """
    iv = os.urandom(8)
    padder = padding.PKCS7(64).padder()
    padded = padder.update(plaintext) + padder.finalize()
    triple_key = key * 3
    cipher = Cipher(algorithms.TripleDES(triple_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {"iv": iv, "ciphertext": ciphertext}


def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt ciphertext that was encrypted with des_encrypt.

    WARNING: DES is broken. This function is for EDUCATIONAL USE ONLY.

    Args:
        ciphertext: The encrypted data.
        key: 8-byte DES key.
        iv: Initialization vector (8 bytes).

    Returns:
        Decrypted plaintext bytes.
    """
    triple_key = key * 3
    cipher = Cipher(algorithms.TripleDES(triple_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
