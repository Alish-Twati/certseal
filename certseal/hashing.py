"""
Hashing module for CertSeal.

Provides SHA-256, SHA-512, file hashing, hash verification, and salted hashing.
"""

import os
import hmac
import hashlib


def sha256_hash(data: bytes) -> str:
    """Compute the SHA-256 hash of data.

    Args:
        data: Bytes to hash.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    return hashlib.sha256(data).hexdigest()


def sha512_hash(data: bytes) -> str:
    """Compute the SHA-512 hash of data.

    Args:
        data: Bytes to hash.

    Returns:
        Hex-encoded SHA-512 digest string.
    """
    return hashlib.sha512(data).hexdigest()


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Compute the hash of a file, streaming it in chunks.

    Args:
        filepath: Path to the file to hash.
        algorithm: Hash algorithm to use ('sha256' or 'sha512'). Defaults to 'sha256'.

    Returns:
        Hex-encoded hash digest string.

    Raises:
        ValueError: If an unsupported algorithm is specified.
        FileNotFoundError: If the file does not exist.
    """
    if algorithm == "sha256":
        h = hashlib.sha256()
    elif algorithm == "sha512":
        h = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'sha256' or 'sha512'.")
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_hash(data: bytes, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify that data matches an expected hash using constant-time comparison.

    Uses hmac.compare_digest to prevent timing attacks.

    Args:
        data: Bytes to verify.
        expected_hash: Expected hex-encoded hash digest.
        algorithm: Hash algorithm ('sha256' or 'sha512'). Defaults to 'sha256'.

    Returns:
        True if the hash matches, False otherwise.

    Raises:
        ValueError: If an unsupported algorithm is specified.
    """
    if algorithm == "sha256":
        actual = sha256_hash(data)
    elif algorithm == "sha512":
        actual = sha512_hash(data)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'sha256' or 'sha512'.")
    return hmac.compare_digest(actual, expected_hash)


def salted_hash(data: bytes, salt: bytes = None, algorithm: str = "sha256") -> dict:
    """Compute a salted hash of data.

    Generates a random 32-byte salt if none is provided. Useful for password storage
    since the salt prevents rainbow-table and dictionary attacks.

    Args:
        data: Bytes to hash.
        salt: Optional salt bytes. If None, a 32-byte random salt is generated.
        algorithm: Hash algorithm ('sha256' or 'sha512'). Defaults to 'sha256'.

    Returns:
        A dict with keys:
            'salt' (bytes): The salt used.
            'hash' (str): Hex-encoded hash of salt + data.

    Raises:
        ValueError: If an unsupported algorithm is specified.
    """
    if salt is None:
        salt = os.urandom(32)
    salted_data = salt + data
    if algorithm == "sha256":
        digest = hashlib.sha256(salted_data).hexdigest()
    elif algorithm == "sha512":
        digest = hashlib.sha512(salted_data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'sha256' or 'sha512'.")
    return {"salt": salt, "hash": digest}
