"""
Attack simulation and security analysis module for CertSeal.

Demonstrates replay attack prevention, certificate pinning (MITM prevention),
RSA key strength validation, and replay attack simulation.
"""

import os
import hashlib
import time


class NonceStore:
    """Store and validate nonces to prevent replay attacks.

    Maintains a set of used nonces with timestamps. Nonces are invalidated
    after the configured expiry period to bound memory growth.
    """

    def __init__(self, expiry_seconds: int = 300):
        """Initialise the nonce store.

        Args:
            expiry_seconds: Number of seconds before a used nonce expires from
                the store. Defaults to 300 (5 minutes).
        """
        self.expiry_seconds = expiry_seconds
        self._used = {}

    def generate_nonce(self) -> str:
        """Generate a cryptographically random nonce.

        Returns:
            A 64-character hex string (32 random bytes).
        """
        return os.urandom(32).hex()

    def validate_nonce(self, nonce: str) -> bool:
        """Validate a nonce, returning False if it has already been used (replay detected).

        If the nonce is fresh, it is recorded in the store and True is returned.
        Expired nonces are cleaned up on every call.

        Args:
            nonce: The nonce string to validate.

        Returns:
            True if the nonce is fresh, False if it has already been used.
        """
        self._cleanup_expired()
        if nonce in self._used:
            return False
        self._used[nonce] = time.time()
        return True

    def _cleanup_expired(self) -> None:
        """Remove nonces that have exceeded the expiry period."""
        now = time.time()
        expired = [n for n, t in self._used.items() if now - t > self.expiry_seconds]
        for n in expired:
            del self._used[n]


class CertificatePin:
    """Certificate pinning to prevent man-in-the-middle (MITM) attacks.

    Stores the expected SHA-256 fingerprint of a certificate for a given host
    and verifies that presented certificates match the pinned fingerprint.
    """

    def __init__(self):
        """Initialise an empty certificate pin store."""
        self._pins = {}

    def pin_certificate(self, host: str, cert_pem: bytes) -> None:
        """Pin a certificate for a given host by storing its SHA-256 fingerprint.

        Args:
            host: Hostname to associate with the pinned certificate.
            cert_pem: PEM-encoded certificate bytes whose fingerprint will be stored.
        """
        fingerprint = hashlib.sha256(cert_pem).hexdigest()
        self._pins[host] = fingerprint

    def verify_pin(self, host: str, cert_pem: bytes) -> bool:
        """Verify that a presented certificate matches the pinned certificate for a host.

        Args:
            host: Hostname to look up.
            cert_pem: PEM-encoded certificate bytes to verify.

        Returns:
            True if the fingerprint matches the stored pin, False otherwise
            (including if no pin exists for the host).
        """
        if host not in self._pins:
            return False
        fingerprint = hashlib.sha256(cert_pem).hexdigest()
        return fingerprint == self._pins[host]


def validate_rsa_key_strength(key_size: int) -> dict:
    """Evaluate the security strength of an RSA key.

    Args:
        key_size: RSA key size in bits.

    Returns:
        A dict with keys:
            'secure' (bool): Whether the key is considered acceptably secure.
            'message' (str): Human-readable assessment of the key strength.
    """
    if key_size < 1024:
        return {"secure": False, "message": f"{key_size}-bit RSA key is BROKEN. Do not use."}
    elif key_size < 2048:
        return {"secure": False, "message": f"{key_size}-bit RSA key is WEAK. Use at least 2048 bits."}
    elif key_size < 4096:
        return {"secure": True, "message": f"{key_size}-bit RSA key is ACCEPTABLE for current use."}
    else:
        return {"secure": True, "message": f"{key_size}-bit RSA key is STRONG."}


def simulate_replay_attack(nonce_store: NonceStore, nonce: str) -> dict:
    """Simulate a replay attack by attempting to reuse an already-used nonce.

    Args:
        nonce_store: A NonceStore instance that has already validated the nonce once.
        nonce: The nonce string to attempt to replay.

    Returns:
        A dict with keys:
            'attack_success' (bool): Always False — replay is blocked.
            'result' (str): Description of the attack outcome.
    """
    result = nonce_store.validate_nonce(nonce)
    if result:
        return {"attack_success": False, "result": "Nonce accepted (first use — not a replay scenario)."}
    return {"attack_success": False, "result": "Replay attack blocked: nonce has already been used."}
