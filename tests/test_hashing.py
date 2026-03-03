"""Tests for certseal.hashing — SHA-256, SHA-512, salted hash, and verification."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.hashing import sha256_hash, sha512_hash, verify_hash, salted_hash  # noqa: E402


class TestHashing:
    """Tests for hashing functions."""

    def test_sha256_known_value(self):
        """SHA-256 of b'hello' should match the known digest."""
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert sha256_hash(b"hello") == expected

    def test_sha512_length(self):
        """SHA-512 hex digest should be 128 characters long."""
        digest = sha512_hash(b"hello")
        assert len(digest) == 128

    def test_verify_hash_correct(self):
        """verify_hash should return True for matching data."""
        data = b"test data"
        digest = sha256_hash(data)
        assert verify_hash(data, digest, "sha256") is True

    def test_verify_hash_tampered(self):
        """verify_hash should return False for tampered data."""
        data = b"test data"
        digest = sha256_hash(data)
        assert verify_hash(b"tampered data", digest, "sha256") is False

    def test_salted_hash_different_salts(self):
        """Same data with different salts should produce different hashes."""
        data = b"password"
        r1 = salted_hash(data)
        r2 = salted_hash(data)
        assert r1["hash"] != r2["hash"]

    def test_salted_hash_same_salt(self):
        """Same data and same salt should produce the same hash."""
        data = b"password"
        salt = os.urandom(32)
        r1 = salted_hash(data, salt=salt)
        r2 = salted_hash(data, salt=salt)
        assert r1["hash"] == r2["hash"]
