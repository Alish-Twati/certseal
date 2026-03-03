"""Tests for certseal.symmetric — AES and DES encryption."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest  # noqa: E402

from certseal.symmetric import (  # noqa: E402
    aes_generate_key, aes_encrypt, aes_decrypt,
    des_generate_key, des_encrypt, des_decrypt
)


class TestAES:
    """Tests for AES-256-CBC encryption and decryption."""

    def test_key_generation_256(self):
        """AES-256 key should be 32 bytes."""
        key = aes_generate_key(256)
        assert len(key) == 32

    def test_key_generation_128(self):
        """AES-128 key should be 16 bytes."""
        key = aes_generate_key(128)
        assert len(key) == 16

    def test_invalid_key_size(self):
        """Non-standard key size should raise ValueError."""
        with pytest.raises(ValueError):
            aes_generate_key(512)

    def test_encrypt_decrypt_roundtrip(self):
        """Decrypting an encrypted message should recover the original plaintext."""
        plaintext = b"Hello, CertSeal!"
        key = aes_generate_key(256)
        result = aes_encrypt(plaintext, key)
        recovered = aes_decrypt(result["ciphertext"], key, result["iv"])
        assert recovered == plaintext

    def test_different_plaintexts_produce_different_ciphertexts(self):
        """Different plaintexts encrypted with the same key should yield different ciphertexts."""
        key = aes_generate_key(256)
        r1 = aes_encrypt(b"message one", key)
        r2 = aes_encrypt(b"message two", key)
        assert r1["ciphertext"] != r2["ciphertext"]

    def test_iv_is_unique(self):
        """Two encryptions of the same data should produce different IVs."""
        key = aes_generate_key(256)
        plaintext = b"same data"
        r1 = aes_encrypt(plaintext, key)
        r2 = aes_encrypt(plaintext, key)
        assert r1["iv"] != r2["iv"]


class TestDES:
    """Tests for DES (educational) encryption and decryption."""

    def test_key_generation(self):
        """DES key should be 8 bytes."""
        key = des_generate_key()
        assert len(key) == 8

    def test_encrypt_decrypt_roundtrip(self):
        """Decrypting a DES-encrypted message should recover the original plaintext."""
        plaintext = b"DES test!"
        key = des_generate_key()
        result = des_encrypt(plaintext, key)
        recovered = des_decrypt(result["ciphertext"], key, result["iv"])
        assert recovered == plaintext
