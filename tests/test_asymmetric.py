"""Tests for certseal.asymmetric — RSA and ECC hybrid encryption."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest  # noqa: E402

from certseal.asymmetric import (  # noqa: E402
    rsa_generate_keypair, rsa_encrypt, rsa_decrypt,
    rsa_hybrid_encrypt, rsa_hybrid_decrypt,
    ecc_generate_keypair, ecc_hybrid_encrypt, ecc_hybrid_decrypt
)


class TestRSA:
    """Tests for RSA key generation and hybrid encryption."""

    def setup_method(self):
        """Generate a 2048-bit RSA keypair before each test."""
        self.priv, self.pub = rsa_generate_keypair(2048)

    def test_keypair_generation(self):
        """Generated RSA keypair should have private and public keys."""
        assert self.priv is not None
        assert self.pub is not None

    def test_encrypt_decrypt(self):
        """RSA-OAEP encrypt/decrypt roundtrip should recover the original plaintext."""
        plaintext = b"secret"
        ciphertext = rsa_encrypt(plaintext, self.pub)
        recovered = rsa_decrypt(ciphertext, self.priv)
        assert recovered == plaintext

    def test_wrong_key_fails(self):
        """Decrypting with the wrong private key should raise an exception."""
        plaintext = b"secret"
        ciphertext = rsa_encrypt(plaintext, self.pub)
        other_priv, _ = rsa_generate_keypair(2048)
        with pytest.raises(Exception):
            rsa_decrypt(ciphertext, other_priv)

    def test_hybrid_encrypt_decrypt(self):
        """RSA hybrid encrypt/decrypt should handle long plaintexts correctly."""
        plaintext = b"A" * 100
        result = rsa_hybrid_encrypt(plaintext, self.pub)
        recovered = rsa_hybrid_decrypt(result, self.priv)
        assert recovered == plaintext


class TestECC:
    """Tests for ECC keypair generation and hybrid encryption."""

    def setup_method(self):
        """Generate an ECC keypair before each test."""
        self.priv, self.pub = ecc_generate_keypair()

    def test_keypair_generation(self):
        """Generated ECC keypair should have private and public keys."""
        assert self.priv is not None
        assert self.pub is not None

    def test_hybrid_encrypt_decrypt(self):
        """ECC hybrid encrypt/decrypt should recover the original plaintext."""
        plaintext = b"ECC message"
        result = ecc_hybrid_encrypt(plaintext, self.pub)
        recovered = ecc_hybrid_decrypt(result, self.priv)
        assert recovered == plaintext

    def test_wrong_key_fails(self):
        """Decrypting with the wrong ECC private key should raise an exception."""
        plaintext = b"ECC message"
        result = ecc_hybrid_encrypt(plaintext, self.pub)
        other_priv, _ = ecc_generate_keypair()
        with pytest.raises(Exception):
            ecc_hybrid_decrypt(result, other_priv)
