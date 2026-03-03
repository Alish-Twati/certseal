"""Tests for certseal.signatures — RSA-PSS and ECDSA sign/verify with multi-user scenarios."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.asymmetric import rsa_generate_keypair, ecc_generate_keypair  # noqa: E402
from certseal.signatures import rsa_sign, rsa_verify, ecdsa_sign, ecdsa_verify  # noqa: E402


class TestRSASignatures:
    """Tests for RSA-PSS signatures with multiple simulated users."""

    def setup_method(self):
        """Generate RSA-2048 keypairs for Alice and Bob before each test."""
        self.alice_priv, self.alice_pub = rsa_generate_keypair(2048)
        self.bob_priv, self.bob_pub = rsa_generate_keypair(2048)

    def test_alice_signs_bob_verifies(self):
        """Bob should be able to verify a document signed by Alice."""
        document = b"Contract: Alice agrees to pay Bob."
        sig = rsa_sign(document, self.alice_priv)
        assert rsa_verify(document, sig, self.alice_pub) is True

    def test_unauthorized_user_cannot_forge_signature(self):
        """Bob's signature should fail verification against Alice's public key."""
        document = b"Contract: Alice agrees to pay Bob."
        bob_sig = rsa_sign(document, self.bob_priv)
        assert rsa_verify(document, bob_sig, self.alice_pub) is False

    def test_tampered_document_fails_verification(self):
        """A tampered document should fail signature verification."""
        document = b"Original document content."
        sig = rsa_sign(document, self.alice_priv)
        tampered = b"Tampered document content."
        assert rsa_verify(tampered, sig, self.alice_pub) is False

    def test_multiple_users_sign_same_document(self):
        """Alice's and Bob's signatures on the same document should each verify only with their own key."""
        document = b"Joint agreement between Alice and Bob."
        alice_sig = rsa_sign(document, self.alice_priv)
        bob_sig = rsa_sign(document, self.bob_priv)
        assert rsa_verify(document, alice_sig, self.alice_pub) is True
        assert rsa_verify(document, bob_sig, self.bob_pub) is True
        # Cross-verification should fail
        assert rsa_verify(document, alice_sig, self.bob_pub) is False
        assert rsa_verify(document, bob_sig, self.alice_pub) is False


class TestECDSASignatures:
    """Tests for ECDSA signatures."""

    def setup_method(self):
        """Generate ECC keypairs for Alice and Bob before each test."""
        self.alice_priv, self.alice_pub = ecc_generate_keypair()
        self.bob_priv, self.bob_pub = ecc_generate_keypair()

    def test_sign_and_verify(self):
        """An ECDSA signature should verify correctly with the matching public key."""
        data = b"ECDSA test message"
        sig = ecdsa_sign(data, self.alice_priv)
        assert ecdsa_verify(data, sig, self.alice_pub) is True

    def test_wrong_public_key_fails(self):
        """An ECDSA signature should fail verification with a different public key."""
        data = b"ECDSA test message"
        sig = ecdsa_sign(data, self.alice_priv)
        assert ecdsa_verify(data, sig, self.bob_pub) is False
