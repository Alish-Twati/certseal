"""Tests for certseal.attacks — replay attack prevention, MITM prevention, and key strength."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.attacks import NonceStore, CertificatePin, validate_rsa_key_strength, simulate_replay_attack  # noqa: E402
from certseal.asymmetric import rsa_generate_keypair  # noqa: E402
from certseal.pki import generate_ca_certificate, cert_to_pem  # noqa: E402


class TestReplayAttackPrevention:
    """Tests for nonce-based replay attack prevention."""

    def test_nonce_first_use_accepted(self):
        """A freshly generated nonce should be accepted on first use."""
        store = NonceStore()
        nonce = store.generate_nonce()
        assert store.validate_nonce(nonce) is True

    def test_replay_blocked(self):
        """A nonce used a second time should be rejected (replay detected)."""
        store = NonceStore()
        nonce = store.generate_nonce()
        store.validate_nonce(nonce)  # first use
        assert store.validate_nonce(nonce) is False  # replay

    def test_simulate_replay_attack(self):
        """simulate_replay_attack should return attack_success=False."""
        store = NonceStore()
        nonce = store.generate_nonce()
        store.validate_nonce(nonce)  # first use — mark as used
        result = simulate_replay_attack(store, nonce)
        assert result["attack_success"] is False

    def test_different_nonces_accepted(self):
        """Multiple distinct nonces should each be accepted on first use."""
        store = NonceStore()
        nonces = [store.generate_nonce() for _ in range(5)]
        for nonce in nonces:
            assert store.validate_nonce(nonce) is True


class TestMITMPrevention:
    """Tests for certificate pinning as MITM prevention."""

    def setup_method(self):
        """Set up a certificate pin store with a real certificate for secure.example.com."""
        self.pin = CertificatePin()
        priv, _ = rsa_generate_keypair(2048)
        ca = generate_ca_certificate(priv, "Real CA")
        self.real_pem = cert_to_pem(ca)
        self.pin.pin_certificate("secure.example.com", self.real_pem)

        fake_priv, _ = rsa_generate_keypair(2048)
        fake_ca = generate_ca_certificate(fake_priv, "Fake CA")
        self.fake_pem = cert_to_pem(fake_ca)

    def test_real_cert_accepted(self):
        """The pinned certificate should be accepted."""
        assert self.pin.verify_pin("secure.example.com", self.real_pem) is True

    def test_fake_cert_blocked(self):
        """A different certificate for a pinned host should be rejected."""
        assert self.pin.verify_pin("secure.example.com", self.fake_pem) is False

    def test_unregistered_host_blocked(self):
        """Any certificate for a host with no pin should be rejected."""
        assert self.pin.verify_pin("unknown.com", self.real_pem) is False


class TestKeyStrengthValidation:
    """Tests for RSA key strength evaluation."""

    def test_512_bit_insecure(self):
        """512-bit RSA key should be marked as insecure."""
        result = validate_rsa_key_strength(512)
        assert result["secure"] is False

    def test_1024_bit_weak(self):
        """1024-bit RSA key should be marked as insecure (weak)."""
        result = validate_rsa_key_strength(1024)
        assert result["secure"] is False

    def test_2048_bit_acceptable(self):
        """2048-bit RSA key should be marked as secure (acceptable)."""
        result = validate_rsa_key_strength(2048)
        assert result["secure"] is True

    def test_4096_bit_strong(self):
        """4096-bit RSA key should be marked as secure (strong)."""
        result = validate_rsa_key_strength(4096)
        assert result["secure"] is True
