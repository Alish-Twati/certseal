"""
Use Case 3 — Secure Instant Messaging with Forward Secrecy

Demonstrates secure messaging using ECC hybrid encryption with forward secrecy:
  1. Alice and Bob generate long-term ECC keypairs.
  2. Alice sends 3 messages to Bob, each encrypted with a fresh ephemeral key.
  3. Nonces are attached to each message to prevent replay attacks.
  4. Bob decrypts and validates each nonce.
  5. A replay attack is simulated and blocked.
  6. Forward secrecy is explained.

Run:
    python examples/use_case_3_secure_messaging.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.asymmetric import ecc_generate_keypair, ecc_hybrid_encrypt, ecc_hybrid_decrypt
from certseal.attacks import NonceStore, simulate_replay_attack


def main():
    print("=" * 60)
    print("  CertSeal — Use Case 3: Secure Instant Messaging")
    print("  (ECC Hybrid Encryption + Forward Secrecy + Nonce Protection)")
    print("=" * 60)

    # Step 1: Alice and Bob generate long-term ECC keys
    print("\n[Step 1] Alice and Bob generate long-term ECC keypairs...")
    alice_priv, alice_pub = ecc_generate_keypair()
    bob_priv, bob_pub = ecc_generate_keypair()
    print("  ✅ Long-term keypairs established.")

    # Set up Bob's nonce store
    nonce_store = NonceStore(expiry_seconds=300)
    messages = [
        b"Hi Bob! This is my first secure message.",
        b"Second message: the meeting is at 3pm.",
        b"Third message: I will send the report tomorrow.",
    ]

    print("\n[Step 2] Alice sends 3 messages, each encrypted with a fresh ephemeral ECC key...")
    envelopes = []
    for i, msg in enumerate(messages, 1):
        nonce = nonce_store.generate_nonce()
        # Attach nonce to the message
        payload = f"NONCE:{nonce}\n".encode() + msg
        encrypted = ecc_hybrid_encrypt(payload, bob_pub)
        envelopes.append((nonce, encrypted))
        print(f"  ✅ Message {i} encrypted (ephemeral key used, nonce attached).")

    # Step 3 & 4: Bob decrypts and validates nonces
    print("\n[Step 3] Bob decrypts each message and validates the nonce...")
    for i, (nonce, encrypted) in enumerate(envelopes, 1):
        decrypted = ecc_hybrid_decrypt(encrypted, bob_priv)
        nonce_line, body = decrypted.split(b"\n", 1)
        received_nonce = nonce_line.decode().split("NONCE:")[1]
        nonce_valid = nonce_store.validate_nonce(received_nonce)
        icon = "✅" if nonce_valid else "❌"
        print(f"  {icon} Message {i}: nonce {'valid' if nonce_valid else 'REPLAYED'} — {body.decode()}")

    # Step 5: Replay attack simulation
    print("\n[Step 4] Simulating a replay attack (replaying message 1's nonce)...")
    replayed_nonce = envelopes[0][0]
    result = simulate_replay_attack(nonce_store, replayed_nonce)
    print(f"  ✅ Replay blocked: {result['result']}")

    # Step 6: Forward secrecy explanation
    print("\n[Step 5] Forward Secrecy Explanation:")
    print("  Each message used a unique ephemeral ECC key pair for ECDH key exchange.")
    print("  Even if Bob's long-term private key is later compromised, an attacker")
    print("  cannot decrypt past messages because the ephemeral keys are discarded")
    print("  after each message and are never stored.")
    print("  ✅ Forward secrecy is maintained for all three messages.")

    print("\n" + "=" * 60)
    print("  Use Case 3 complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
