"""
Use Case 2 — Legal Document Signing

Demonstrates multi-party ECDSA document signing:
  1. Alice, Bob, and Charlie each generate ECC keypairs.
  2. All three sign the same legal contract.
  3. All three signatures are verified.
  4. Eve attempts to forge Alice's signature — blocked.
  5. Document tampering is detected.

Run:
    python examples/use_case_2_document_signing.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.asymmetric import ecc_generate_keypair
from certseal.signatures import ecdsa_sign, ecdsa_verify


CONTRACT = (
    b"LEGAL CONTRACT\n\n"
    b"This agreement is entered into between Alice, Bob, and Charlie.\n"
    b"All parties agree to the terms outlined in Schedule A.\n\n"
    b"Signed on: 2026-03-03\n"
    b"Reference: CONTRACT-2026-001\n"
)


def main():
    print("=" * 60)
    print("  CertSeal — Use Case 2: Legal Document Signing")
    print("=" * 60)

    # Step 1: Generate keypairs
    print("\n[Step 1] Generating ECC keypairs for Alice, Bob, and Charlie...")
    alice_priv, alice_pub = ecc_generate_keypair()
    bob_priv, bob_pub = ecc_generate_keypair()
    charlie_priv, charlie_pub = ecc_generate_keypair()
    print("  ✅ All three keypairs generated.")

    # Step 2: All three sign the contract
    print("\n[Step 2] All three parties sign the contract with ECDSA...")
    alice_sig = ecdsa_sign(CONTRACT, alice_priv)
    bob_sig = ecdsa_sign(CONTRACT, bob_priv)
    charlie_sig = ecdsa_sign(CONTRACT, charlie_priv)
    print("  ✅ Alice signed the contract.")
    print("  ✅ Bob signed the contract.")
    print("  ✅ Charlie signed the contract.")

    # Step 3: Verify all signatures
    print("\n[Step 3] Verifying all three signatures...")
    results = {
        "Alice": ecdsa_verify(CONTRACT, alice_sig, alice_pub),
        "Bob": ecdsa_verify(CONTRACT, bob_sig, bob_pub),
        "Charlie": ecdsa_verify(CONTRACT, charlie_sig, charlie_pub),
    }
    for name, valid in results.items():
        icon = "✅" if valid else "❌"
        print(f"  {icon} {name}'s signature: {'VALID' if valid else 'INVALID'}")

    # Step 4: Eve tries to forge Alice's signature using Bob's key
    print("\n[Step 4] Eve attempts to forge Alice's signature using Bob's key...")
    eve_fake_sig = ecdsa_sign(CONTRACT, bob_priv)
    forgery_detected = not ecdsa_verify(CONTRACT, eve_fake_sig, alice_pub)
    if forgery_detected:
        print("  ✅ Forgery detected — Eve's fake signature fails Alice's public key check.")
    else:
        print("  ❌ Forgery not detected (unexpected).")

    # Step 5: Document tampering
    print("\n[Step 5] Attempting to tamper with the contract...")
    tampered = CONTRACT.replace(b"Schedule A", b"Schedule Z [MODIFIED]")
    tamper_detected = not ecdsa_verify(tampered, alice_sig, alice_pub)
    if tamper_detected:
        print("  ✅ Tampering detected — Alice's signature fails on modified document.")
    else:
        print("  ❌ Tampering not detected (unexpected).")

    print("\n" + "=" * 60)
    print("  Use Case 2 complete. Non-repudiation and integrity confirmed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
