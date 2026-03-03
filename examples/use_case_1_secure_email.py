"""
Use Case 1 — Secure Email Communication

Demonstrates how CertSeal can be used to simulate secure email:
  1. Alice and Bob generate RSA-2048 keypairs.
  2. Alice signs the email with her private key (RSA-PSS).
  3. Alice encrypts the email with Bob's public key (RSA hybrid).
  4. Bob decrypts the email with his private key.
  5. Bob verifies Alice's signature.
  6. Tamper detection is demonstrated.

Run:
    python examples/use_case_1_secure_email.py
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from certseal.asymmetric import rsa_generate_keypair, rsa_hybrid_encrypt, rsa_hybrid_decrypt
from certseal.signatures import rsa_sign, rsa_verify


def main():
    print("=" * 60)
    print("  CertSeal — Use Case 1: Secure Email Communication")
    print("=" * 60)

    # Step 1: Generate keypairs
    print("\n[Step 1] Generating RSA-2048 keypairs for Alice and Bob...")
    alice_priv, alice_pub = rsa_generate_keypair(2048)
    bob_priv, bob_pub = rsa_generate_keypair(2048)
    print("  ✅ Alice's keypair generated.")
    print("  ✅ Bob's keypair generated.")

    # Step 2: Alice writes and signs the email
    email = (
        b"Subject: Quarterly Report\n\n"
        b"Hi Bob,\n\n"
        b"Please find attached the Q1 report. All figures are final.\n\n"
        b"Regards, Alice"
    )
    print("\n[Step 2] Alice signs the email with her RSA-PSS private key...")
    signature = rsa_sign(email, alice_priv)
    print(f"  ✅ Signature created ({len(signature)} bytes).")

    # Step 3: Alice encrypts the email for Bob
    print("\n[Step 3] Alice encrypts the email using Bob's public key (RSA Hybrid)...")
    encrypted = rsa_hybrid_encrypt(email, bob_pub)
    print(f"  ✅ Email encrypted (ciphertext: {len(encrypted['ciphertext'])} bytes).")

    # Step 4: Bob decrypts the email
    print("\n[Step 4] Bob decrypts the email with his private key...")
    decrypted = rsa_hybrid_decrypt(encrypted, bob_priv)
    assert decrypted == email
    print("  ✅ Email decrypted successfully.")
    print(f"\n  --- Decrypted Email ---\n{decrypted.decode()}\n  -----------------------")

    # Step 5: Bob verifies Alice's signature
    print("\n[Step 5] Bob verifies Alice's signature...")
    valid = rsa_verify(decrypted, signature, alice_pub)
    if valid:
        print("  ✅ Signature VALID — email is authentic and from Alice.")
    else:
        print("  ❌ Signature INVALID — email may have been tampered with.")

    # Step 6: Tamper detection
    print("\n[Step 6] Demonstrating tamper detection...")
    tampered = decrypted.replace(b"Q1 report", b"Q2 report [FORGED]")
    tamper_valid = rsa_verify(tampered, signature, alice_pub)
    if not tamper_valid:
        print("  ✅ Tamper detected — forged email signature is INVALID.")
    else:
        print("  ❌ Tamper NOT detected (unexpected).")

    print("\n" + "=" * 60)
    print("  Use Case 1 complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
