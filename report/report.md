# CertSeal: Design and Development of an Open-Source PKI Cryptographic Tool

**Module:** ST6051CEM Practical Cryptography
**Institution:** Softwarica College of IT and E-Commerce / Coventry University
**Student:** Alish Twati
**Date:** March 2026

---

## 1. Introduction

Modern networked systems face relentless cryptographic threats: data interception, impersonation, message forgery, and the gradual obsolescence of legacy algorithms. As organisations increasingly rely on digital communication for everything from legal contracts to financial transactions, the need to understand and correctly apply cryptographic primitives has never been more pressing. Despite the availability of mature tools such as OpenSSL and well-documented standards from NIST, a gap persists between theoretical cryptographic knowledge and practical implementation. Many existing educational platforms visualise algorithms without producing real, testable cryptographic output.

CertSeal was designed to close that gap. It is an open-source Python-based PKI (Public Key Infrastructure) tool that allows a practitioner or student to generate keys, encrypt data, produce and verify digital signatures, issue X.509 certificates, and simulate real-world attacks — all from a single unified tool. The project is inspired by the [CrypTool Project](https://www.cryptool.org), a well-established e-learning platform for cryptography. Where CrypTool focuses primarily on algorithm visualisation, CertSeal produces functionally correct cryptographic artefacts that interoperate with the Python `cryptography` library and real-world PKI infrastructure.

This report documents the cryptographic algorithms chosen and their rationale, the security features built into the tool, three practical use case demonstrations, implementation challenges encountered, and reflections on what the development process revealed about the gap between cryptographic theory and practice.

---

## 2. Cryptographic Techniques and Algorithms

### 2.1 Symmetric Encryption: AES-256-CBC and DES

The primary symmetric cipher in CertSeal is AES-256-CBC. AES (Advanced Encryption Standard) was standardised by NIST in 2001 as FIPS 197 and remains the globally recommended symmetric block cipher for protecting data at rest and in transit. I chose the 256-bit variant because it offers the highest security margin among the three permitted key sizes (128, 192, 256 bits), making it resistant to brute-force attacks for the foreseeable future.

AES operates on 128-bit (16-byte) blocks. In Cipher Block Chaining (CBC) mode, each plaintext block is XORed with the previous ciphertext block before encryption. This means that identical plaintext blocks will produce different ciphertext blocks, provided the IV is unique — which CertSeal guarantees by generating a fresh 16-byte random IV for every encryption call. PKCS7 padding is applied to ensure the plaintext length is a multiple of the block size. In `certseal/symmetric.py`, the `aes_encrypt` function returns both the IV and ciphertext as a dictionary so that the caller can transmit or store them together.

DES (Data Encryption Standard) is included in CertSeal strictly for educational purposes. With an effective key length of only 56 bits, DES was demonstrated to be practically breakable by brute force as early as 1998 by the EFF DES Cracker. I implemented DES using the TripleDES API from the `cryptography` library with the same 8-byte key repeated three times (`key * 3`), simulating single-DES behaviour through the Triple DES code path. The functions carry explicit `WARNING` docstrings making clear that DES must never be used in real deployments. Its inclusion allows the tool to demonstrate, side by side, why AES superseded DES.

### 2.2 Asymmetric Encryption: RSA-OAEP and ECC Hybrid

RSA is implemented in `certseal/asymmetric.py` using OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 as the hash function and MGF1 as the mask generation function. OAEP is the correct modern padding scheme for RSA encryption; the older PKCS1v15 padding is vulnerable to Bleichenbacher-style chosen-ciphertext attacks, which have repeatedly been exploited against real TLS implementations. By choosing OAEP exclusively, CertSeal avoids this class of vulnerability by design.

A key practical limitation of RSA is that the maximum plaintext size that can be encrypted in a single operation is bounded by the key size minus OAEP overhead — approximately 190 bytes for a 2048-bit key with SHA-256. To encrypt arbitrary-length messages, CertSeal uses hybrid encryption in `rsa_hybrid_encrypt`: a random AES-256 session key is generated, the plaintext is encrypted with AES-CBC, and the session key is encrypted with RSA-OAEP. The recipient decrypts the session key with their RSA private key and then decrypts the ciphertext with AES. This pattern is used in every major real-world cryptographic protocol, including TLS and PGP.

For ECC (Elliptic Curve Cryptography), CertSeal uses the P-256 curve (SECP256R1) with Elliptic Curve Diffie-Hellman (ECDH) key exchange. In `ecc_hybrid_encrypt`, an ephemeral ECC key pair is generated for each encryption call. The ephemeral private key performs an ECDH exchange with the recipient's long-term public key, producing a shared secret. This secret is then passed through HKDF (HMAC-based Key Derivation Function) using SHA-256 and the info string `b"certseal-ecc-encryption"` to derive a 32-byte AES-256 session key. The plaintext is then encrypted with AES-CBC.

The critical security property here is **forward secrecy**: because each encryption uses a freshly generated ephemeral key that is discarded immediately, compromising the recipient's long-term private key at some future point does not reveal past messages. The ephemeral public key is serialised to PEM and included in the encrypted envelope so the recipient can perform the matching ECDH operation for decryption.

### 2.3 Hashing: SHA-256 and SHA-512

CertSeal implements SHA-256 and SHA-512 hashing in `certseal/hashing.py` using Python's built-in `hashlib` module. SHA-256 produces a 256-bit (32-byte) digest and SHA-512 produces a 512-bit (64-byte) digest; both are members of the SHA-2 family standardised by NIST in FIPS 180-4.

Both algorithms provide collision resistance (computationally infeasible to find two inputs with the same hash), preimage resistance (infeasible to find an input that produces a given hash), and second preimage resistance. SHA-256 is widely used in certificate fingerprinting, blockchain, and TLS handshakes. SHA-512 provides a larger security margin and is preferred when a wider hash output is desired, for example in high-assurance key derivation contexts.

For hash verification, I deliberately used `hmac.compare_digest` rather than a direct string comparison (`==`). A naive equality check terminates early as soon as a mismatch is found, which can leak information about how many bytes match through timing measurements — a timing side-channel attack. `hmac.compare_digest` compares all bytes in constant time regardless of where the first difference occurs, eliminating this vulnerability.

The `salted_hash` function demonstrates password-storage best practice: a 32-byte random salt is generated and prepended to the data before hashing. Without salting, identical passwords produce identical hashes, which enables precomputed rainbow-table attacks. The salt is returned alongside the hash so it can be stored for later verification.

### 2.4 Digital Signatures: RSA-PSS and ECDSA

Digital signatures provide authentication, integrity, and non-repudiation. CertSeal implements RSA-PSS signatures in `certseal/signatures.py`. PSS (Probabilistic Signature Scheme) is strongly preferred over the older PKCS1v15 signature scheme for the same reasons OAEP is preferred for encryption: PSS has a security proof in the random oracle model, whereas PKCS1v15 signatures do not. The PSS implementation uses MGF1 with SHA-256 and the maximum salt length, which maximises the randomness introduced per signature.

ECDSA (Elliptic Curve Digital Signature Algorithm) is also implemented, using the P-256 curve with SHA-256. ECDSA produces signatures significantly shorter than RSA signatures for equivalent security — a 256-bit ECDSA signature versus a 256-byte RSA-2048 signature — making it more efficient in bandwidth-constrained environments.

In Use Case 2 (document signing), the multi-party ECDSA scenario demonstrates non-repudiation: once Alice, Bob, and Charlie have each signed the contract, none of them can plausibly deny having done so, because only their respective private keys could have produced those signatures.

### 2.5 PKI: X.509 Certificates, CA Hierarchy, and PKCS#12

The `certseal/pki.py` module implements a two-tier PKI using the `cryptography` library's X.509 builder API. `generate_ca_certificate` produces a self-signed root CA certificate with `BasicConstraints(ca=True)` and a `SubjectKeyIdentifier` extension. `issue_certificate` signs an end-entity certificate using the CA's private key, setting `BasicConstraints(ca=False)`.

Certificate validation in `validate_certificate` checks three conditions: the certificate has not expired, its issuer field matches the CA's subject field, and its cryptographic signature over the TBS (to-be-signed) certificate bytes can be verified with the CA's public key. Both RSA PKCS1v15 and ECDSA signature algorithms are handled.

The `RevocationList` class provides a simple in-memory CRL. Certificate serial numbers are stored in a Python set; `is_revoked` checks membership in O(1). While a production system would use a signed CRL distributed via LDAP or OCSP, the in-memory version is sufficient to demonstrate the revocation concept.

The `certseal/keystore.py` module wraps the `pkcs12` API from `cryptography` to save and load private keys and certificates in PKCS#12 format with password-based encryption using `BestAvailableEncryption`. PEM export and import are also provided for interoperability with OpenSSL and other tools.

---

## 3. Security Features and Threat Mitigations

### 3.1 Replay Attack Prevention

A replay attack occurs when an adversary captures a valid message and retransmits it later to impersonate the original sender or re-execute a previously authorised action. CertSeal's `NonceStore` class in `certseal/attacks.py` prevents this by associating a unique, cryptographically random nonce with each message. The nonce is generated using `os.urandom(32).hex()`, producing 64 hex characters of entropy. On receipt, `validate_nonce` checks whether the nonce has been seen before. If it has, the message is rejected as a potential replay. Used nonces are stored with a timestamp and cleaned up after an expiry period (default 300 seconds) to prevent unbounded memory growth.

Use Case 3 demonstrates this: Alice attaches a fresh nonce to each of her three encrypted messages. Bob validates each nonce on decryption. A subsequent attempt to replay the first message's nonce is rejected by the store.

### 3.2 MITM Attack Prevention

A man-in-the-middle attack occurs when an attacker intercepts communication and substitutes their own public key or certificate. The `CertificatePin` class addresses this by storing the expected SHA-256 fingerprint of a host's certificate. On each connection, the presented certificate's fingerprint is compared with the stored pin. A mismatch — which would occur if an attacker substituted a different certificate, even one signed by a legitimate CA — causes the connection to be rejected. If no pin has been registered for a host, verification also fails, enforcing an explicit trust decision.

### 3.3 Weak Key Defence

The `validate_rsa_key_strength` function evaluates RSA key sizes against current security recommendations. Keys below 1024 bits are marked as broken; keys between 1024 and 2048 bits are marked as weak; 2048-bit keys are acceptable; 4096-bit keys are strong. This provides a programmatic guard that can be integrated into certificate issuance pipelines to reject inadequate keys before they are embedded in long-lived certificates.

### 3.4 Chosen-Ciphertext Attack Defence

RSA with PKCS1v15 encryption padding is vulnerable to Bleichenbacher's chosen-ciphertext attack, in which an adversary submits carefully crafted ciphertexts to a decryption oracle and uses the error responses to recover plaintext. By using RSA-OAEP throughout CertSeal, this entire attack class is eliminated. OAEP randomises the plaintext before encryption and includes an integrity check that causes decryption to fail on modified ciphertexts without revealing which byte was wrong.

### 3.5 Forward Secrecy

As described in section 2.2, ECC hybrid encryption in CertSeal uses a fresh ephemeral key pair for every encryption operation. The ephemeral private key is never stored. This means that even if an adversary later obtains Bob's long-term private key, they cannot decrypt any previously captured ciphertexts because the ephemeral keys that were used in the ECDH exchange no longer exist. Forward secrecy is a critical property for secure messaging systems: it limits the damage of a key compromise to future communications only.

### 3.6 Timing Attack Defence

Hash comparison using a naive `==` check is vulnerable to timing attacks because Python's string equality operator short-circuits on the first mismatched byte. An attacker who can make many verification requests and measure response times can statistically determine the correct hash one byte at a time. CertSeal uses `hmac.compare_digest` in the `verify_hash` function. This function is guaranteed by the Python standard library to execute in constant time regardless of how many bytes match, eliminating the timing side channel.

---

## 4. Use Cases

### 4.1 Use Case 1 — Secure Email Communication

The security problem with email is fundamental: SMTP transmits messages as plaintext by default. Even when TLS is used between mail servers, messages are typically decrypted and re-encrypted at each hop, meaning the mail server operator can read all messages. For genuinely confidential communication, end-to-end encryption with non-repudiation is required.

Use Case 1 in `examples/use_case_1_secure_email.py` simulates Alice sending a sensitive email to Bob. Alice first signs the email body with her RSA-PSS private key, establishing that the content originated from her. She then encrypts the email using Bob's RSA public key via hybrid encryption, ensuring only Bob can decrypt it. Bob decrypts the AES session key with his RSA private key, recovers the email plaintext, and verifies Alice's signature. The script then deliberately modifies the email body and shows that signature verification fails, demonstrating tamper detection. This pattern is directly analogous to S/MIME and OpenPGP, the two main standards for secure email.

### 4.2 Use Case 2 — Legal Document Signing

Legal and contractual documents require a mechanism by which multiple parties can each attest to the document's contents and the fact of their agreement. Traditional wet-ink signatures are difficult to verify remotely and easily forged. A cryptographic signature scheme provides a much stronger guarantee: the signature can only be produced by the holder of the corresponding private key, and any modification to the document — even changing a single byte — will cause all signatures to become invalid.

Use Case 2 in `examples/use_case_2_document_signing.py` demonstrates ECDSA multi-party signing with three parties. Alice, Bob, and Charlie each independently sign the same contract document. The script verifies all three signatures successfully. It then simulates two attacks: Eve attempting to forge Alice's signature by signing with Bob's key (which fails Alice's public key check), and a document tampering attempt (which invalidates Alice's existing signature). ECDSA is chosen here for its efficiency — smaller keys and signatures compared with RSA — which is important when storing many signatures or when the document signing occurs on constrained devices.

### 4.3 Use Case 3 — Secure Instant Messaging with Forward Secrecy

Mass surveillance and targeted interception of encrypted communications have motivated the adoption of forward-secret messaging protocols such as Signal's Double Ratchet. The core insight is that long-term key compromise should not expose historical messages. Classical RSA hybrid encryption does not have this property: if Bob's long-term RSA private key is stolen, an attacker who previously captured encrypted messages can decrypt them all retrospectively.

Use Case 3 in `examples/use_case_3_secure_messaging.py` demonstrates how CertSeal's ECC hybrid encryption achieves forward secrecy. Alice sends three messages to Bob. For each message, a completely new ephemeral ECC key pair is generated and used for ECDH. The resulting session key is used to encrypt that one message and then discarded. Bob decrypts each message using the ephemeral public key (included in the encrypted envelope) and his long-term private key. The script also demonstrates nonce-based replay protection: Bob's `NonceStore` validates the nonce attached to each message, and a subsequent attempt to replay message 1's nonce is blocked.

---

## 5. Implementation Challenges and Improvements

### Challenge 1: PKCS#12 Keystore Compatibility

PKCS#12 is a complex binary format with multiple layers of encryption and MAC. The `cryptography` library's `pkcs12.serialize_key_and_certificates` API changed its default encryption algorithm between versions, and `BestAvailableEncryption` may produce PKCS#12 files that older tools (such as older versions of OpenSSL or Java's keytool) cannot read. During development, I encountered version-related warnings when loading PKCS#12 files saved with newer encryption. I resolved this by sticking with `BestAvailableEncryption` but documenting that compatibility with legacy tools may require downgrading to RC2-based encryption.

### Challenge 2: Certificate Validation for RSA and ECC

Implementing `validate_certificate` required handling both RSA and ECC certificate signatures. The `verify` method for RSA keys requires `padding.PKCS1v15()` and a hash algorithm, while ECC keys use `ec.ECDSA(hash_algorithm)`. Since the certificate object does not expose the key type directly in a way that avoids trying both, I implemented a try/except structure: first attempt RSA-PKCS1v15 verification; if that raises an exception, fall back to ECDSA. This is not elegant, but it works correctly for the two key types used in CertSeal. In production, one would inspect the key type explicitly using `isinstance`.

### Challenge 3: ECC Hybrid Encryption and HKDF Parameters

The HKDF key derivation step in `ecc_hybrid_encrypt` required careful parameter selection. The ECDH shared secret for P-256 is 32 bytes, which would be sufficient to use directly as an AES-256 key. However, HKDF is recommended because the shared secret is not uniformly random — it is an x-coordinate on an elliptic curve — and HKDF's extract phase normalises it to a proper pseudorandom key. I used SHA-256 as the HKDF hash, `None` for the salt (producing a fixed salt of all zeros, as specified in RFC 5869), and `b"certseal-ecc-encryption"` as the info string to domain-separate this key derivation from any other use of the same shared secret.

### Potential Improvements

Several enhancements could extend CertSeal towards production-grade PKI. Integration with an HSM (Hardware Security Module) via the PKCS#11 interface would allow CA private keys to be stored in tamper-resistant hardware. OCSP (Online Certificate Status Protocol) support, as defined in RFC 6960, would replace the in-memory CRL with a real-time revocation checking infrastructure. A full TLS integration layer, where CertSeal-issued certificates are used to negotiate TLS connections, would demonstrate end-to-end PKI in action. A web-based interface using Flask would make the tool accessible without requiring local installation. Finally, a threshold signature scheme would improve the CA's resilience against single-point-of-compromise by requiring k-of-n key shares to sign a certificate.

---

## 6. Reflection

Developing CertSeal gave me a far deeper understanding of PKI than I had gained from reading standards documents alone. The most significant lesson was appreciating the gap between an algorithm being conceptually straightforward and implementing it correctly and securely. For example, I knew abstractly that CBC mode required a unique IV per encryption; implementing it made concrete why — without uniqueness, an attacker who knows one plaintext can recover another by XORing the blocks. Similarly, reading about timing attacks on hash comparison is very different from actually replacing an `==` with `hmac.compare_digest` and understanding why the byte-by-byte execution behaviour of the former leaks information.

I also developed a much greater appreciation for the cryptographic standards ecosystem — PKCS#7, PKCS#8, PKCS#12, PKCS#11, X.509 v3, RFC 5280, RFC 8017. These standards represent decades of accumulated experience with what goes wrong when cryptography is deployed in the real world. The `cryptography` Python library, which I used throughout CertSeal, is itself a thin wrapper around OpenSSL's native C implementation; understanding its API forced me to reason about the underlying primitives more carefully than using a higher-level abstraction would have.

The project also highlighted the importance of algorithm agility — the ability to replace a cryptographic primitive when it is broken — which is why CertSeal's architecture separates hashing, signing, encrypting, and PKI concerns into distinct modules. If SHA-256 were someday broken, replacing it would require changes to only a few functions rather than a system-wide rewrite.

---

## 7. Conclusion

CertSeal is a complete, tested, and documented open-source PKI cryptographic tool that meets the requirements of the ST6051CEM Practical Cryptography assignment. It implements AES-256-CBC, DES (educational), RSA-OAEP, RSA hybrid encryption, ECC hybrid encryption with ECDH and HKDF, SHA-256/SHA-512 hashing, RSA-PSS and ECDSA digital signatures, X.509 certificate generation and validation, PKCS#12 key storage, and attack simulations for replay, MITM, and weak-key scenarios. It ships with a CLI, a Tkinter GUI, 43 unit tests across six test modules, three end-to-end use case scripts, and a GitHub Actions CI pipeline. The project demonstrates that it is possible to build a functionally correct, pedagogically valuable cryptographic tool in Python that bridges the gap between theoretical algorithm knowledge and practical PKI deployment.

---

## References

1. CrypTool Project. *CrypTool 2*. [https://github.com/CrypTool/ct2](https://github.com/CrypTool/ct2). Apache 2.0 License. Accessed March 2026.

2. National Institute of Standards and Technology (NIST). *Advanced Encryption Standard (AES)*. FIPS PUB 197. November 2001. [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

3. National Institute of Standards and Technology (NIST). *Secure Hash Standard (SHS)*. FIPS PUB 180-4. August 2015. [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

4. Moriarty, K., Kaliski, B., Jonsson, J., and Rusch, A. *PKCS #1: RSA Cryptography Specifications Version 2.2*. RFC 8017. November 2016. [https://www.rfc-editor.org/rfc/rfc8017](https://www.rfc-editor.org/rfc/rfc8017)

5. Turner, S. and Brown, D. *Elliptic Curve Cryptography Subject Public Key Information*. RFC 5480. March 2009. [https://www.rfc-editor.org/rfc/rfc5480](https://www.rfc-editor.org/rfc/rfc5480)

6. Python Cryptographic Authority. *cryptography — Cryptographic recipes and primitives for Python*. [https://cryptography.io](https://cryptography.io). Accessed March 2026.

7. Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and Polk, W. *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*. RFC 5280. May 2008. [https://www.rfc-editor.org/rfc/rfc5280](https://www.rfc-editor.org/rfc/rfc5280)

8. Krawczyk, H. and Eronen, P. *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*. RFC 5869. May 2010. [https://www.rfc-editor.org/rfc/rfc5869](https://www.rfc-editor.org/rfc/rfc5869)
