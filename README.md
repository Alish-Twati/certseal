# CertSeal

[![CI](https://github.com/Alish-Twati/certseal/actions/workflows/ci.yml/badge.svg)](https://github.com/Alish-Twati/certseal/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

**CertSeal** is an open-source Python PKI cryptographic tool for learning and demonstrating modern cryptographic algorithms — inspired by [CrypTool](https://www.cryptool.org).

---

## Overview

CertSeal provides a complete implementation of Public Key Infrastructure (PKI) primitives: symmetric encryption (AES-256-CBC, DES), asymmetric encryption (RSA hybrid, ECC hybrid with ECDH+HKDF), cryptographic hashing (SHA-256, SHA-512), digital signatures (RSA-PSS, ECDSA), X.509 certificate management, PKCS#12 keystores, and attack simulations (replay, MITM, weak-key analysis).

It ships with a CLI, a Tkinter GUI, 43 unit tests, and three end-to-end use case scripts.

> **Inspiration & Attribution:** CertSeal is inspired by the [CrypTool Project](https://github.com/CrypTool/ct2) (Apache 2.0). CrypTool is a free e-learning platform for cryptography and cryptanalysis.

---

## Improvements Over CrypTool

| Feature | CrypTool | CertSeal |
|---|---|---|
| Language | Java/C# | Python 3.9+ |
| Interface | Desktop (Java Swing / WPF) | CLI + Tkinter GUI |
| PKI / X.509 | Limited | Full CA, issue, validate, CRL, PKCS#12 |
| Forward Secrecy | No | ✅ Ephemeral ECDH per message |
| Attack Simulations | Visualisations | Replay, MITM, weak-key with code |
| CI/CD | No | ✅ GitHub Actions matrix (Python 3.9/3.10/3.11) |

---

## Algorithms Implemented

| Algorithm | Module | Details |
|---|---|---|
| AES-256-CBC | `certseal/symmetric.py` | PKCS7 padding, random IV |
| DES (educational) | `certseal/symmetric.py` | Legacy demo — do NOT use in production |
| RSA-2048/4096 | `certseal/asymmetric.py` | OAEP + hybrid (AES session key) |
| ECC P-256 | `certseal/asymmetric.py` | ECDH + HKDF + AES-256-CBC |
| SHA-256 | `certseal/hashing.py` | Hex digest, file hash, salted hash |
| SHA-512 | `certseal/hashing.py` | Hex digest, file hash |
| RSA-PSS | `certseal/signatures.py` | MGF1+SHA-256, MAX_LENGTH salt |
| ECDSA | `certseal/signatures.py` | SHA-256, DER-encoded |

---

## Installation

```bash
git clone https://github.com/Alish-Twati/certseal.git
cd certseal
pip install -r requirements.txt
```

---

## Usage

### CLI

```bash
# Key generation
python -m cli.main keygen --type rsa --size 2048 --output mykey
python -m cli.main keygen --type ecc --output ecckey

# Hashing
python -m cli.main hash --message "Hello, CertSeal!" --algorithm sha256
python -m cli.main hash --file report/report.md --algorithm sha512

# Sign and verify
python -m cli.main sign --file document.pdf --key mykey_private.pem --algorithm rsa
python -m cli.main verify --file document.pdf --signature document.pdf.sig --key mykey_public.pem

# Encrypt and decrypt
python -m cli.main encrypt --file secret.txt --key mykey_public.pem --algorithm rsa
python -m cli.main decrypt --file secret.txt.enc --key mykey_private.pem

# PKI
python -m cli.main pki --action create-ca --name "My Root CA"
python -m cli.main pki --action issue --name "Alice"
python -m cli.main pki --action validate --cert alice_cert.pem

# Attack simulations
python -m cli.main attack --type replay
python -m cli.main attack --type weak-key
python -m cli.main attack --type mitm
```

### GUI

```bash
python gui/app.py
```

---

## PKI Features

- Self-signed CA certificate generation (X.509, BasicConstraints CA:True)
- End-entity certificate issuance signed by the CA
- Certificate validation (expiry, issuer match, signature check)
- Certificate Revocation List (CRL) — in-memory `RevocationList` class
- PKCS#12 keystore save/load with password encryption
- PEM import/export for private and public keys

---

## Security Features

| Threat | Mitigation |
|---|---|
| Replay attacks | `NonceStore` — nonce validation with expiry |
| MITM attacks | `CertificatePin` — SHA-256 certificate fingerprint pinning |
| Weak RSA keys | `validate_rsa_key_strength` — rejects < 2048-bit keys |
| Chosen-ciphertext attacks | RSA-OAEP padding (not PKCS1v15) |
| Timing attacks on hash comparison | `hmac.compare_digest` in `verify_hash` |
| Forward secrecy | Ephemeral ECDH key per message in `ecc_hybrid_encrypt` |

---

## Use Case Demonstrations

### Use Case 1 — Secure Email Communication
```bash
python examples/use_case_1_secure_email.py
```
Alice signs and encrypts an email with RSA-PSS + RSA hybrid. Bob decrypts and verifies. Tamper detection demonstrated.

### Use Case 2 — Legal Document Signing
```bash
python examples/use_case_2_document_signing.py
```
Three parties (Alice, Bob, Charlie) sign a legal contract with ECDSA. Forgery and tampering are blocked.

### Use Case 3 — Secure Instant Messaging with Forward Secrecy
```bash
python examples/use_case_3_secure_messaging.py
```
Three messages encrypted with fresh ephemeral ECC keys. Nonce validation prevents replay. Forward secrecy explained.

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v --tb=short

# Run with coverage
pytest tests/ -v --cov=certseal --cov-report=term-missing
```

---

## Project Structure

```
certseal/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── requirements.txt
├── setup.py
├── .github/workflows/ci.yml
├── certseal/
│   ├── __init__.py
│   ├── symmetric.py
│   ├── asymmetric.py
│   ├── hashing.py
│   ├── signatures.py
│   ├── pki.py
│   ├── keystore.py
│   ├── attacks.py
│   └── utils.py
├── cli/main.py
├── gui/app.py
├── tests/
│   ├── test_symmetric.py
│   ├── test_asymmetric.py
│   ├── test_hashing.py
│   ├── test_signatures.py
│   ├── test_pki.py
│   └── test_attacks.py
├── examples/
│   ├── use_case_1_secure_email.py
│   ├── use_case_2_document_signing.py
│   └── use_case_3_secure_messaging.py
└── report/report.md
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on extending CertSeal with new algorithms, tests, and CLI/GUI features.

---

## License

MIT License — Copyright © 2026 Alish Twati. See [LICENSE](LICENSE).

---

## Attribution

CertSeal is inspired by the **CrypTool Project** ([https://www.cryptool.org](https://www.cryptool.org)) — a free educational platform for cryptography and cryptanalysis. CrypTool source code is available at [https://github.com/CrypTool/ct2](https://github.com/CrypTool/ct2) under the Apache 2.0 License.
