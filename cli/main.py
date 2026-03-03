"""
CertSeal CLI — command-line interface for the CertSeal cryptographic tool.

Provides subcommands: keygen, hash, sign, verify, encrypt, decrypt, pki, attack.
"""

import argparse
import json

from certseal.utils import print_banner, bytes_to_base64, base64_to_bytes, save_to_file, load_from_file
from certseal.asymmetric import (
    rsa_generate_keypair, ecc_generate_keypair,
    rsa_hybrid_encrypt, rsa_hybrid_decrypt,
    ecc_hybrid_encrypt, ecc_hybrid_decrypt
)
from certseal.hashing import sha256_hash, sha512_hash, hash_file
from certseal.signatures import sign_file, verify_file_signature
from certseal.keystore import (
    export_private_key_pem, export_public_key_pem,
    load_private_key_pem, load_public_key_pem,
)
from certseal.pki import generate_ca_certificate, issue_certificate, validate_certificate, cert_to_pem, cert_from_pem
from certseal.attacks import NonceStore, validate_rsa_key_strength, simulate_replay_attack, CertificatePin


def cmd_keygen(args):
    """Generate and save RSA or ECC key pairs.

    Args:
        args: Parsed argparse namespace with type, size, output, and password attributes.
    """
    password = args.password.encode() if args.password else None
    if args.type == "rsa":
        priv, pub = rsa_generate_keypair(args.size)
    else:
        priv, pub = ecc_generate_keypair()
    priv_pem = export_private_key_pem(priv, password)
    pub_pem = export_public_key_pem(pub)
    priv_path = f"{args.output}_private.pem"
    pub_path = f"{args.output}_public.pem"
    save_to_file(priv_pem, priv_path)
    save_to_file(pub_pem, pub_path)
    print(f"[+] Private key saved to: {priv_path}")
    print(f"[+] Public key saved to:  {pub_path}")


def cmd_hash(args):
    """Compute and print the hash of a file or message.

    Args:
        args: Parsed argparse namespace with file, message, and algorithm attributes.
    """
    algo = args.algorithm
    if args.file:
        digest = hash_file(args.file, algo)
        print(f"[+] {algo.upper()} hash of {args.file}:")
    elif args.message:
        data = args.message.encode("utf-8")
        if algo == "sha256":
            digest = sha256_hash(data)
        else:
            digest = sha512_hash(data)
        print(f"[+] {algo.upper()} hash of message:")
    else:
        print("[-] Provide --file or --message")
        return
    print(f"    {digest}")


def cmd_sign(args):
    """Sign a file and save the signature.

    Args:
        args: Parsed argparse namespace with file, key, algorithm, and password attributes.
    """
    password = args.password.encode() if args.password else None
    priv_pem = load_from_file(args.key)
    priv_key = load_private_key_pem(priv_pem, password)
    sig_b64 = sign_file(args.file, priv_key, args.algorithm)
    sig_path = f"{args.file}.sig"
    with open(sig_path, "w") as f:
        f.write(sig_b64)
    print(f"[+] Signature saved to: {sig_path}")


def cmd_verify(args):
    """Verify a file signature.

    Args:
        args: Parsed argparse namespace with file, signature, key, and algorithm attributes.
    """
    with open(args.signature, "r") as f:
        sig_b64 = f.read().strip()
    pub_pem = load_from_file(args.key)
    pub_key = load_public_key_pem(pub_pem)
    valid = verify_file_signature(args.file, sig_b64, pub_key, args.algorithm)
    if valid:
        print("[+] Signature is VALID ✅")
    else:
        print("[-] Signature is INVALID ❌")


def cmd_encrypt(args):
    """Encrypt a file using RSA hybrid or ECC hybrid encryption.

    Args:
        args: Parsed argparse namespace with file, key, and algorithm attributes.
    """
    plaintext = load_from_file(args.file)
    pub_pem = load_from_file(args.key)
    pub_key = load_public_key_pem(pub_pem)
    if args.algorithm == "rsa":
        result = rsa_hybrid_encrypt(plaintext, pub_key)
        enc_data = {
            "algorithm": "rsa",
            "encrypted_key": bytes_to_base64(result["encrypted_key"]),
            "iv": bytes_to_base64(result["iv"]),
            "ciphertext": bytes_to_base64(result["ciphertext"])
        }
    else:
        result = ecc_hybrid_encrypt(plaintext, pub_key)
        enc_data = {
            "algorithm": "ecc",
            "ephemeral_public_key_pem": bytes_to_base64(result["ephemeral_public_key_pem"]),
            "iv": bytes_to_base64(result["iv"]),
            "ciphertext": bytes_to_base64(result["ciphertext"])
        }
    out_path = f"{args.file}.enc"
    with open(out_path, "w") as f:
        json.dump(enc_data, f)
    print(f"[+] Encrypted file saved to: {out_path}")


def cmd_decrypt(args):
    """Decrypt a file encrypted by cmd_encrypt.

    Args:
        args: Parsed argparse namespace with file, key, and password attributes.
    """
    with open(args.file, "r") as f:
        enc_data = json.load(f)
    password = args.password.encode() if args.password else None
    priv_pem = load_from_file(args.key)
    priv_key = load_private_key_pem(priv_pem, password)
    algorithm = enc_data.get("algorithm", "rsa")
    if algorithm == "rsa":
        data_in = {
            "encrypted_key": base64_to_bytes(enc_data["encrypted_key"]),
            "iv": base64_to_bytes(enc_data["iv"]),
            "ciphertext": base64_to_bytes(enc_data["ciphertext"])
        }
        plaintext = rsa_hybrid_decrypt(data_in, priv_key)
    else:
        data_in = {
            "ephemeral_public_key_pem": base64_to_bytes(enc_data["ephemeral_public_key_pem"]),
            "iv": base64_to_bytes(enc_data["iv"]),
            "ciphertext": base64_to_bytes(enc_data["ciphertext"])
        }
        plaintext = ecc_hybrid_decrypt(data_in, priv_key)
    base_name = args.file
    if base_name.endswith(".enc"):
        base_name = base_name[:-4]
    out_path = f"{base_name}.dec"
    save_to_file(plaintext, out_path)
    print(f"[+] Decrypted file saved to: {out_path}")


def cmd_pki(args):
    """Perform PKI operations: create-ca, issue, or validate.

    Args:
        args: Parsed argparse namespace with action, name, subject_key, and cert attributes.
    """
    if args.action == "create-ca":
        priv, _ = rsa_generate_keypair(2048)
        ca_cert = generate_ca_certificate(priv, common_name=args.name or "CertSeal Root CA")
        priv_pem = export_private_key_pem(priv)
        cert_pem = cert_to_pem(ca_cert)
        save_to_file(priv_pem, "ca_private.pem")
        save_to_file(cert_pem, "ca_cert.pem")
        print("[+] CA certificate created: ca_cert.pem, ca_private.pem")
    elif args.action == "issue":
        ca_priv_pem = load_from_file("ca_private.pem")
        ca_cert_pem = load_from_file("ca_cert.pem")
        ca_priv = load_private_key_pem(ca_priv_pem)
        ca_cert = cert_from_pem(ca_cert_pem)
        subj_priv, subj_pub = rsa_generate_keypair(2048)
        issued = issue_certificate(args.name or "Entity", subj_pub, ca_priv, ca_cert)
        cert_pem = cert_to_pem(issued)
        fname = (args.name or "entity").replace(" ", "_").lower()
        save_to_file(cert_pem, f"{fname}_cert.pem")
        save_to_file(export_private_key_pem(subj_priv), f"{fname}_private.pem")
        print(f"[+] Certificate issued: {fname}_cert.pem")
    elif args.action == "validate":
        cert_pem_data = load_from_file(args.cert)
        ca_cert_pem = load_from_file("ca_cert.pem")
        cert = cert_from_pem(cert_pem_data)
        ca_cert = cert_from_pem(ca_cert_pem)
        result = validate_certificate(cert, ca_cert)
        status = "✅ VALID" if result["valid"] else "❌ INVALID"
        print(f"[+] Certificate {status}: {result['reason']}")
    else:
        print(f"[-] Unknown PKI action: {args.action}")


def cmd_attack(args):
    """Run attack simulations.

    Args:
        args: Parsed argparse namespace with type attribute.
    """
    if args.type == "replay":
        store = NonceStore()
        nonce = store.generate_nonce()
        first = store.validate_nonce(nonce)
        result = simulate_replay_attack(store, nonce)
        print(f"[+] First use accepted: {first} ✅")
        print(f"[+] Replay attempt: {result['result']} ❌")
    elif args.type == "weak-key":
        for size in [512, 1024, 2048, 4096]:
            r = validate_rsa_key_strength(size)
            icon = "✅" if r["secure"] else "❌"
            print(f"  {icon} {r['message']}")
    elif args.type == "mitm":
        from certseal.asymmetric import rsa_generate_keypair
        pin = CertificatePin()
        priv, _ = rsa_generate_keypair(2048)
        ca_cert = generate_ca_certificate(priv)
        real_pem = cert_to_pem(ca_cert)
        pin.pin_certificate("example.com", real_pem)
        fake_priv, _ = rsa_generate_keypair(2048)
        fake_cert = generate_ca_certificate(fake_priv, "Fake CA")
        fake_pem = cert_to_pem(fake_cert)
        print(f"[+] Real cert verified: {pin.verify_pin('example.com', real_pem)} ✅")
        print(f"[+] Fake cert blocked: {not pin.verify_pin('example.com', fake_pem)} ✅")
    else:
        print(f"[-] Unknown attack type: {args.type}")


def main():
    """Entry point for the CertSeal CLI."""
    print_banner()
    parser = argparse.ArgumentParser(
        description="CertSeal — Open-source PKI Cryptographic Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to run")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate key pairs")
    p_keygen.add_argument("--type", choices=["rsa", "ecc"], default="rsa")
    p_keygen.add_argument("--size", type=int, default=2048)
    p_keygen.add_argument("--output", default="key")
    p_keygen.add_argument("--password", default=None)

    # hash
    p_hash = subparsers.add_parser("hash", help="Hash a file or message")
    p_hash.add_argument("--file", default=None)
    p_hash.add_argument("--message", default=None)
    p_hash.add_argument("--algorithm", choices=["sha256", "sha512"], default="sha256")

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign a file")
    p_sign.add_argument("--file", required=True)
    p_sign.add_argument("--key", required=True)
    p_sign.add_argument("--algorithm", choices=["rsa", "ecdsa"], default="rsa")
    p_sign.add_argument("--password", default=None)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify a file signature")
    p_verify.add_argument("--file", required=True)
    p_verify.add_argument("--signature", required=True)
    p_verify.add_argument("--key", required=True)
    p_verify.add_argument("--algorithm", choices=["rsa", "ecdsa"], default="rsa")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--file", required=True)
    p_enc.add_argument("--key", required=True)
    p_enc.add_argument("--algorithm", choices=["rsa", "ecc"], default="rsa")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--file", required=True)
    p_dec.add_argument("--key", required=True)
    p_dec.add_argument("--password", default=None)

    # pki
    p_pki = subparsers.add_parser("pki", help="PKI operations")
    p_pki.add_argument("--action", choices=["create-ca", "issue", "validate"], required=True)
    p_pki.add_argument("--name", default=None)
    p_pki.add_argument("--subject-key", default=None)
    p_pki.add_argument("--cert", default=None)

    # attack
    p_attack = subparsers.add_parser("attack", help="Run attack simulations")
    p_attack.add_argument("--type", choices=["replay", "weak-key", "mitm"], required=True)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    dispatch = {
        "keygen": cmd_keygen,
        "hash": cmd_hash,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "pki": cmd_pki,
        "attack": cmd_attack,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
