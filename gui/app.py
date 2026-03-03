"""
CertSeal GUI — Tkinter graphical interface with 6 functional tabs.

Provides a user-friendly interface for key generation, hashing, encryption,
digital signatures, PKI operations, and attack simulations.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

from certseal.asymmetric import (
    rsa_generate_keypair, ecc_generate_keypair,
    rsa_hybrid_encrypt, rsa_hybrid_decrypt,
    ecc_hybrid_encrypt, ecc_hybrid_decrypt
)
from certseal.hashing import sha256_hash, sha512_hash, hash_file
from certseal.signatures import rsa_sign, rsa_verify, ecdsa_sign, ecdsa_verify
from certseal.pki import generate_ca_certificate, issue_certificate, validate_certificate, cert_to_pem
from certseal.keystore import export_private_key_pem, export_public_key_pem
from certseal.attacks import NonceStore, CertificatePin, validate_rsa_key_strength, simulate_replay_attack


class CertSealApp(tk.Tk):
    """Main CertSeal GUI application window."""

    def __init__(self):
        """Initialise the CertSeal application window and all tabs."""
        super().__init__()
        self.title("CertSeal — PKI Cryptographic Tool v1.0.0")
        self.geometry("900x650")
        self.configure(bg="#1a1a2e")

        # Dark header bar
        header = tk.Frame(self, bg="#16213e", height=50)
        header.pack(fill=tk.X)
        tk.Label(
            header,
            text="🔐  CertSeal — Open-source PKI Cryptographic Tool",
            bg="#16213e",
            fg="#e94560",
            font=("Helvetica", 14, "bold")
        ).pack(side=tk.LEFT, padx=15, pady=12)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self._build_tab_keygen(notebook)
        self._build_tab_hashing(notebook)
        self._build_tab_encryption(notebook)
        self._build_tab_signatures(notebook)
        self._build_tab_pki(notebook)
        self._build_tab_attacks(notebook)

        # Shared state
        self._keygen_priv = None
        self._keygen_pub = None
        self._enc_last_encrypted = None
        self._enc_priv = None
        self._enc_pub = None
        self._sig_priv = None
        self._sig_pub = None
        self._sig_last_data = None
        self._sig_last_signature = None
        self._pki_ca_priv = None
        self._pki_ca_cert = None
        self._pki_issued_cert = None
        self._pki_issued_pub = None

    # ------------------------------------------------------------------ #
    #  Helper
    # ------------------------------------------------------------------ #
    @staticmethod
    def _make_frame(notebook, title):
        """Create a labelled frame inside a notebook tab.

        Args:
            notebook: The ttk.Notebook widget.
            title: Tab title string.

        Returns:
            Tuple of (tab_frame, inner_frame).
        """
        tab = ttk.Frame(notebook)
        notebook.add(tab, text=title)
        frame = ttk.LabelFrame(tab, text=title, padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        return tab, frame

    @staticmethod
    def _output_box(parent):
        """Create a ScrolledText output widget.

        Args:
            parent: Parent widget.

        Returns:
            ScrolledText widget.
        """
        box = scrolledtext.ScrolledText(parent, height=10, wrap=tk.WORD, font=("Courier", 10))
        box.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        return box

    # ------------------------------------------------------------------ #
    #  Tab 1 — Key Generation
    # ------------------------------------------------------------------ #
    def _build_tab_keygen(self, notebook):
        """Build the Key Generation tab."""
        _, frame = self._make_frame(notebook, "🔑 Key Generation")

        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=5)
        ttk.Label(row, text="Key Type:").pack(side=tk.LEFT, padx=5)
        self._keygen_type = ttk.Combobox(row, values=["RSA-2048", "RSA-4096", "ECC-P256"], state="readonly", width=15)
        self._keygen_type.set("RSA-2048")
        self._keygen_type.pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Generate Keys", command=self._do_keygen).pack(side=tk.LEFT, padx=10)

        self._keygen_out = self._output_box(frame)

    def _do_keygen(self):
        """Generate keys based on the selected type and display results."""
        sel = self._keygen_type.get()
        try:
            if sel == "RSA-2048":
                priv, pub = rsa_generate_keypair(2048)
            elif sel == "RSA-4096":
                priv, pub = rsa_generate_keypair(4096)
            else:
                priv, pub = ecc_generate_keypair()
            self._keygen_priv = priv
            self._keygen_pub = pub
            pub_pem = export_public_key_pem(pub).decode()
            priv_pem = export_private_key_pem(priv).decode()
            self._keygen_out.delete("1.0", tk.END)
            self._keygen_out.insert(tk.END, f"=== Public Key ===\n{pub_pem}\n")
            self._keygen_out.insert(tk.END, f"=== Private Key (first 200 chars) ===\n{priv_pem[:200]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------------------------------------------------------ #
    #  Tab 2 — Hashing
    # ------------------------------------------------------------------ #
    def _build_tab_hashing(self, notebook):
        """Build the Hashing tab."""
        _, frame = self._make_frame(notebook, "🔎 Hashing")

        ttk.Label(frame, text="Message:").pack(anchor=tk.W)
        self._hash_input = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self._hash_input.pack(fill=tk.X, pady=3)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=5)
        ttk.Label(row, text="Algorithm:").pack(side=tk.LEFT, padx=5)
        self._hash_algo = ttk.Combobox(row, values=["SHA-256", "SHA-512"], state="readonly", width=10)
        self._hash_algo.set("SHA-256")
        self._hash_algo.pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Hash Message", command=self._do_hash_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Hash File", command=self._do_hash_file).pack(side=tk.LEFT, padx=5)

        self._hash_out = self._output_box(frame)

    def _do_hash_message(self):
        """Hash the message in the input box."""
        msg = self._hash_input.get("1.0", tk.END).strip().encode("utf-8")
        algo = self._hash_algo.get().lower().replace("-", "")
        try:
            digest = sha256_hash(msg) if algo == "sha256" else sha512_hash(msg)
            self._hash_out.delete("1.0", tk.END)
            self._hash_out.insert(tk.END, f"{self._hash_algo.get()} Hash:\n{digest}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_hash_file(self):
        """Hash a user-selected file."""
        path = filedialog.askopenfilename(title="Select file to hash")
        if not path:
            return
        algo = self._hash_algo.get().lower().replace("-", "")
        try:
            digest = hash_file(path, algo)
            self._hash_out.delete("1.0", tk.END)
            self._hash_out.insert(tk.END, f"{self._hash_algo.get()} Hash of {path}:\n{digest}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------------------------------------------------------ #
    #  Tab 3 — Encryption
    # ------------------------------------------------------------------ #
    def _build_tab_encryption(self, notebook):
        """Build the Encryption tab."""
        _, frame = self._make_frame(notebook, "🔒 Encryption")

        ttk.Label(frame, text="Plaintext:").pack(anchor=tk.W)
        self._enc_input = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self._enc_input.insert(tk.END, "Enter plaintext to encrypt...")
        self._enc_input.pack(fill=tk.X, pady=3)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=5)
        ttk.Label(row, text="Algorithm:").pack(side=tk.LEFT, padx=5)
        self._enc_algo = ttk.Combobox(row, values=["RSA Hybrid", "ECC Hybrid"], state="readonly", width=12)
        self._enc_algo.set("RSA Hybrid")
        self._enc_algo.pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Encrypt", command=self._do_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Decrypt", command=self._do_decrypt).pack(side=tk.LEFT, padx=5)

        self._enc_out = self._output_box(frame)

    def _do_encrypt(self):
        """Encrypt the plaintext using the selected algorithm."""
        plaintext = self._enc_input.get("1.0", tk.END).strip().encode("utf-8")
        algo = self._enc_algo.get()
        try:
            if algo == "RSA Hybrid":
                priv, pub = rsa_generate_keypair(2048)
                result = rsa_hybrid_encrypt(plaintext, pub)
                self._enc_last_encrypted = ("rsa", result, priv)
                self._enc_out.delete("1.0", tk.END)
                self._enc_out.insert(tk.END, f"[RSA Hybrid Encrypted]\n")
                self._enc_out.insert(tk.END, f"Ciphertext (hex): {result['ciphertext'].hex()[:80]}...\n")
            else:
                priv, pub = ecc_generate_keypair()
                result = ecc_hybrid_encrypt(plaintext, pub)
                self._enc_last_encrypted = ("ecc", result, priv)
                self._enc_out.delete("1.0", tk.END)
                self._enc_out.insert(tk.END, f"[ECC Hybrid Encrypted]\n")
                self._enc_out.insert(tk.END, f"Ciphertext (hex): {result['ciphertext'].hex()[:80]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_decrypt(self):
        """Decrypt the last encrypted result."""
        if not self._enc_last_encrypted:
            messagebox.showwarning("No data", "Encrypt something first.")
            return
        algo, data, priv = self._enc_last_encrypted
        try:
            if algo == "rsa":
                plaintext = rsa_hybrid_decrypt(data, priv)
            else:
                plaintext = ecc_hybrid_decrypt(data, priv)
            self._enc_out.insert(tk.END, f"\n[Decrypted]\n{plaintext.decode('utf-8')}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------------------------------------------------------ #
    #  Tab 4 — Digital Signatures
    # ------------------------------------------------------------------ #
    def _build_tab_signatures(self, notebook):
        """Build the Digital Signatures tab."""
        _, frame = self._make_frame(notebook, "✍️ Digital Signatures")

        ttk.Label(frame, text="Message:").pack(anchor=tk.W)
        self._sig_input = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self._sig_input.insert(tk.END, "Enter message to sign...")
        self._sig_input.pack(fill=tk.X, pady=3)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=5)
        ttk.Label(row, text="Algorithm:").pack(side=tk.LEFT, padx=5)
        self._sig_algo = ttk.Combobox(row, values=["RSA-PSS", "ECDSA"], state="readonly", width=10)
        self._sig_algo.set("RSA-PSS")
        self._sig_algo.pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Sign", command=self._do_sign).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Verify", command=self._do_verify_sig).pack(side=tk.LEFT, padx=5)

        self._sig_out = self._output_box(frame)

    def _do_sign(self):
        """Sign the message using the selected algorithm."""
        data = self._sig_input.get("1.0", tk.END).strip().encode("utf-8")
        algo = self._sig_algo.get()
        try:
            if algo == "RSA-PSS":
                priv, pub = rsa_generate_keypair(2048)
                sig = rsa_sign(data, priv)
            else:
                priv, pub = ecc_generate_keypair()
                sig = ecdsa_sign(data, priv)
            self._sig_priv = priv
            self._sig_pub = pub
            self._sig_last_data = data
            self._sig_last_signature = sig
            self._sig_out.delete("1.0", tk.END)
            self._sig_out.insert(tk.END, f"[{algo}] Signature (hex):\n{sig.hex()[:80]}...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_verify_sig(self):
        """Verify the last signature."""
        if not self._sig_last_signature:
            messagebox.showwarning("No data", "Sign something first.")
            return
        algo = self._sig_algo.get()
        try:
            if algo == "RSA-PSS":
                valid = rsa_verify(self._sig_last_data, self._sig_last_signature, self._sig_pub)
            else:
                valid = ecdsa_verify(self._sig_last_data, self._sig_last_signature, self._sig_pub)
            result = "✅ VALID" if valid else "❌ INVALID"
            self._sig_out.insert(tk.END, f"\nVerification: {result}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------------------------------------------------------ #
    #  Tab 5 — PKI
    # ------------------------------------------------------------------ #
    def _build_tab_pki(self, notebook):
        """Build the PKI tab."""
        _, frame = self._make_frame(notebook, "🏛️ PKI")

        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=5)
        ttk.Button(row, text="Create CA", command=self._do_create_ca).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Issue Certificate", command=self._do_issue_cert).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Validate Certificate", command=self._do_validate_cert).pack(side=tk.LEFT, padx=5)

        self._pki_out = self._output_box(frame)

    def _do_create_ca(self):
        """Create a self-signed CA certificate."""
        try:
            priv, _ = rsa_generate_keypair(2048)
            ca_cert = generate_ca_certificate(priv, "CertSeal Root CA")
            self._pki_ca_priv = priv
            self._pki_ca_cert = ca_cert
            pem = cert_to_pem(ca_cert).decode()
            self._pki_out.delete("1.0", tk.END)
            self._pki_out.insert(tk.END, "[CA Certificate Created]\n")
            self._pki_out.insert(tk.END, f"Subject: {ca_cert.subject}\n")
            self._pki_out.insert(tk.END, f"Serial: {ca_cert.serial_number}\n")
            self._pki_out.insert(tk.END, f"Valid until: {ca_cert.not_valid_after}\n\n")
            self._pki_out.insert(tk.END, pem)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_issue_cert(self):
        """Issue a certificate for Alice signed by the CA."""
        if not self._pki_ca_cert:
            messagebox.showwarning("No CA", "Create a CA first.")
            return
        try:
            priv, pub = rsa_generate_keypair(2048)
            cert = issue_certificate("Alice", pub, self._pki_ca_priv, self._pki_ca_cert)
            self._pki_issued_cert = cert
            self._pki_issued_pub = pub
            pem = cert_to_pem(cert).decode()
            self._pki_out.insert(tk.END, "\n[Certificate Issued for Alice]\n")
            self._pki_out.insert(tk.END, f"Subject: {cert.subject}\n")
            self._pki_out.insert(tk.END, f"Issuer: {cert.issuer}\n")
            self._pki_out.insert(tk.END, f"Serial: {cert.serial_number}\n")
            self._pki_out.insert(tk.END, f"Valid until: {cert.not_valid_after}\n\n")
            self._pki_out.insert(tk.END, pem[:300] + "...\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_validate_cert(self):
        """Validate the issued certificate against the CA."""
        if not self._pki_issued_cert or not self._pki_ca_cert:
            messagebox.showwarning("No cert", "Issue a certificate first.")
            return
        try:
            result = validate_certificate(self._pki_issued_cert, self._pki_ca_cert)
            icon = "✅" if result["valid"] else "❌"
            self._pki_out.insert(tk.END, f"\n{icon} Validation: {result['reason']}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ------------------------------------------------------------------ #
    #  Tab 6 — Attacks
    # ------------------------------------------------------------------ #
    def _build_tab_attacks(self, notebook):
        """Build the Attacks simulation tab."""
        _, frame = self._make_frame(notebook, "⚔️ Attacks")

        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=5)
        ttk.Button(row, text="Replay Attack", command=self._do_replay).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="MITM Prevention", command=self._do_mitm).pack(side=tk.LEFT, padx=5)
        ttk.Button(row, text="Weak Key Analysis", command=self._do_weak_key).pack(side=tk.LEFT, padx=5)

        self._attack_out = self._output_box(frame)

    def _do_replay(self):
        """Simulate a replay attack."""
        try:
            store = NonceStore()
            nonce = store.generate_nonce()
            first = store.validate_nonce(nonce)
            result = simulate_replay_attack(store, nonce)
            self._attack_out.delete("1.0", tk.END)
            self._attack_out.insert(tk.END, "=== Replay Attack Simulation ===\n")
            self._attack_out.insert(tk.END, f"✅ First use accepted: {first}\n")
            self._attack_out.insert(tk.END, f"❌ Replay blocked: {result['result']}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_mitm(self):
        """Simulate MITM prevention via certificate pinning."""
        try:
            pin = CertificatePin()
            priv, _ = rsa_generate_keypair(2048)
            ca = generate_ca_certificate(priv, "Real CA")
            real_pem = cert_to_pem(ca)
            pin.pin_certificate("secure.example.com", real_pem)
            fake_priv, _ = rsa_generate_keypair(2048)
            fake_ca = generate_ca_certificate(fake_priv, "Fake CA")
            fake_pem = cert_to_pem(fake_ca)
            self._attack_out.delete("1.0", tk.END)
            self._attack_out.insert(tk.END, "=== MITM Prevention (Certificate Pinning) ===\n")
            self._attack_out.insert(tk.END, f"✅ Real cert accepted: {pin.verify_pin('secure.example.com', real_pem)}\n")
            self._attack_out.insert(tk.END, f"✅ Fake cert blocked: {not pin.verify_pin('secure.example.com', fake_pem)}\n")
            self._attack_out.insert(tk.END, f"✅ Unknown host blocked: {not pin.verify_pin('unknown.com', real_pem)}\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _do_weak_key(self):
        """Analyse RSA key strengths."""
        self._attack_out.delete("1.0", tk.END)
        self._attack_out.insert(tk.END, "=== RSA Key Strength Analysis ===\n")
        for size in [512, 1024, 2048, 4096]:
            r = validate_rsa_key_strength(size)
            icon = "✅" if r["secure"] else "❌"
            self._attack_out.insert(tk.END, f"{icon} {r['message']}\n")


def main():
    """Launch the CertSeal GUI application."""
    app = CertSealApp()
    app.mainloop()


if __name__ == "__main__":
    main()
