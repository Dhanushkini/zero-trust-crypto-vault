# Modern Zero-Trust Cryptographic Vault & Secure Transfer Portal

An end-to-end encrypted storage vault and messaging portal engineered under the strict architectural tenet: **"Never Trust, Always Verify"**. The persistent database layer (`vault_storage.json`) is treated as entirely untrusted and hostile, storing exclusively blind ciphertexts and public curve coordinates. Plaintext reconstruction is executed strictly inside client device memory.

---

## Authors & Academic Credits
* **Bhargav Adiga** (USN: `4CB23CG010`)
* **Dhanush Kini** (USN: `4CB23CG013`)
* **Institution:** Canara Engineering College, Mangaluru
* **Department:** Department of Computer Science and Design
* **Course:** Cryptography and Network Security (`BCS703`)
* **Academic Year:** 2025–2026

---

## Cryptographic Triad

* **Argon2id (RFC 9106):** Memory-hard Key Derivation Function (KDF) parameterized at $m=64\text{ MB}$, $t=3$, $p=4$ to defeat GPU, FPGA, and ASIC brute-force password-cracking engines.
* **X25519 (RFC 7748):** Asymmetric Elliptic Curve Diffie–Hellman (ECDH) over Curve25519 for automated, zero-knowledge ephemeral Data Encryption Key (DEK) encapsulation.
* **ChaCha20-Poly1305 (RFC 8439):** High-speed Authenticated Encryption with Associated Data (AEAD) stream cipher operating in constant-time.
* **Active Tamper Defense:** Live verification of the 128-bit Poly1305 MAC tag. Any bit flipping inside the persistence layer halts decryption before memory execution and triggers an audio alarm siren via the HTML5 Web Audio API.

---

## Hardware Telemetry & Empirical Benchmarks

Telemetry measured directly on commodity host CPU hardware:
* **X25519 Key Agreement Rate:** $25{,}931.73\text{ operations/sec}$
* **Peak AEAD Symmetric Throughput:** $264.89\text{ MB/s}$ (at 10 MB payload)
* **Argon2id KDF Latency:** $63.61\text{ ms}$ (at 64 MB default memory hardness)

---

## Required Packages & Software Stack

* **Runtime:** Python 3.10 or higher
* **Backend:** FastAPI, Uvicorn (ASGI)
* **Cryptography:** `cryptography` (hazmat bindings for X25519, ChaCha20-Poly1305), `argon2-cffi`
* **Frontend:** Vanilla ES6+ JavaScript, HTML5 Web Audio API, Tailwind CSS

| Package | Version | Purpose |
| :--- | :--- | :--- |
| `fastapi` | `>=0.110.0` | Asynchronous REST routing and API endpoints |
| `uvicorn[standard]` | `>=0.28.0` | High-performance ASGI web server |
| `cryptography` | `>=42.0.0` | Low-level primitives for X25519 & ChaCha20-Poly1305 |
| `argon2-cffi` | `>=23.1.0` | Memory-hard key derivation and authentication hashing |
| `pydantic` | `>=2.6.0` | Data schema validation and model parsing |
| `jinja2` | `>=3.1.3` | HTML template rendering engine |
| `python-multipart` | `>=0.0.9` | Streaming multipart file and form processing |

---

## Quickstart Guide

### 1. Clone the Repository
```bash
git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/zero-trust-crypto-vault.git
cd zero-trust-crypto-vault
