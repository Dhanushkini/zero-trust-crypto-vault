import base64
import os
from typing import Tuple
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class CryptoEngine:
    @staticmethod
    def derive_keys_from_password(password: str, salt: bytes) -> Tuple[bytes, bytes]:
        """Derives a 32-byte DEK and a 32-byte Auth Key from password using Argon2id."""
        raw_key = hash_secret_raw(
            secret=password.encode('utf-8') if isinstance(password, str) else password,
            salt=salt,
            time_cost=3,
            memory_cost=64 * 1024,  # 64 MB
            parallelism=4,
            hash_len=64,
            type=Type.ID
        )
        dek = raw_key[:32]
        auth_key = raw_key[32:]
        return dek, auth_key

    @staticmethod
    def generate_x25519_keypair() -> Tuple[bytes, bytes]:
        """Generates raw 32-byte private and public keys on Curve25519."""
        priv_obj = X25519PrivateKey.generate()
        pub_obj = priv_obj.public_key()
        from cryptography.hazmat.primitives import serialization
        priv_bytes = priv_obj.private_bytes_raw()
        pub_bytes = pub_obj.public_bytes_raw()
        return priv_bytes, pub_bytes

    @staticmethod
    def derive_shared_secret(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
        """Computes ECDH shared secret and expands it to 32 bytes using HKDF-SHA256."""
        priv_obj = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_obj = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        raw_shared = priv_obj.exchange(pub_obj)
        
        # HKDF expansion to 32-byte symmetric key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"zero-trust-vault-salt",
            info=b"x25519-ecdh-aead-key",
        )
        return hkdf.derive(raw_shared)

    @staticmethod
    def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[str, str]:
        """Encrypts data using ChaCha20-Poly1305 with random 96-bit nonce. Returns (nonce_b64, cipher_b64)."""
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)
        return base64.b64encode(nonce).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_aead(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes = b"") -> bytes:
        """Decrypts and verifies 128-bit Poly1305 MAC tag. Raises exception if corrupted."""
        chacha = ChaCha20Poly1305(key)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        return chacha.decrypt(nonce, ciphertext, aad)