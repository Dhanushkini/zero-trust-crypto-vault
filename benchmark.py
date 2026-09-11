import time
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from app.crypto_engine import CryptoEngine

console = Console()

def run_benchmarks():
    console.print(Panel("[bold green]Zero Trust Cryptography Performance Benchmarking Suite[/bold green]"))

    table = Table(title="Cryptographic Benchmark Results")
    table.add_column("Algorithm / Primitive", style="cyan")
    table.add_column("Operation", style="yellow")
    table.add_column("Parameters / Payload", style="magenta")
    table.add_column("Performance Metric", style="bold green")

    # 1. Argon2id KDF Benchmark
    salt = os.urandom(16)
    start = time.perf_counter()
    CryptoEngine.derive_keys_from_password("MasterPassword123!", salt)
    argon_time = (time.perf_counter() - start) * 1000
    table.add_row("Argon2id", "Key Derivation", "m=64MB, t=3, p=4", f"{argon_time:.2f} ms")

    # 2. X25519 Key Agreement Benchmark
    count = 1000
    start = time.perf_counter()
    for _ in range(count):
        CryptoEngine.generate_x25519_keypair()
    x25519_rate = count / (time.perf_counter() - start)
    table.add_row("X25519", "Keypair Gen / ECDH", "Curve25519 (256-bit)", f"{x25519_rate:.2f} ops/sec")

    # 3. ChaCha20-Poly1305 AEAD Throughput
    key = os.urandom(32)
    payload_10mb = os.urandom(10 * 1024 * 1024)
    start = time.perf_counter()
    nonce, cipher = CryptoEngine.encrypt_aead(key, payload_10mb, b"benchmark-aad")
    elapsed = time.perf_counter() - start
    throughput = 10 / elapsed
    table.add_row("ChaCha20-Poly1305", "AEAD Encryption", "10 MB Payload", f"{throughput:.2f} MB/s")

    console.print(table)

if __name__ == "__main__":
    run_benchmarks()