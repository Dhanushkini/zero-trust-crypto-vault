import sys
import base64
import os
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from app.crypto_engine import CryptoEngine

console = Console()
API_BASE = "http://127.0.0.1:8000"

class CLIClient:
    def __init__(self):
        self.username = None
        self.mek = None
        self.priv_bytes = None
        self.pub_b64 = None

    def register(self):
        console.print(Panel("[bold cyan]Zero Trust Client Registration[/bold cyan]", border_style="cyan"))
        username = Prompt.ask("[yellow]Enter Username[/yellow]")
        password = Prompt.ask("[yellow]Enter Master Password[/yellow]", password=True)

        salt = os.urandom(16)
        console.print("[dim]Computing Argon2id (m=64MB, t=3, p=4)...[/dim]")
        mek, auth_hash = CryptoEngine.derive_keys_from_password(password, salt)
        priv_bytes, pub_b64 = CryptoEngine.generate_x25519_keypair()

        nonce_b64, enc_priv_b64 = CryptoEngine.encrypt_aead(mek, priv_bytes, b"identity-keypair")

        payload = {
            "username": username,
            "auth_hash": auth_hash,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "public_key": pub_b64,
            "encrypted_privkey": enc_priv_b64,
            "privkey_nonce": nonce_b64
        }
        res = requests.post(f"{API_BASE}/api/register", json=payload)
        if res.status_code == 200:
            console.print(f"[bold green]✓ User {username} registered successfully![/bold green]")
        else:
            console.print(f"[bold red]✗ Registration Failed: {res.text}[/bold red]")

    def login(self):
        console.print(Panel("[bold cyan]Zero Trust Blind Login[/bold cyan]", border_style="cyan"))
        username = Prompt.ask("[yellow]Enter Username[/yellow]")
        password = Prompt.ask("[yellow]Enter Master Password[/yellow]", password=True)

        salt_res = requests.get(f"{API_BASE}/api/salt/{username}")
        if salt_res.status_code != 200:
            console.print("[bold red]✗ User does not exist![/bold red]")
            return

        salt = base64.b64decode(salt_res.json()["salt"])
        mek, auth_hash = CryptoEngine.derive_keys_from_password(password, salt)

        login_res = requests.post(f"{API_BASE}/api/login", json={"username": username, "auth_hash": auth_hash})
        if login_res.status_code != 200:
            console.print("[bold red]✗ Authentication Failed[/bold red]")
            return

        data = login_res.json()
        try:
            priv_bytes = CryptoEngine.decrypt_aead(
                mek, 
                data["privkey_nonce"], 
                data["encrypted_privkey"], 
                b"identity-keypair"
            )
            self.username = username
            self.mek = mek
            self.priv_bytes = priv_bytes
            self.pub_b64 = data["public_key"]
            console.print(f"[bold green]✓ Identity Unlocked for {username}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]✗ AEAD Integrity Failure during Key Decryption: {e}[/bold red]")

    def add_secret(self):
        if not self.username:
            console.print("[red]Please login first.[/red]")
            return
        
        title = Prompt.ask("[yellow]Secret Label / Name[/yellow]")
        secret_val = Prompt.ask("[yellow]Secret Payload / Password[/yellow]")

        recipients = {self.username: self.pub_b64}
        envelope_data = CryptoEngine.encrypt_vault_item(secret_val, title, recipients)
        res = requests.post(f"{API_BASE}/api/secrets", json=envelope_data)
        if res.status_code == 200:
            console.print("[bold green]✓ Secret encrypted & stored in zero-knowledge vault![/bold green]")

    def list_secrets(self):
        if not self.username:
            console.print("[red]Please login first.[/red]")
            return

        res = requests.get(f"{API_BASE}/api/secrets/{self.username}")
        data = res.json().get("secrets", [])
        
        table = Table(title=f"Vault Items for {self.username}")
        table.add_column("Title", style="cyan")
        table.add_column("Ciphertext Nonce", style="dim")
        table.add_column("Plaintext (Client Decrypted)", style="bold green")
        table.add_column("Shared With", style="magenta")

        for item in data:
            try:
                decrypted = CryptoEngine.decrypt_vault_item(
                    self.priv_bytes,
                    item["user_envelope"],
                    item["payload_nonce"],
                    item["payload_ciphertext"],
                    item["title"]
                )
            except Exception:
                decrypted = "[red]DECRYPTION FAILED / TAMPERED[/red]"

            table.add_row(
                item["title"],
                item["payload_nonce"][:12] + "...",
                decrypted,
                ", ".join(item["accessible_users"])
            )
        console.print(table)

    def share_secret(self):
        if not self.username:
            console.print("[red]Please login first.[/red]")
            return
        
        res = requests.get(f"{API_BASE}/api/secrets/{self.username}")
        secrets = res.json().get("secrets", [])
        if not secrets:
            console.print("[yellow]No secrets available to share.[/yellow]")
            return

        for idx, s in enumerate(secrets):
            console.print(f"[{idx + 1}] {s['title']} (ID: {s['id']})")
        
        choice = int(Prompt.ask("Select Secret Number")) - 1
        selected = secrets[choice]
        target_user = Prompt.ask("Enter recipient username")

        pk_res = requests.get(f"{API_BASE}/api/users/public-keys")
        pks = pk_res.json()
        if target_user not in pks:
            console.print("[red]Recipient not found.[/red]")
            return

        decrypted_payload = CryptoEngine.decrypt_vault_item(
            self.priv_bytes,
            selected["user_envelope"],
            selected["payload_nonce"],
            selected["payload_ciphertext"],
            selected["title"]
        )

        envelope_data = CryptoEngine.encrypt_vault_item(decrypted_payload, selected["title"], {target_user: pks[target_user]})
        target_env = envelope_data["envelopes"][target_user]

        share_res = requests.post(f"{API_BASE}/api/secrets/share", json={
            "secret_id": selected["id"],
            "target_username": target_user,
            "envelope": target_env
        })
        if share_res.status_code == 200:
            console.print(f"[bold green]✓ Access granted to {target_user} via X25519 envelope![/bold green]")

def main():
    client = CLIClient()
    while True:
        console.print("\n[bold magenta]Zero-Trust Cryptographic Vault Menu[/bold magenta]")
        console.print("1. Register User\n2. Login\n3. Add Secret\n4. List & Decrypt Vault\n5. Share Secret\n6. Exit")
        choice = Prompt.ask("Action", choices=["1", "2", "3", "4", "5", "6"])
        if choice == "1": client.register()
        elif choice == "2": client.login()
        elif choice == "3": client.add_secret()
        elif choice == "4": client.list_secrets()
        elif choice == "5": client.share_secret()
        elif choice == "6": sys.exit(0)

if __name__ == "__main__":
    main()