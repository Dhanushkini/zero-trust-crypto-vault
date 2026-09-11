import uuid
import base64
import os
import json
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from argon2.low_level import hash_secret_raw, Type
from app.crypto_engine import CryptoEngine

app = FastAPI(title="Zero Trust Cryptographic Vault")

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

DATA_FILE = os.path.abspath("vault_storage.json")

def load_data() -> Dict[str, Any]:
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "items": {}}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"users": {}, "items": {}}

def save_data(data: Dict[str, Any]):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SendItemRequest(BaseModel):
    sender: str
    receiver: str
    item_type: str
    title: str
    filename: str = ""
    raw_content_b64: str
    crypto_mode: str  # "ecdh" or "master_key"
    master_key: Optional[str] = ""
    burn_after_read: bool = False
    ttl_seconds: Optional[int] = 0

class DecryptRequest(BaseModel):
    item_id: str
    receiver: str
    crypto_mode: str
    master_key: Optional[str] = ""

class DeleteItemRequest(BaseModel):
    item_id: str
    username: str

@app.get("/", response_class=HTMLResponse)
async def serve_portal(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/users")
async def list_users():
    data = load_data()
    user_list = [{"username": u, "public_key": val["public_key"]} for u, val in data["users"].items()]
    return {"users": user_list}

@app.post("/api/register")
async def register(req: RegisterRequest):
    data = load_data()
    if req.username in data["users"]:
        raise HTTPException(status_code=400, detail="Username already registered.")
    
    # 1. Derive Auth Hash with Argon2id
    salt = os.urandom(16)
    auth_key, _ = CryptoEngine.derive_keys_from_password(req.password, salt)
    auth_hash = base64.b64encode(auth_key).decode('utf-8')
    
    # 2. Generate Valid Curve25519 Keypair
    priv_bytes, pub_bytes = CryptoEngine.generate_x25519_keypair()
    
    data["users"][req.username] = {
        "username": req.username,
        "auth_hash": auth_hash,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "public_key": base64.b64encode(pub_bytes).decode('utf-8'),
        "private_key": base64.b64encode(priv_bytes).decode('utf-8')
    }
    save_data(data)
    return {"status": "success", "message": f"User '{req.username}' registered successfully!"}

@app.post("/api/login")
async def login(req: LoginRequest):
    data = load_data()
    if req.username not in data["users"]:
        raise HTTPException(status_code=404, detail="User not found. Please register first.")
    
    user = data["users"][req.username]
    salt = base64.b64decode(user["salt"])
    auth_key, _ = CryptoEngine.derive_keys_from_password(req.password, salt)
    computed_hash = base64.b64encode(auth_key).decode('utf-8')
    
    if computed_hash != user["auth_hash"]:
        raise HTTPException(status_code=401, detail="Incorrect password. Authentication failed.")
    
    return {
        "status": "authenticated",
        "username": req.username,
        "public_key": user["public_key"]
    }

@app.post("/api/send")
async def send_item(req: SendItemRequest):
    data = load_data()
    if req.receiver not in data["users"]:
        raise HTTPException(status_code=404, detail="Receiver user not found.")
    
    try:
        raw_bytes = base64.b64decode(req.raw_content_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Corrupted payload content.")

    item_salt = os.urandom(16)
    ephemeral_pubkey_b64 = ""
    wrapped_dek_b64 = ""
    dek_nonce_b64 = ""

    if req.crypto_mode == "ecdh":
        # 1. Ephemeral DEK (ChaCha20 32-byte key)
        dek = os.urandom(32)
        nonce_b64, cipher_b64 = CryptoEngine.encrypt_aead(dek, raw_bytes, req.title.encode('utf-8'))
        
        # 2. X25519 ECDH Agreement with Receiver's Public Key
        eph_priv_bytes, eph_pub_bytes = CryptoEngine.generate_x25519_keypair()
        receiver_pub_bytes = base64.b64decode(data["users"][req.receiver]["public_key"])
        
        shared_secret = CryptoEngine.derive_shared_secret(eph_priv_bytes, receiver_pub_bytes)
        dek_nonce_b64, wrapped_dek_b64 = CryptoEngine.encrypt_aead(shared_secret, dek, b"dek-wrapping")
        ephemeral_pubkey_b64 = base64.b64encode(eph_pub_bytes).decode('utf-8')
    else:
        # Mode 2: Manual Master Key (Argon2id)
        if not req.master_key:
            raise HTTPException(status_code=400, detail="Master Key is required for Manual Key Mode.")
        derived_dek, _ = CryptoEngine.derive_keys_from_password(req.master_key, item_salt)
        nonce_b64, cipher_b64 = CryptoEngine.encrypt_aead(derived_dek, raw_bytes, req.title.encode('utf-8'))

    created_at = time.time()
    expires_at = (created_at + req.ttl_seconds) if (req.ttl_seconds and req.ttl_seconds > 0) else None

    item_id = str(uuid.uuid4())
    data["items"][item_id] = {
        "id": item_id,
        "sender": req.sender,
        "receiver": req.receiver,
        "item_type": req.item_type,
        "title": req.title,
        "filename": req.filename,
        "crypto_mode": req.crypto_mode,
        "payload_nonce": nonce_b64,
        "payload_ciphertext": cipher_b64,
        "ephemeral_pubkey": ephemeral_pubkey_b64,
        "wrapped_dek": wrapped_dek_b64,
        "dek_nonce": dek_nonce_b64,
        "item_salt": base64.b64encode(item_salt).decode('utf-8'),
        "burn_after_read": req.burn_after_read,
        "created_at": created_at,
        "expires_at": expires_at
    }
    save_data(data)
    return {"status": "sent", "item_id": item_id}

@app.get("/api/inbox/{username}")
async def get_inbox(username: str):
    data = load_data()
    now = time.time()
    inbox = []
    for item in data["items"].values():
        if item["receiver"] == username:
            if item.get("expires_at") and now > item["expires_at"]:
                continue
            inbox.append(item)
    return {"inbox": inbox, "server_time": now}

@app.get("/api/outbox/{username}")
async def get_outbox(username: str):
    data = load_data()
    now = time.time()
    outbox = [item for item in data["items"].values() if item["sender"] == username]
    return {"outbox": outbox, "server_time": now}

@app.post("/api/decrypt")
async def decrypt_item(req: DecryptRequest):
    data = load_data()
    if req.item_id not in data["items"]:
        raise HTTPException(status_code=404, detail="Payload not found or already deleted.")
    
    item = data["items"][req.item_id]
    if item["receiver"] != req.receiver:
        raise HTTPException(status_code=403, detail="Unauthorized receiver.")

    try:
        if item["crypto_mode"] == "ecdh":
            receiver_priv_bytes = base64.b64decode(data["users"][req.receiver]["private_key"])
            eph_pub_bytes = base64.b64decode(item["ephemeral_pubkey"])
            
            shared_secret = CryptoEngine.derive_shared_secret(receiver_priv_bytes, eph_pub_bytes)
            dek = CryptoEngine.decrypt_aead(shared_secret, item["dek_nonce"], item["wrapped_dek"], b"dek-wrapping")
            decrypted_bytes = CryptoEngine.decrypt_aead(dek, item["payload_nonce"], item["payload_ciphertext"], item["title"].encode('utf-8'))
        else:
            item_salt = base64.b64decode(item["item_salt"])
            derived_dek, _ = CryptoEngine.derive_keys_from_password(req.master_key, item_salt)
            decrypted_bytes = CryptoEngine.decrypt_aead(derived_dek, item["payload_nonce"], item["payload_ciphertext"], item["title"].encode('utf-8'))
    except Exception:
        raise HTTPException(
            status_code=400, 
            detail="SECURITY ALERT: A hacker has attacked your database and changed some JSON vault! This file is INVALID. You cannot access this file."
        )

    if item.get("burn_after_read"):
        del data["items"][req.item_id]
        save_data(data)

    return {
        "status": "success",
        "decrypted_content_b64": base64.b64encode(decrypted_bytes).decode('utf-8'),
        "filename": item.get("filename", ""),
        "item_type": item.get("item_type", "text")
    }

@app.post("/api/delete")
async def delete_item(req: DeleteItemRequest):
    data = load_data()
    if req.item_id in data["items"]:
        item = data["items"][req.item_id]
        if item["sender"] == req.username or item["receiver"] == req.username:
            del data["items"][req.item_id]
            save_data(data)
            return {"status": "deleted", "message": "Record permanently deleted."}
    raise HTTPException(status_code=404, detail="Record not found or unauthorized.")

@app.get("/api/benchmark/run")
async def run_live_crypto_benchmarks():
    payload_sizes_mb = [1, 5, 10, 25]
    chacha_throughput = []
    
    key = os.urandom(32)
    for sz in payload_sizes_mb:
        data_chunk = os.urandom(sz * 1024 * 1024)
        start = time.perf_counter()
        _nonce, _cipher = CryptoEngine.encrypt_aead(key, data_chunk, b"live-aad-bench")
        elapsed = time.perf_counter() - start
        throughput_mbps = sz / elapsed if elapsed > 0 else 0
        chacha_throughput.append(round(throughput_mbps, 2))

    memory_configs_mb = [16, 32, 64, 128]
    argon_latencies = []
    salt = os.urandom(16)
    
    for mem in memory_configs_mb:
        start = time.perf_counter()
        hash_secret_raw(
            secret=b"BenchmarkingMasterPass123!",
            salt=salt,
            time_cost=3,
            memory_cost=mem * 1024,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        latency_ms = (time.perf_counter() - start) * 1000
        argon_latencies.append(round(latency_ms, 2))

    count = 500
    start = time.perf_counter()
    for _ in range(count):
        CryptoEngine.generate_x25519_keypair()
    x25519_ops_sec = round(count / (time.perf_counter() - start), 2)

    return {
        "chacha": {
            "labels": [f"{s} MB" for s in payload_sizes_mb],
            "data": chacha_throughput
        },
        "argon2": {
            "labels": [f"{m} MB" for m in memory_configs_mb],
            "data": argon_latencies
        },
        "x25519": {
            "ops_per_sec": x25519_ops_sec
        }
    }