"""Core vault logic: encrypted wallet storage with BIP39 generation."""
import json
import hashlib
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic

VAULT_FILE = Path.home() / ".cryptovault" / "vault.enc"
FREE_WALLET_LIMIT = 3


class VaultError(Exception):
    """Domain error for vault operations."""


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def _encrypt(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return salt + nonce + ct


def _decrypt(blob: bytes, password: str) -> bytes:
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = _derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


def _load(password: str) -> dict:
    if not VAULT_FILE.exists():
        return {"wallets": [], "license": None}
    return json.loads(_decrypt(VAULT_FILE.read_bytes(), password))


def _save(store: dict, password: str):
    VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    VAULT_FILE.write_bytes(_encrypt(json.dumps(store).encode(), password))


def is_pro(store: dict) -> bool:
    return store.get("license") not in (None, "")


def create_wallet(password: str, label: str = "") -> dict:
    store = _load(password)
    if not is_pro(store) and len(store["wallets"]) >= FREE_WALLET_LIMIT:
        raise VaultError(f"Free tier limited to {FREE_WALLET_LIMIT} wallets. Upgrade to Pro.")
    phrase = Mnemonic("english").generate(strength=128)
    seed_hex = hashlib.sha256(phrase.encode()).hexdigest()
    address = "0x" + hashlib.sha256(seed_hex.encode()).hexdigest()[:40]
    wallet = {"label": label or f"wallet-{len(store['wallets']) + 1}", "address": address, "mnemonic": phrase}
    store["wallets"].append(wallet)
    _save(store, password)
    return {"label": wallet["label"], "address": address}


def list_wallets(password: str) -> list:
    store = _load(password)
    return [{"label": w["label"], "address": w["address"]} for w in store["wallets"]]


def export_wallets(password: str, export_password: str) -> bytes:
    store = _load(password)
    if not is_pro(store):
        raise VaultError("Encrypted export requires a Pro license.")
    return _encrypt(json.dumps(store["wallets"]).encode(), export_password)


def activate_license(password: str, license_key: str) -> bool:
    store = _load(password)
    store["license"] = license_key
    _save(store, password)
    return True
