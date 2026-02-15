"""Core vault logic: encrypted wallet storage with BIP39 generation."""
import json
import hashlib
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic
from licensing import validate_license, TIER_LIMITS, UPGRADE_URL

VAULT_FILE = Path.home() / ".cryptovault" / "vault.enc"
FREE_WALLET_LIMIT = 3


class VaultError(Exception):
    """Domain error for vault operations."""


class UpgradeRequiredError(VaultError):
    """Raised when an operation requires a higher licensing tier."""


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


def _get_tier(store: dict) -> str:
    """Resolve the current tier from the stored license key."""
    license_key = store.get("license")
    if not license_key:
        return "free"
    result = validate_license(license_key)
    if result["valid"]:
        return result["tier"]
    return "free"


def check_tier_limit(store: dict, operation: str):
    """Enforce tier restrictions. Raises UpgradeRequiredError when exceeded."""
    tier = _get_tier(store)
    limits = TIER_LIMITS[tier]

    if operation == "create_wallet":
        max_wallets = limits["max_wallets"]
        if max_wallets is not None and len(store["wallets"]) >= max_wallets:
            raise UpgradeRequiredError(
                f"Free tier limited to {max_wallets} wallets. "
                f"Upgrade to Pro: {UPGRADE_URL}"
            )
    elif operation == "export":
        if not limits["export"]:
            raise UpgradeRequiredError(
                f"Pro license required for export. "
                f"Upgrade: {UPGRADE_URL}"
            )
    elif operation == "multi_currency":
        if not limits["multi_currency"]:
            raise UpgradeRequiredError(
                f"Pro license required for multi-currency support. "
                f"Upgrade: {UPGRADE_URL}"
            )
    elif operation == "audit_log":
        if not limits["audit_log"]:
            raise UpgradeRequiredError(
                f"Team license required for audit log. "
                f"Upgrade: {UPGRADE_URL}"
            )


def is_pro(store: dict) -> bool:
    """Check if the store has a valid pro-or-above license."""
    return _get_tier(store) in ("pro", "team")


def create_wallet(password: str, label: str = "") -> dict:
    """Generate a BIP39 wallet and store it encrypted."""
    store = _load(password)
    check_tier_limit(store, "create_wallet")
    phrase = Mnemonic("english").generate(strength=128)
    seed_hex = hashlib.sha256(phrase.encode()).hexdigest()
    address = "0x" + hashlib.sha256(seed_hex.encode()).hexdigest()[:40]
    if not label:
        label = f"wallet-{len(store['wallets']) + 1}"
    wallet = {"label": label, "address": address, "mnemonic": phrase}
    store["wallets"].append(wallet)
    _save(store, password)
    return {"label": label, "address": address}


def list_wallets(password: str) -> list:
    """List all wallets (address + label only, no secrets)."""
    store = _load(password)
    return [{"label": w["label"], "address": w["address"]} for w in store["wallets"]]


def activate_license(password: str, license_key: str):
    """Validate and store a license key in the vault."""
    result = validate_license(license_key)
    if not result["valid"]:
        raise VaultError(f"Invalid license: {result.get('error', 'unknown error')}")
    store = _load(password)
    store["license"] = license_key
    _save(store, password)


def export_wallets(password: str, backup_key: str) -> bytes:
    """Export all wallets encrypted with a separate backup key. Requires Pro tier."""
    store = _load(password)
    check_tier_limit(store, "export")
    export_data = json.dumps(store["wallets"]).encode()
    return _encrypt(export_data, backup_key)
