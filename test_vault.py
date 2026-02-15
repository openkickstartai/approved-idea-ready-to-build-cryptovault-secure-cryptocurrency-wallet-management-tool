"""Tests for CryptoVault core logic."""
import pytest
from datetime import datetime, timedelta, timezone
import vault
from licensing import generate_license


def _make_pro_key():
    return generate_license("pro", datetime.now(timezone.utc) + timedelta(days=30))


def _make_team_key():
    return generate_license("team", datetime.now(timezone.utc) + timedelta(days=30))


def _make_expired_key():
    return generate_license("pro", datetime.now(timezone.utc) - timedelta(days=1))


@pytest.fixture(autouse=True)
def isolated_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "VAULT_FILE", tmp_path / "vault.enc")


def test_create_and_list():
    result = vault.create_wallet("pass123", "main-wallet")
    assert result["label"] == "main-wallet"
    assert result["address"].startswith("0x")
    assert len(result["address"]) == 42
    wallets = vault.list_wallets("pass123")
    assert len(wallets) == 1
    assert wallets[0]["address"] == result["address"]


def test_free_tier_limit_enforced():
    for i in range(3):
        vault.create_wallet("pass123", f"w{i}")
    with pytest.raises(vault.VaultError, match="Free tier"):
        vault.create_wallet("pass123", "w3")


def test_pro_license_removes_limit():
    for i in range(3):
        vault.create_wallet("pass123", f"w{i}")
    vault.activate_license("pass123", _make_pro_key())
    w4 = vault.create_wallet("pass123", "w3")
    assert w4["label"] == "w3"
    assert len(vault.list_wallets("pass123")) == 4


def test_export_blocked_on_free():
    vault.create_wallet("pass123", "w0")
    with pytest.raises(vault.VaultError, match="Pro license"):
        vault.export_wallets("pass123", "backup-key")


def test_export_works_on_pro():
    vault.create_wallet("pass123", "w0")
    vault.activate_license("pass123", _make_pro_key())
    data = vault.export_wallets("pass123", "backup-key")
    assert isinstance(data, bytes)
    assert len(data) > 28  # salt(16) + nonce(12) + ciphertext


def test_wrong_password_rejected():
    vault.create_wallet("correct", "w0")
    with pytest.raises(Exception):
        vault.list_wallets("wrong")


def test_default_label_assigned():
    w = vault.create_wallet("pass123")
    assert w["label"] == "wallet-1"
    w2 = vault.create_wallet("pass123")
    assert w2["label"] == "wallet-2"


def test_expired_license_rejected():
    expired_key = _make_expired_key()
    with pytest.raises(vault.VaultError, match="Invalid license"):
        vault.activate_license("pass123", expired_key)


def test_upgrade_required_error_is_vault_error():
    assert issubclass(vault.UpgradeRequiredError, vault.VaultError)


def test_team_license_allows_export():
    vault.create_wallet("pass123", "w0")
    vault.activate_license("pass123", _make_team_key())
    data = vault.export_wallets("pass123", "backup-key")
    assert isinstance(data, bytes)
    assert len(data) > 28


def test_team_license_unlimited_wallets():
    vault.activate_license("pass123", _make_team_key())
    for i in range(5):
        vault.create_wallet("pass123", f"w{i}")
    assert len(vault.list_wallets("pass123")) == 5


def test_invalid_license_string_rejected():
    with pytest.raises(vault.VaultError, match="Invalid license"):
        vault.activate_license("pass123", "not-a-real-key")


def test_upgrade_url_in_error_message():
    for i in range(3):
        vault.create_wallet("pass123", f"w{i}")
    with pytest.raises(vault.UpgradeRequiredError, match="cryptovault.dev/pricing"):
        vault.create_wallet("pass123", "w3")
