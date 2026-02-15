"""Tests for CryptoVault core logic."""
import pytest
import vault


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
    vault.activate_license("pass123", "PRO-XXXX-YYYY")
    w4 = vault.create_wallet("pass123", "w3")
    assert w4["label"] == "w3"
    assert len(vault.list_wallets("pass123")) == 4


def test_export_blocked_on_free():
    vault.create_wallet("pass123", "w0")
    with pytest.raises(vault.VaultError, match="Pro license"):
        vault.export_wallets("pass123", "backup-key")


def test_export_works_on_pro():
    vault.create_wallet("pass123", "w0")
    vault.activate_license("pass123", "PRO-KEY")
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
