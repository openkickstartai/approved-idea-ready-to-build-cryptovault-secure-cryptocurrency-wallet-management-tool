# 🔐 CryptoVault

Secure cryptocurrency wallet management — CLI & API.

Generate BIP39 wallets, encrypt with AES-256-GCM, manage via terminal or REST API.

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# Create a wallet
python main.py create --label my-eth

# List wallets
python main.py list

# Start API server
python main.py serve
```

### API Usage

```bash
# Create wallet via API
curl -X POST http://localhost:8000/wallets \
  -H 'X-Vault-Password: mypass' \
  -H 'Content-Type: application/json' \
  -d '{"label": "trading"}'

# List wallets
curl http://localhost:8000/wallets -H 'X-Vault-Password: mypass'
```

## 📊 Why Pay for CryptoVault?

| Pain Point | Free Alternative | CryptoVault Pro |
|---|---|---|
| Key sprawl across files | Manual management | Encrypted vault, one password |
| No backup strategy | Copy-paste seeds | Encrypted export with separate key |
| Team wallet sharing | Shared spreadsheets | API server with auth headers |
| Audit compliance | None | Export logs + license SLA |

## 💰 Pricing

| Feature | Free | Pro ($19/mo) | Enterprise ($99/mo) |
|---|:---:|:---:|:---:|
| Wallet generation (BIP39) | ✅ | ✅ | ✅ |
| AES-256-GCM encryption | ✅ | ✅ | ✅ |
| Max wallets | 3 | Unlimited | Unlimited |
| CLI interface | ✅ | ✅ | ✅ |
| REST API server | ✅ | ✅ | ✅ |
| Encrypted backup export | ❌ | ✅ | ✅ |
| Multi-chain support | ❌ | ✅ | ✅ |
| Team license (5 seats) | ❌ | ❌ | ✅ |
| Priority support & SLA | ❌ | ❌ | ✅ |

## Architecture

```
~/.cryptovault/vault.enc   ← AES-256-GCM encrypted JSON
     │
     ├── CLI (click)       ← main.py create/list/export
     └── API (FastAPI)     ← main.py serve → POST/GET /wallets
```

Master password → scrypt → 256-bit key → AESGCM(nonce‖ciphertext).
No plaintext secrets ever touch disk.

## License

BSL 1.1 — free for non-production use. Production requires a paid license.
