"""CryptoVault CLI & API entry point."""
import click
import uvicorn
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import vault

app = FastAPI(title="CryptoVault API", version="1.0.0")


class CreateReq(BaseModel):
    label: str = ""


class LicenseReq(BaseModel):
    license_key: str


@app.post("/wallets")
def api_create(req: CreateReq, x_vault_password: str = Header(...)):
    try:
        return vault.create_wallet(x_vault_password, req.label)
    except vault.VaultError as e:
        raise HTTPException(403, str(e))


@app.get("/wallets")
def api_list(x_vault_password: str = Header(...)):
    try:
        return vault.list_wallets(x_vault_password)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/license")
def api_activate(req: LicenseReq, x_vault_password: str = Header(...)):
    vault.activate_license(x_vault_password, req.license_key)
    return {"status": "activated"}


@click.group()
def cli():
    """CryptoVault — Secure Wallet Management"""


@cli.command()
@click.option("--password", prompt=True, hide_input=True)
@click.option("--label", default="")
def create(password, label):
    """Create a new wallet."""
    try:
        w = vault.create_wallet(password, label)
        click.echo(f"Created: {w['label']} -> {w['address']}")
    except vault.VaultError as e:
        click.echo(f"Error: {e}", err=True)


@cli.command("list")
@click.option("--password", prompt=True, hide_input=True)
def list_cmd(password):
    """List all wallets."""
    try:
        for w in vault.list_wallets(password):
            click.echo(f"  {w['label']}: {w['address']}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.option("--password", prompt=True, hide_input=True)
@click.option("--export-password", prompt=True, hide_input=True)
@click.option("--output", default="backup.vault")
def export(password, export_password, output):
    """Export encrypted backup (Pro only)."""
    try:
        data = vault.export_wallets(password, export_password)
        with open(output, "wb") as f:
            f.write(data)
        click.echo(f"Exported to {output}")
    except vault.VaultError as e:
        click.echo(f"Error: {e}", err=True)


@cli.command()
@click.option("--password", prompt=True, hide_input=True)
@click.argument("license_key")
def activate(password, license_key):
    """Activate a Pro license key."""
    vault.activate_license(password, license_key)
    click.echo("License activated.")


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
def serve(host, port):
    """Start the REST API server."""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    cli()
