# Installing wks-diary-core on your VPS

## 1. Prerequisites on the VPS

```bash
sudo apt update && sudo apt install -y build-essential curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## 2. Get the project onto the VPS

Unzip the archive locally, then copy the `rust/` folder to the server:

```bash
scp -r rust your-user@your-vps:/opt/wks-diary-core
```

## 3. Configure secrets

```bash
cd /opt/wks-diary-core
cp env.example.txt .env
openssl rand -hex 32   # run twice, once for each key below
nano .env
```

Fill in:
```
WKS_API_KEY=<first random hex string>
WKS_VAULT_KEY=<second random hex string, 64 hex chars>
STORAGE_DIR=/opt/wks-diary-core/storage
MAX_UPLOAD_BYTES=52428800
BIND_ADDR=127.0.0.1:8080
```

`WKS_VAULT_KEY` must be the exact same value you enter later in the Python client on every device -- store it in a password manager, never commit it.

## 4. Build the release binary

```bash
cargo build --release
mkdir -p storage
```

## 5. Run it as a systemd service

```bash
sudo tee /etc/systemd/system/wks-diary-core.service > /dev/null <<'EOF'
[Unit]
Description=wks-diary-core backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/wks-diary-core
ExecStart=/opt/wks-diary-core/target/release/wks-server
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now wks-diary-core
sudo systemctl status wks-diary-core
```

Expose it through a reverse proxy with TLS, e.g. Caddy:

```bash
sudo apt install -y caddy
sudo tee /etc/caddy/Caddyfile > /dev/null <<'EOF'
your-domain.tld {
    reverse_proxy 127.0.0.1:8080
}
EOF
sudo systemctl reload caddy
```

## 6. Quick check

```bash
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/version
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/history
```

## 7. Set up the Python client (any device you write your diary on)

```bash
pip install pynacl requests
python wks_diary_core.py
```

Enter `WKS_VAULT_KEY`, `WKS_API_KEY`, and `https://your-domain.tld` when prompted. Save to `.env` if you want (gitignore it immediately).

## 8. First run

1. Create `vault/` locally with `diary/`, `people/`, `misc/` subfolders, write `.txt` files following `SYNTAX.md`.
2. Menu option 1 (Lock) to produce `vault.wks`.
3. Menu option 5 (Push) to send it to the VPS for the first time.
4. On any other device: option 4 (Pull), then unlock.

## 9. Recovering from a mistake

Every push, merge, and restore is logged and the previous state is archived first -- nothing is ever silently lost.

```
8) Show history       -> lists every past version with its hash and timestamp
9) Restore            -> pick a hash from that list, server makes it current again
```

After restoring, pull + unlock to get the restored content back into your local `vault/`.

## 10. Backups

Everything under `STORAGE_DIR` (`vault.wks`, `storage/history/*.wks`, `storage/log.json`) is fully encrypted except the log's metadata (hashes/timestamps/sizes, no content) -- safe to include in regular off-site backups without any extra encryption step.
