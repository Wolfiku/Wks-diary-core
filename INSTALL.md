# Installing wks-diary-core on your VPS

## 1. Prerequisites on the VPS

```bash
sudo apt update && sudo apt install -y build-essential curl rsync
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## 2. Get the project onto the VPS

```bash
scp -r rust backup.sh your-user@your-vps:/opt/wks-diary-core
```

## 3. Configure secrets

```bash
cd /opt/wks-diary-core
cp env.example.txt .env
openssl rand -hex 32   # for WKS_API_KEY
openssl rand -hex 32   # for WKS_VAULT_KEY (Mode A) or WKS_VAULT_SALT (Mode B)
nano .env
```

Pick a key mode:

- **Mode A (simple, unattended-friendly):** set `WKS_VAULT_KEY` to a random 32-byte hex string. Works with automatic systemd restarts, but the raw key sits in `.env` at rest.
- **Mode B (more secure at rest, manual-start only):** set `WKS_VAULT_SALT` instead (also random hex, but this one is NOT secret by itself) and leave `WKS_VAULT_KEY` unset. The server will then prompt for a passphrase on every manual start. This does not survive an unattended `systemctl restart` without a human typing the passphrase in, so it's a genuine trade-off between convenience and at-rest exposure -- pick Mode A if you want the service to self-heal after a reboot without you.

Also set:
```
STORAGE_DIR=/opt/wks-diary-core/storage
BIND_ADDR=127.0.0.1:8080
WKS_ALLOW_PUBLIC_BIND=no
RETENTION_DAYS=30
RATE_LIMIT_MAX_FAILURES=10
RATE_LIMIT_WINDOW_SECS=60
```

Whatever vault key/passphrase you choose must be identical on every device you use the Python client from. Store it in a password manager.

## 4. Build the release binary

```bash
cd rust
cargo build --release
mkdir -p storage
```

## 5. Run it as a systemd service

If you're using Mode A (`WKS_VAULT_KEY`), a plain systemd unit works fine:

```bash
sudo tee /etc/systemd/system/wks-diary-core.service > /dev/null <<'EOF'
[Unit]
Description=wks-diary-core backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/wks-diary-core/rust
ExecStart=/opt/wks-diary-core/rust/target/release/wks-server
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now wks-diary-core
sudo systemctl status wks-diary-core
```

If you're using Mode B (`WKS_VAULT_SALT` + passphrase prompt), skip the systemd unit and instead run it manually in a `screen`/`tmux` session so it survives your SSH disconnect but you still typed the passphrase in interactively:

```bash
tmux new -s wks-diary-core
cd /opt/wks-diary-core/rust && ./target/release/wks-server
# type your passphrase when prompted, then Ctrl+B D to detach
```

## 6. Reverse proxy with TLS

`BIND_ADDR=127.0.0.1:8080` keeps the raw API local-only. Put Caddy in front:

```bash
sudo apt install -y caddy
sudo tee /etc/caddy/Caddyfile > /dev/null <<'EOF'
your-domain.tld {
    reverse_proxy 127.0.0.1:8080
}
EOF
sudo systemctl reload caddy
```

## 7. Quick check

```bash
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/version
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/history
```

## 8. Set up the Python client (any device you write your diary on)

```bash
pip install pynacl requests
python wks_diary_core.py
```

Enter your vault passphrase, `WKS_API_KEY`, the backend URL, and a device name (e.g. `laptop`, `phone`) when prompted. Only the salt/API key/URL/device name get saved to `.env` if you choose to -- the passphrase itself is never written to disk.

## 9. First run

1. Create `vault/` locally with `diary/`, `people/`, `misc/` subfolders, write `.md` files following `SYNTAX.md`.
2. Menu option 1 (Lock) to produce `vault.wks`.
3. Menu option 5 (Push) to send it to the VPS for the first time.
4. On any other device: option 4 (Pull), then unlock.

## 10. Recovering from a mistake

```
8) Show history       -> lists every past version, device name, and pruned status
9) Restore            -> pick a hash from that list, server makes it current again
```

If a version shows `pruned`, its blob content is gone (per `RETENTION_DAYS`) but the metadata (hash/timestamp/size/device) remains visible forever -- restoring it will return `410 Gone`.

## 11. Off-site backups

```bash
chmod +x backup.sh
export STORAGE_DIR=/opt/wks-diary-core/storage
export BACKUP_TARGET=user@backup-host:/backups/wks-diary-core/
./backup.sh
```

Add it to cron:
```bash
crontab -e
# 0 3 * * * STORAGE_DIR=/opt/wks-diary-core/storage BACKUP_TARGET=user@backup-host:/backups/wks-diary-core/ /opt/wks-diary-core/backup.sh >> /var/log/wks-backup.log 2>&1
```

Everything under `STORAGE_DIR` is encrypted except `log.json`'s metadata (hashes/timestamps/sizes/device names, never content) -- safe to back up as-is.
