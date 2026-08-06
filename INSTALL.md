# Installing wks-diary-core

This guide covers installing the Rust backend on any server you control (VPS, home server, Raspberry Pi, a spare laptop) and connecting the Python client from any device. It's written to be provider-agnostic -- swap in whichever Linux distro, reverse proxy, or process manager you already use.

## 1. What you're setting up

Two independent pieces:

- **Backend** (`rust/`) -- one binary (`wks-server`), runs continuously, holds the encrypted vault and version history. Needs exactly one always-reachable machine.
- **Client** (`python/wks_diary_core.py`) -- runs on every device you actually write from. No server-side install needed for this part.

You only need to follow the backend steps once, on one machine. Repeat the client steps on as many devices as you want.

## 2. Prerequisites

Any Linux server with:

- A recent 64-bit Linux distribution (Debian, Ubuntu, Fedora, Alpine, etc.)
- `curl`, `build-essential` (or your distro's equivalent C toolchain), `rsync` if you plan to use the backup script
- A way to keep a process running after you disconnect: `systemd`, `tmux`/`screen`, Docker, or a process supervisor of your choice
- A reverse proxy capable of TLS termination if you expose this beyond localhost: Caddy, Nginx, Traefik, or a managed load balancer -- any of them work, this guide shows Caddy as the simplest example

Install the Rust toolchain if you're building natively:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

If you'd rather not install a Rust toolchain on the server itself, build the binary elsewhere (your laptop, CI, a throwaway container) for the same target architecture and just copy the resulting `target/release/wks-server` binary over -- the backend has no runtime dependency beyond libc.

## 3. Get the code

Clone directly, or download the files however you prefer:

```bash
git clone https://github.com/Wolfiku/Wks-diary-core.git
cd Wks-diary-core
```

## 4. Choose a vault key mode

The backend needs the same 32-byte encryption key your clients use, because it decrypts in memory during merges, restores, and push-time validation. Pick one:

| Mode | How | Best for |
|---|---|---|
| **A -- raw key** | Set `WKS_VAULT_KEY` to a random hex string in `.env` | Unattended servers that restart themselves after a crash or reboot |
| **B -- passphrase** | Set `WKS_VAULT_SALT` instead (no `WKS_VAULT_KEY`); the process prompts for a passphrase on every start | Servers you start by hand and don't need to self-heal without you |

Neither mode is "more correct" -- it's a straight trade-off between at-rest exposure and unattended uptime. If you're not sure, start with Mode A; you can switch later.

## 5. Configure `.env`

```bash
cd rust
cp env.example.txt .env
openssl rand -hex 32   # -> WKS_API_KEY
openssl rand -hex 32   # -> WKS_VAULT_KEY (Mode A) or WKS_VAULT_SALT (Mode B)
$EDITOR .env
chmod 600 .env
```

Every variable, what it does, and safe defaults:

| Variable | Purpose | Default |
|---|---|---|
| `WKS_API_KEY` | Required on every request (`X-API-KEY` header). Compromise = someone can push/pull junk, rate-limited. | none, must set |
| `WKS_VAULT_KEY` | Raw 32-byte hex encryption key (Mode A). Compromise = your content is exposed. | none |
| `WKS_VAULT_SALT` | Non-secret salt for passphrase derivation (Mode B). Use instead of `WKS_VAULT_KEY`. | none |
| `STORAGE_DIR` | Where encrypted blobs, history, and the log live. | `./storage` |
| `MAX_UPLOAD_BYTES` | Upload size cap. | 50 MB |
| `BIND_ADDR` | Listen address. Must be loopback unless you opt in below. | `127.0.0.1:8080` |
| `WKS_ALLOW_PUBLIC_BIND` | Set to `yes` only if you really want to skip a reverse proxy. | `no` |
| `RETENTION_DAYS` | Full history kept this long; older blobs pruned to weekly snapshots. | 30 |
| `RATE_LIMIT_MAX_FAILURES` | Failed auth attempts allowed per window before `429`. | 10 |
| `RATE_LIMIT_WINDOW_SECS` | Length of that window. | 60 |

Whichever key/passphrase you choose must be identical on every client device. Store it in a password manager, not just in your head.

## 6. Build

```bash
cargo build --release
mkdir -p storage
```

The binary lands at `target/release/wks-server`. This is the only artifact you need on the server going forward -- you can delete the `target/debug` directory and source checkout afterward if you prefer a minimal footprint, as long as you keep `.env` and `storage/`.

## 7. Run it continuously

Pick whichever fits your setup. All three do the same thing: keep `wks-server` running and restart it if it crashes.

**systemd** (works well with Mode A; Mode B needs a human to type the passphrase, so skip to the tmux option below for that mode):

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

**tmux/screen** (needed for Mode B, also fine for Mode A if you don't want a systemd unit):

```bash
tmux new -s wks-diary-core
./target/release/wks-server
# type your passphrase if prompted, then Ctrl+B D to detach
```

**Docker**, if you'd rather containerize (write your own minimal Dockerfile around the built binary, e.g. `FROM debian:bookworm-slim`, copy the binary and `.env`/`storage` as a mounted volume, `EXPOSE` nothing beyond loopback, run with `--restart unless-stopped`). Not included here since the exact base image and orchestration depend on your existing setup.

## 8. Put a reverse proxy in front

`BIND_ADDR=127.0.0.1:8080` keeps the raw API off the public internet. Terminate TLS in front of it with whatever you already run:

**Caddy** (simplest, automatic certificates):
```bash
your-domain.tld {
    reverse_proxy 127.0.0.1:8080
}
```

**Nginx**:
```nginx
server {
    listen 443 ssl;
    server_name your-domain.tld;
    ssl_certificate     /etc/letsencrypt/live/your-domain.tld/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.tld/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Either way, only ports 80/443 (or whatever your proxy uses) need to be open on your firewall; port 8080 stays local-only. With `ufw`, for example: `sudo ufw allow 443/tcp` and nothing else for this service.

## 9. Verify every endpoint

```bash
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/version
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/history
curl -H "X-API-KEY: <WKS_API_KEY>" https://your-domain.tld/pull -o /dev/null -w "%{http_code}\n"
```

A fresh install returns `{"hash":null,...}` from `/version`, `[]` from `/history`, and `404` from `/pull` until the first push happens -- all of that is expected.

## 10. Set up the client on every writing device

```bash
pip install pynacl requests
python wks_diary_core.py
```

You'll be prompted for: the vault passphrase (or it reads a legacy raw key if one is already in a local `.env`), the backend API key, the backend URL, and a device name (used only in the version log so you can tell devices apart later). Only the salt, API key, URL, and device name are ever saved locally if you opt in -- the passphrase itself is never written to disk on any device.

## 11. First real use

1. Create a `vault/` folder next to the client script with `diary/`, `people/`, `misc/` subfolders, and start writing `.md` files following `SYNTAX.md`.
2. Menu option 1 (Lock) to produce `vault.wks`.
3. Menu option 5 (Push) to send it to the backend for the first time.
4. On any other device, repeat the client setup, then option 4 (Pull) followed by unlock.

From here on, edit freely on any device; pushes fast-forward when nothing else changed, or merge automatically line-by-line when something did.

## 12. Recovering from a mistake

```
8) Show history   -> every past version, its hash, device, and whether it's been pruned
9) Restore        -> pick a hash, the backend makes it current again
```

If an entry shows as pruned, its content is gone per your `RETENTION_DAYS` setting but the metadata (hash, timestamp, size, device) stays visible forever; restoring a pruned hash returns `410 Gone`.

## 13. Off-site backups

Everything under `STORAGE_DIR` is encrypted except the log's metadata (hashes, timestamps, sizes, device names -- never content), so it's safe to back up as-is with any tool:

```bash
chmod +x backup.sh
STORAGE_DIR=/opt/wks-diary-core/rust/storage \
BACKUP_TARGET=user@backup-host:/backups/wks-diary-core/ \
./backup.sh
```

Add it to cron or your scheduler of choice; the script itself also documents a `restic` alternative for deduplicated, generation-based backups if you prefer that over plain `rsync`.

## 14. Updating to a newer version later

```bash
git pull
cargo build --release
sudo systemctl restart wks-diary-core   # or re-attach your tmux session
```

Your `.env` and `storage/` are untouched by a `git pull` since they're not tracked in the repository -- only the code changes.

## 15. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Server exits immediately with "refusing to start: BIND_ADDR ... is not loopback-only" | You set a public `BIND_ADDR` without opting in | Set `BIND_ADDR=127.0.0.1:8080` and put a reverse proxy in front, or set `WKS_ALLOW_PUBLIC_BIND=yes` if that's genuinely what you want |
| "failed to read passphrase from stdin" on startup | Using Mode B under systemd (no TTY) | Either switch to Mode A, or run manually via tmux/screen instead of systemd |
| `401 unauthorized` from every request | Wrong or missing `X-API-KEY` header | Double-check the header name casing and that the client's `.env`/prompt matches the server's `WKS_API_KEY` exactly |
| `429 too many failed auth attempts` | Rate limiter tripped, usually from a typo'd key retried repeatedly | Wait out `RATE_LIMIT_WINDOW_SECS`, then double-check the key |
| `409 conflict` on push that never resolves | The base version referenced by the client is no longer in `storage/history/` (may have been pruned) | Pull the current version fresh, re-apply your local edits, and push again without an `expected_base_hash` |
| `410 Gone` on restore | That version's blob was pruned by retention policy | Only the metadata survives; the content itself is unrecoverable if it was pruned |
| Push succeeds but `validation.errors` is non-empty | A `people/*.md` file is missing its definition line, or has a filename mismatch | Fix the flagged file locally, then push again |
| `cargo build` fails on a fresh server | Missing C toolchain or OpenSSL headers | Install your distro's build-essential/gcc package and retry |
