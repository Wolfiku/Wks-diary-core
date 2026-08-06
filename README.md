# wks-diary-core

`wks-diary-core` is a local-first, encrypted personal diary/knowledge vault. Two components: a Rust backend and a Python client.

| Component | Language | Role |
|---|---|---|
| `rust/` | Rust | Always-online server: stores, serves, LINE-LEVEL merges, versions, prunes, validates, and rate-limits access to encrypted vault blobs. |
| `python/` | Python | Single-file interactive client: enter your passphrase once, then lock/unlock/validate/merge/push/pull/history/restore from one menu. |

Vault files use the **`.md`** extension throughout (changed from an earlier `.txt` draft -- everything here renders fine as normal Markdown).

## 1. What's new in this revision

1. **Line-level merge (the big one).** Conflicts used to mark an entire file as conflicting the moment both sides touched it. Now the backend (and the Python client's offline mode) run a real diff3-style line-level merge: non-overlapping edits to the same file -- e.g. one device appends a paragraph, another fixes a typo elsewhere -- merge automatically with zero manual work. Only genuinely overlapping edits get `<<<<<<< / ======= / >>>>>>>` markers, scoped to just the conflicting lines.
2. **Passphrase-derived keys.** Instead of a raw 32-byte key sitting in `.env`, the Python client now derives the vault key from a passphrase you type each run (Argon2id via PyNaCl). Only a non-secret salt is ever persisted. The Rust backend supports the same passphrase mode for manual starts, with raw-key mode kept for unattended systemd restarts (documented trade-off, see `rust/env.example.txt`).
3. **Rate limiting.** The backend tracks failed `X-API-KEY` attempts in a sliding window and returns `429` once too many failures happen in too short a time, mitigating brute-force key guessing.
4. **History retention.** Old encrypted blobs beyond `RETENTION_DAYS` get pruned down to one snapshot per calendar week. Log metadata (hash/timestamp/size/device) is kept forever regardless -- you can always see *that* a version existed, even after its blob content has been pruned.
5. **Server-side validation on every push.** The backend now returns a validation report (unresolved mentions, broken links, alias errors) in the push response, so syntax problems show up immediately instead of only on your next local `validate` run.
6. **Backup helper.** `backup.sh` for a cron-driven off-site rsync/restic backup of `STORAGE_DIR` -- safe to run as-is since everything in there is already encrypted.
7. **Bind-address safety check.** The backend refuses to start on a non-loopback address unless you explicitly set `WKS_ALLOW_PUBLIC_BIND=yes`, so accidentally exposing the raw API without a TLS reverse proxy in front is a lot harder.
8. **Device-tagged history.** Every push can include a `device_name`, stored in the version log, so you can tell which machine made which change when troubleshooting.

## 2. Data model

```
vault/
  diary/kapitel-01/2026-08-03.md
  people/max_mustermann.md
  misc/ideen.md
  .meta/last_sync.json
```

Markup syntax (`*name*` mentions, `[[links]]`, `#tags`, alias definitions) is documented in `SYNTAX.md` and `SYNTAX_EXAMPLES.md`.

## 3. Rust backend (`rust/`)

Endpoints:

- `GET /version` -> `{hash, updated_at, size, version}`
- `GET /pull` -> streams current `vault.wks`
- `POST /push` -> multipart `file` (+ `expected_base_hash`, `device_name`); fast-forwards, or line-level auto-merges on conflict; response includes a validation report
- `GET /history` -> full version log, newest first, including device names and pruned status
- `POST /restore` -> JSON `{"hash": "..."}`, makes a past version current again (410 Gone if that blob was pruned)

Config via `.env` (see `rust/env.example.txt`): `WKS_API_KEY`, `WKS_VAULT_KEY` (Mode A) or `WKS_VAULT_SALT` (Mode B, passphrase prompt), `STORAGE_DIR`, `MAX_UPLOAD_BYTES`, `BIND_ADDR` + `WKS_ALLOW_PUBLIC_BIND`, `RETENTION_DAYS`, `RATE_LIMIT_MAX_FAILURES`, `RATE_LIMIT_WINDOW_SECS`.

## 4. Python client (`python/wks_diary_core.py`)

```bash
pip install pynacl requests
python wks_diary_core.py
```

Prompts for your vault passphrase (or uses a legacy raw `WKS_VAULT_KEY` if still present), the backend API key, URL, and a device name, then shows a menu:

1. Lock `vault/` -> `vault.wks`
2. Unlock `vault.wks` -> `vault/`
3. Validate syntax
4. Pull from backend
5. Push to backend (line-level auto-merge on conflict, pulls+unlocks the result, shows the server's validation report)
6. Local merge -- line-level merge two `vault.wks` files entirely offline, no backend
7. Check backend version
8. Show history (device names, pruned status, like `git log`)
9. Restore to a past version (like `git checkout`)
0. Quit

## 5. How the line-level merge works

For each conflicting file where a common ancestor (`base`) exists, the merge diffs `base -> remote` and `base -> incoming` independently (Myers diff, via the `similar` crate in Rust / `difflib` in Python), then walks both diffs together:

- A stretch of lines unchanged in both -> kept as-is.
- Changed in only one side -> that side's version is taken.
- Changed identically in both -> either (they agree).
- Changed differently in both, in the *same* stretch of lines -> `<<<<<<< / ======= / >>>>>>>` markers around just that stretch.

Binary files, or files with no shared ancestor (e.g. a brand-new file independently created on both sides with different content), fall back to the old whole-file conflict marker -- always correct, just less automatic.

## 6. Threat model

The backend holds the vault key and decrypts on every push (for validation) as well as during merges and restores -- only run it on infrastructure you fully control. `WKS_API_KEY` and the vault key/passphrase are separate secrets with separate blast radii. Rate limiting slows down online key-guessing; it does not protect against someone who already has your `.env`. Because every past state is preserved (subject to the retention/pruning policy), a bad push or merge is recoverable via `/restore` as long as its blob hasn't been pruned yet.

## 7. Repository layout

```
wks-diary-core/
  README.md
  INSTALL.md
  SYNTAX.md
  SYNTAX_EXAMPLES.md
  backup.sh
  rust/
    Cargo.toml
    src/main.rs
    env.example.txt
  python/
    wks_diary_core.py
```

See `INSTALL.md` for step-by-step VPS setup.
