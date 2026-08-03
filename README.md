# wks-diary-core

`wks-diary-core` is a local-first, encrypted personal diary/knowledge vault. Two components, no third-party naming baggage:

| Component | Language | Role |
|---|---|---|
| `rust/` | Rust | The backend: an always-online server that stores, serves, merges, and **versions** encrypted vault blobs -- restorable like Git commits. |
| `python/` | Python | The single-file interactive client: run it, enter your key(s) once, then lock/unlock/validate/merge/push/pull/history/restore from one menu. |

## 1. Data model

```
vault/
  diary/kapitel-01/2026-08-03.txt
  people/max_mustermann.txt
  misc/ideen.txt
  .meta/last_sync.json
```

Markup syntax (`*name*` mentions, `[[links]]`, `#tags`, alias definitions) is documented in `SYNTAX.md` and `SYNTAX_EXAMPLES.md`.

## 2. Encryption & compression pipeline

Compress the whole `vault/` directory into a ZIP, then encrypt with XChaCha20-Poly1305 (libsodium-compatible, 24-byte nonce), giving one opaque `vault.wks` blob. Reverse for unlock. Both the Rust backend and the Python client use the exact same construction, so blobs are interchangeable between them.

## 3. Rust backend (`rust/`)

An Axum HTTP server with five endpoints:

- `GET /version` -> `{hash, updated_at, size, version}` of the current blob
- `GET /pull` -> streams the current `vault.wks`
- `POST /push` -> multipart `file` (+ optional `expected_base_hash`); fast-forwards, or auto-merges file-by-file on conflict
- `GET /history` -> the full version log, newest first -- every push, merge, and restore ever made, like `git log`
- `POST /restore` -> JSON `{"hash": "<hash>"}`; makes any past version current again, like `git checkout <commit> --`

### How versioning/restore works (the "GitHub-style" part)

Every time the current blob changes -- first push, fast-forward, merge, or restore -- the server:

1. Copies whatever was current into `storage/history/<old_hash>.wks` (nothing is ever silently deleted).
2. Appends an entry to `storage/log.json`: `{version, hash, size, updated_at, mode}`.
3. Writes the new blob as the new `vault.wks` and updates `storage/meta.json`.

`GET /history` just returns that log, newest first. `POST /restore {"hash": "..."}` looks the requested hash up in `storage/history/`, archives the current blob first (so restoring is itself non-destructive and can be undone), and makes the target the new current version -- exactly like checking out an old commit and having it become your new HEAD. Nothing is ever overwritten without a copy surviving in history first.

Config via `.env` (see `rust/env.example.txt`): `WKS_API_KEY`, `WKS_VAULT_KEY` (32 bytes hex, must match your clients), `STORAGE_DIR`, `MAX_UPLOAD_BYTES`, `BIND_ADDR`.

## 4. Python client (`python/wks_diary_core.py`)

```bash
pip install pynacl requests
python wks_diary_core.py
```

Prompts for `WKS_VAULT_KEY`, `WKS_API_KEY`, and the backend URL once, then shows a menu:

1. Lock `vault/` -> `vault.wks`
2. Unlock `vault.wks` -> `vault/`
3. Validate syntax
4. Pull from backend
5. Push to backend (auto-merges on conflict, pulls+unlocks the merged result)
6. Local merge -- merge two `vault.wks` files entirely offline, no backend
7. Check backend version
8. Show history (like `git log`)
9. Restore to a past version (like `git checkout`)
0. Quit

## 5. Merge strategy

File-level three-way merge, implemented identically in Rust and Python:

- Unchanged on one side, changed on the other -> take the changed version.
- Changed identically on both sides -> take either.
- Changed differently on both sides -> conflict: file gets `<<<<<<< remote / ======= / >>>>>>> incoming` markers, filename listed in the report.
- Deleted on one side, unchanged on the other -> deletion wins.
- Deleted on one side, edited on the other -> conflict, edited version kept but flagged.

Available online (server-side, via push) or fully offline (client-side, menu option 6).

## 6. Threat model

The backend holds `WKS_VAULT_KEY` and decrypts in memory during merges and restores -- only run it on infrastructure you fully control. `WKS_API_KEY` and `WKS_VAULT_KEY` are separate secrets: losing the API key only allows push/pull/merge/restore junk; losing the vault key exposes plaintext. Keep `.env` out of git everywhere. Because every past state is preserved in `storage/history/`, a single accidental bad push or merge is always recoverable via `/restore` -- nothing is destructive by default.

## 7. Repository layout

```
wks-diary-core/
  README.md
  INSTALL.md
  SYNTAX.md
  SYNTAX_EXAMPLES.md
  rust/
    Cargo.toml
    src/main.rs
    env.example.txt
  python/
    wks_diary_core.py
```

See `INSTALL.md` for step-by-step VPS setup.
