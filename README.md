# wks-diary-core

`wks-diary-core` is version control for your own head. It takes the exact mechanics that make Git trustworthy for code -- commits, branches-by-device, three-way merges, a full history, and checkout/restore -- and applies them to a private, end-to-end encrypted "second brain": your diary, the people in your life, and everything else you'd normally lose in a pile of loose notes.

You don't "save a file." You **push a new version of your mind**, from whichever device you're on, and the system reconciles it against everything else you've ever written -- automatically, line by line, the same way a merge works in a code repository.

## 1. The mental model

| Git concept | Here |
|---|---|
| Repository | Your vault (`diary/`, `people/`, `misc/`) |
| Commit | A `push` -- a new encrypted snapshot of the whole vault |
| Clone / fetch | `pull` -- get the current snapshot onto a device |
| Working directory | The decrypted `vault/` folder you actually write in |
| Merge | Automatic, line-level, three-way (base / remote / your edit) |
| Merge conflict | `<<<<<<< / ======= / >>>>>>>` markers around just the disputed lines |
| `git log` | `history` -- every version ever pushed, who pushed it, when |
| `git checkout <commit>` | `restore` -- make any past version current again |
| Branch | Each device is effectively its own branch until it pushes |

The Rust backend (`rust/`) is the only component -- it runs continuously on a machine you control, stores the encrypted vault and version history, performs line-level merges, validates markup on every push, and rate-limits access. Any HTTP client (curl, your own script, a future GUI) can talk to it.

Vault files use the `.md` extension throughout.

## 2. Why treat a diary like a repository

A normal notes app has one copy of the truth, and if two devices edit it at once, one edit just loses. That's fine for code because Git solved it decades ago: never let a second writer silently destroy the first writer's work, always look for a common ancestor, and only ask a human when there's a genuine, unresolvable conflict. There's no reason a personal knowledge base should have worse guarantees than a codebase. `wks-diary-core` gives your thoughts the same non-destructive, always-recoverable, always-mergeable properties -- while keeping the actual content unreadable to the server that stores it.

## 3. How a push actually gets merged

1. Every device remembers the hash of the last version it pulled (its "base").
2. On push, if the server's current version still matches that base, it's a **fast-forward** -- plain overwrite, no merge needed, exactly like a Git fast-forward.
3. If the server has moved on (another device pushed first), the backend fetches the base, the server's current version, and your incoming push -- all encrypted -- decrypts them in memory, and runs a **line-level three-way merge** per file (via the `similar` diff engine): a diff of base-to-remote and base-to-incoming, walked together.
   - Non-overlapping edits (you added a paragraph, another device fixed a typo elsewhere) merge with zero manual work.
   - Only genuinely overlapping edits to the same lines get conflict markers, and only around that one stretch -- never the whole file.
4. The merged result becomes the new current version. The version you overwrote **and** the raw upload you sent are both archived first, so nothing is lost even if a merge turns out badly.

## 4. History and restore

Every push -- fast-forward, merge, or restore itself -- is one entry in an append-only log: hash, timestamp, size, which device made it, and whether it was a clean push or a merge. `history` shows this newest-first, like `git log`. `restore` takes any past hash and makes it current again, archiving whatever was current first -- so restoring is itself undoable. **Nothing is ever deleted automatically.** Old blobs stay until you explicitly run `wks-server prune --older-than-days N [--keep-weekly] --yes` (dry run without `--yes`). Even then the current version is never touched, and the log entry (hash, timestamp, device) survives forever.

### Data-safety guarantees (v0.5.0)

- No automatic pruning/retention -- deleting old data always needs an explicit command.
- Every upload is archived in `history/` before it is merged or replaces anything; the current version is archived before it is overwritten, and if archiving fails the push/restore is aborted.
- All files (`vault.wks`, `meta.json`, `log.json`, history blobs) are written atomically (temp file + fsync + rename), so a crash can't leave truncated data.
- A corrupt `log.json` is never overwritten with an empty one (the server refuses to continue and keeps a `.corrupt-*` copy); a missing/corrupt/stale `meta.json` is rebuilt from the real `vault.wks`.
- Uploads that can't be decrypted with the server's vault key are rejected (HTTP 400) and never become the current version.
- A push without `expected_base_hash` onto an existing vault is rejected (HTTP 409) unless `force=yes` is sent, so a device can't silently overwrite another device's state.
- `backup.sh` no longer uses `rsync --delete`.

## 5. Data model

```
vault/
  diary/kapitel-01/2026-08-03.md
  people/max_mustermann.md
  misc/ideen.md
  .meta/last_sync.json
```

Markup syntax (`*name*` mentions, `[[links]]`, `#tags`, alias definitions) is documented in `SYNTAX.md` and `SYNTAX_EXAMPLES.md`.

## 6. Security properties

- **Encryption**: XChaCha20-Poly1305, vault key derived from a passphrase (Argon2id) or a raw stored key, depending on which mode you choose for a given device.
- **Two independent secrets**: an API key (gets you push/pull access, rate-limited against brute force) and a vault key (the only thing that can actually decrypt your content). Losing one doesn't expose the other.
- **Validation on every push**: the backend checks your markup (unresolved mentions, broken links, alias conflicts) and hands the report straight back to you.
- **No public exposure by accident**: the backend refuses to bind to a non-loopback address unless you explicitly opt in, so it can't accidentally end up reachable without a TLS proxy in front.

## 7. Backend endpoints

- `GET /version` -> current `{hash, updated_at, size, version}`
- `GET /pull` -> streams the current encrypted vault
- `POST /push` -> multipart `file` (+ `expected_base_hash`, `device_name`, optional `force=yes`); fast-forwards or line-level merges, returns a validation report
- `GET /history` -> full version log, newest first
- `POST /restore` -> `{"hash": "..."}`, makes a past version current again

Config via `.env` (see `rust/env.example.txt`): `WKS_API_KEY`, `WKS_VAULT_KEY` or `WKS_VAULT_SALT`, `STORAGE_DIR`, `MAX_UPLOAD_BYTES`, `BIND_ADDR` + `WKS_ALLOW_PUBLIC_BIND`, `RATE_LIMIT_MAX_FAILURES`, `RATE_LIMIT_WINDOW_SECS`.

## 8. Repository layout

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
```

See `INSTALL.md` for step-by-step VPS setup.
