#!/usr/bin/env python3
"""
wks-diary-core -- single-file interactive client.

Run it, enter your passphrase once, then use the menu for everything:
lock, unlock, validate, local merge, push, pull, history, restore.

Vault files use the .md extension throughout (renamed from an earlier
.txt draft). This client is wire-compatible with the Rust backend:
both use XChaCha20-Poly1305 (24-byte nonce) via libsodium.

Key handling: instead of storing the raw 32-byte encryption key in
.env, this client derives it from a passphrase you type each run,
using Argon2id (via PyNaCl's pwhash module, same algorithm family the
Rust backend uses). Only a non-secret random salt is ever written to
.env -- the actual key never touches disk. If you still have an old
raw WKS_VAULT_KEY in .env from a previous version, it's used directly
for backward compatibility, but passphrase mode is recommended.

Requires: pip install pynacl requests
"""

import getpass
import hashlib
import io
import json
import os
import re
import shutil
import sys
import zipfile
import difflib
from pathlib import Path

import requests
from nacl import pwhash
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as _encrypt_raw,
    crypto_aead_xchacha20poly1305_ietf_decrypt as _decrypt_raw,
)

NONCE_LEN = 24
SALT_LEN = 16
ENV_PATH = Path(".env")
VAULT_DIR = Path("vault")
BLOB_FILE = Path("vault.wks")
META_FILE = Path(".meta/last_sync.json")

STATE = {}


def load_env_file():
    env = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def save_env_file(env):
    lines = [f"{k}={v}" for k, v in env.items()]
    ENV_PATH.write_text("\n".join(lines) + "\n")


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Argon2id KDF -- same algorithm the Rust backend uses for passphrase mode."""
    return pwhash.argon2id.kdf(
        32, passphrase.encode("utf-8"), salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE,
        memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
    )


def bootstrap():
    env = load_env_file()

    if env.get("WKS_VAULT_KEY"):
        # legacy raw-key mode, kept for backward compatibility
        key_bytes = bytes.fromhex(env["WKS_VAULT_KEY"])
        if len(key_bytes) != 32:
            print("ERROR: WKS_VAULT_KEY must decode to exactly 32 bytes.")
            sys.exit(1)
        print("using legacy raw WKS_VAULT_KEY from .env -- consider switching to passphrase mode.")
    else:
        salt_hex = env.get("WKS_VAULT_SALT")
        if not salt_hex:
            salt = os.urandom(SALT_LEN)
            salt_hex = salt.hex()
            print("no salt found -- generated a new one. This is NOT a secret, safe to store in .env.")
        else:
            salt = bytes.fromhex(salt_hex)
        passphrase = getpass.getpass("Vault passphrase: ")
        key_bytes = derive_key_from_passphrase(passphrase, salt)
        env["WKS_VAULT_SALT"] = salt_hex

    api_key = env.get("WKS_API_KEY") or getpass.getpass("Backend API key (leave empty if offline-only): ").strip()
    backend_url = env.get("WKS_BACKEND_URL") or input("Backend URL (leave empty if offline-only): ").strip()
    device_name = env.get("WKS_DEVICE_NAME") or input("Device name (for the version log, e.g. 'laptop'): ").strip() or "unknown-device"

    STATE["vault_key"] = key_bytes
    STATE["api_key"] = api_key
    STATE["backend_url"] = backend_url.rstrip("/")
    STATE["device_name"] = device_name

    if not ENV_PATH.exists():
        if input("Save salt/API key/URL/device name to .env for next time? (passphrase is NEVER saved) [y/N]: ").lower() == "y":
            save_env_file({
                "WKS_VAULT_SALT": env["WKS_VAULT_SALT"],
                "WKS_API_KEY": api_key,
                "WKS_BACKEND_URL": backend_url,
                "WKS_DEVICE_NAME": device_name,
            })
            print("saved .env (contains no secrets except the API key -- gitignore it anyway)")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = _encrypt_raw(plaintext, None, nonce, key)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes) -> bytes:
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return _decrypt_raw(ciphertext, None, nonce, key)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def zip_directory(vault_dir: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(vault_dir):
            for name in files:
                full = Path(root) / name
                rel = full.relative_to(vault_dir)
                zf.write(full, arcname=str(rel).replace(os.sep, "/"))
    return buf.getvalue()


def unzip_to_directory(zip_bytes: bytes, dest: Path):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(dest)


def zip_to_map(zip_bytes: bytes) -> dict:
    m = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            m[info.filename] = zf.read(info.filename)
    return m


def map_to_zip(m: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(m.keys()):
            zf.writestr(path, m[path])
    return buf.getvalue()


# --------------------------------------------------------------------------
# Line-level three-way merge (diff3-style). Falls back to whole-file
# conflict markers for binary content or files with no common ancestor.
# --------------------------------------------------------------------------

def _build_segments(base_lines, other_lines):
    sm = difflib.SequenceMatcher(None, base_lines, other_lines, autojunk=False)
    segs, pending = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        content = other_lines[j1:j2]
        if i1 == i2:
            pending.extend(content)
            continue
        segs.append({"start": i1, "end": i2, "tag": tag, "content": pending + content})
        pending = []
    if pending:
        if segs:
            segs[-1]["content"] = segs[-1]["content"] + pending
        else:
            segs.append({"start": 0, "end": len(base_lines), "tag": "replace", "content": pending})
    return segs


def merge_lines_3way(base: bytes, remote: bytes, incoming: bytes):
    """Returns (merged_bytes, had_conflict) or None if line-level merge doesn't apply."""
    try:
        base_lines = base.decode("utf-8").splitlines(keepends=True)
        remote_lines = remote.decode("utf-8").splitlines(keepends=True)
        incoming_lines = incoming.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None
    if not base_lines:
        return None

    r_segs = _build_segments(base_lines, remote_lines)
    i_segs = _build_segments(base_lines, incoming_lines)

    result, had_conflict = [], False
    ir = ii = 0
    pos = 0
    base_len = len(base_lines)

    while pos < base_len:
        r_group, i_group = [r_segs[ir]], [i_segs[ii]]
        ir2, ii2 = ir + 1, ii + 1
        while r_group[-1]["end"] != i_group[-1]["end"]:
            if r_group[-1]["end"] < i_group[-1]["end"]:
                r_group.append(r_segs[ir2]); ir2 += 1
            else:
                i_group.append(i_segs[ii2]); ii2 += 1
        end = r_group[-1]["end"]
        ir, ii = ir2, ii2

        base_slice = base_lines[pos:end]
        r_all_equal = all(s["tag"] == "equal" for s in r_group)
        i_all_equal = all(s["tag"] == "equal" for s in i_group)

        if r_all_equal and i_all_equal:
            result.extend(base_slice)
        else:
            r_content = base_slice if r_all_equal else sum((s["content"] for s in r_group), [])
            i_content = base_slice if i_all_equal else sum((s["content"] for s in i_group), [])
            if r_content == i_content:
                result.extend(r_content)
            elif r_all_equal:
                result.extend(i_content)
            elif i_all_equal:
                result.extend(r_content)
            else:
                had_conflict = True
                result.append("<<<<<<< remote\n")
                result.extend(r_content)
                result.append("=======\n")
                result.extend(i_content)
                result.append(">>>>>>> incoming\n")
        pos = end

    return "".join(result).encode("utf-8"), had_conflict


def three_way_merge(base: dict, remote: dict, incoming: dict):
    keys = set(base) | set(remote) | set(incoming)
    merged, conflicts = {}, []

    for key in keys:
        b, r, i = base.get(key), remote.get(key), incoming.get(key)

        if r is not None and i is not None and r == i:
            merged[key] = r
        elif b is not None and r is not None and i is not None and b == r and b != i:
            merged[key] = i
        elif b is not None and r is not None and i is not None and b == i and b != r:
            merged[key] = r
        elif b is None and r is None and i is not None:
            merged[key] = i
        elif b is None and r is not None and i is None:
            merged[key] = r
        elif b is not None and r is None and i is not None and b == i:
            pass
        elif b is not None and r is not None and i is None and b == r:
            pass
        elif b is not None and r is None and i is None:
            pass
        elif r is not None and i is not None:
            lm = merge_lines_3way(b, r, i) if b is not None else None
            if lm is not None:
                merged_bytes, had_conflict = lm
                merged[key] = merged_bytes
                if had_conflict:
                    conflicts.append(key)
            else:
                merged[key] = (
                    b"<<<<<<< remote\n" + r + b"\n=======\n" + i + b"\n>>>>>>> incoming\n"
                )
                conflicts.append(key)
        elif r is None and i is not None:
            merged[key] = i
            conflicts.append(f"{key} (deleted remotely, edited locally)")
        elif r is not None and i is None:
            merged[key] = r
            conflicts.append(f"{key} (deleted locally, edited remotely)")

    return merged, conflicts


# --------------------------------------------------------------------------
# Syntax validation (see SYNTAX.md) -- vault files are .md now
# --------------------------------------------------------------------------

DEF_RE = re.compile(r"^\[\*(.+?)\[(.+?)\]\*\]$")
ALIAS_RE = re.compile(r"^\[aliases:\s*(.+?)\]$")
MENTION_RE = re.compile(r"(?<!\\)\*([^*\\]+)\*")
LINK_RE = re.compile(r"\[\[([^\]|#]+)(?:#([^\]|]+))?(?:\|([^\]]+))?\]\]")


def collect_people(vault_dir: Path):
    people_dir = vault_dir / "people"
    people = []
    if not people_dir.is_dir():
        return people
    for path in sorted(people_dir.glob("*.md")):
        filename = path.name
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if not lines:
            raise ValueError(f"{filename}: empty file")
        m = DEF_RE.match(lines[0].strip())
        if not m:
            raise ValueError(f"{filename}: missing/invalid definition line")
        display_name, declared_file = m.group(1).strip(), m.group(2).strip()
        if declared_file != filename:
            raise ValueError(f"{filename}: self-mismatch ('{declared_file}' != '{filename}')")
        aliases = [display_name]
        if len(lines) > 1:
            am = ALIAS_RE.match(lines[1].strip())
            if am:
                aliases += [a.strip() for a in am.group(1).split(",")]
        people.append({"display_name": display_name, "filename": filename, "aliases": aliases})
    return people


def build_alias_table(people):
    table = {}
    for p in people:
        for alias in p["aliases"]:
            table.setdefault(alias, []).append(p["filename"])
    for alias, files in table.items():
        if len(files) > 1:
            raise ValueError(f"duplicate alias '{alias}' in: {', '.join(files)}")
    return table


def validate_vault(vault_dir: Path):
    people = collect_people(vault_dir)
    alias_table = build_alias_table(people)
    known_paths = {
        str(p.relative_to(vault_dir).with_suffix("")).replace("\\", "/")
        for p in sorted(vault_dir.rglob("*.md"))
    }
    unresolved, broken_links = [], []
    for path in sorted(vault_dir.rglob("*.md")):
        rel = str(path.relative_to(vault_dir))
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("//"):
                continue
            for m in MENTION_RE.finditer(line):
                token = m.group(1).strip()
                if token not in alias_table:
                    unresolved.append(f"{rel}: unresolved mention *{token}*")
            for m in LINK_RE.finditer(line):
                target = m.group(1).strip()
                if target not in known_paths:
                    broken_links.append(f"{rel}: broken link [[{target}]]")
    print(f"people files: {len(people)} | aliases: {len(alias_table)}")
    print(f"unresolved mentions: {len(unresolved)}")
    for u in unresolved:
        print(f"  - {u}")
    print(f"broken links: {len(broken_links)}")
    for b in broken_links:
        print(f"  - {b}")


# --------------------------------------------------------------------------
# Backend calls
# --------------------------------------------------------------------------

def backend_headers():
    return {"X-API-KEY": STATE["api_key"]}


def backend_version():
    r = requests.get(f"{STATE['backend_url']}/version", headers=backend_headers(), timeout=15)
    r.raise_for_status()
    return r.json()


def backend_history():
    r = requests.get(f"{STATE['backend_url']}/history", headers=backend_headers(), timeout=15)
    r.raise_for_status()
    return r.json()


def backend_restore(hash_: str):
    r = requests.post(
        f"{STATE['backend_url']}/restore",
        headers=backend_headers(),
        json={"hash": hash_},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def backend_pull() -> bytes:
    r = requests.get(f"{STATE['backend_url']}/pull", headers=backend_headers(), timeout=30)
    r.raise_for_status()
    return r.content


def backend_push(blob: bytes, expected_base_hash):
    files = {"file": ("vault.wks", blob)}
    data = {"device_name": STATE.get("device_name", "unknown-device")}
    if expected_base_hash:
        data["expected_base_hash"] = expected_base_hash
    r = requests.post(f"{STATE['backend_url']}/push", headers=backend_headers(), files=files, data=data, timeout=60)
    if r.status_code == 429:
        raise RuntimeError(f"rate limited by backend: {r.json()}")
    r.raise_for_status()
    return r.json()


def read_last_sync_hash():
    if META_FILE.exists():
        return json.loads(META_FILE.read_text()).get("hash")
    return None


def write_last_sync(meta: dict):
    META_FILE.parent.mkdir(exist_ok=True)
    META_FILE.write_text(json.dumps(meta, indent=2))


def action_lock():
    zipped = zip_directory(VAULT_DIR)
    blob = encrypt(STATE["vault_key"], zipped)
    BLOB_FILE.write_bytes(blob)
    print(f"locked {VAULT_DIR} -> {BLOB_FILE} ({len(blob)} bytes, sha256={sha256_hex(blob)})")


def action_unlock():
    blob = BLOB_FILE.read_bytes()
    zipped = decrypt(STATE["vault_key"], blob)
    unzip_to_directory(zipped, VAULT_DIR)
    print(f"unlocked {BLOB_FILE} -> {VAULT_DIR}")


def action_validate():
    validate_vault(VAULT_DIR)


def action_pull():
    blob = backend_pull()
    BLOB_FILE.write_bytes(blob)
    write_last_sync({"hash": sha256_hex(blob)})
    print(f"pulled {len(blob)} bytes -> {BLOB_FILE}")
    if input("Unlock into vault/ now? [y/N]: ").lower() == "y":
        action_unlock()


def action_push():
    action_lock()
    blob = BLOB_FILE.read_bytes()
    base_hash = read_last_sync_hash()
    result = backend_push(blob, base_hash)
    print(json.dumps(result, indent=2))
    if result.get("validation"):
        v = result["validation"]
        if v.get("unresolved_mentions") or v.get("broken_links"):
            print("SERVER-SIDE VALIDATION WARNINGS:")
            for u in v.get("unresolved_mentions", []):
                print(f"  - {u}")
            for b in v.get("broken_links", []):
                print(f"  - {b}")
    if result.get("mode") == "merged":
        print("server merged your push with a divergent remote version.")
        if result.get("conflicts"):
            print("CONFLICTS (resolve manually, look for <<<<<<< markers in these files):")
            for c in result["conflicts"]:
                print(f"  - {c}")
        merged_blob = backend_pull()
        BLOB_FILE.write_bytes(merged_blob)
        write_last_sync(result["meta"])
        action_unlock()
        print("vault/ now contains the merged result.")
    else:
        write_last_sync(result["meta"])


def action_local_merge():
    """Merge two vault.wks files entirely offline, without any backend."""
    base_path = Path(input("Path to base (ancestor) vault.wks: ").strip())
    remote_path = Path(input("Path to remote/other-device vault.wks: ").strip())
    base_map = zip_to_map(decrypt(STATE["vault_key"], base_path.read_bytes()))
    remote_map = zip_to_map(decrypt(STATE["vault_key"], remote_path.read_bytes()))
    incoming_map = zip_to_map(zip_directory(VAULT_DIR))

    merged, conflicts = three_way_merge(base_map, remote_map, incoming_map)
    unzip_to_directory(map_to_zip(merged), VAULT_DIR)

    print(f"merged {len(merged)} files into {VAULT_DIR}.")
    if conflicts:
        print("CONFLICTS (resolve manually, look for <<<<<<< markers):")
        for c in conflicts:
            print(f"  - {c}")
    else:
        print("no conflicts -- fully automatic line-level merge.")


def action_history():
    log = backend_history()
    if not log:
        print("no history yet.")
        return
    for entry in log:
        pruned = " (blob pruned, metadata only)" if entry.get("pruned") else ""
        device = entry.get("device_name", "?")
        print(f"v{entry['version']:<4} {entry['mode']:<12} {entry['updated_at']:<16} "
              f"{device:<16} {entry['size']:>8} bytes  {entry['hash']}{pruned}")


def action_restore():
    action_history()
    target_hash = input("\nEnter the hash to restore to: ").strip()
    result = backend_restore(target_hash)
    print(json.dumps(result, indent=2))
    if result.get("status") == "ok":
        blob = backend_pull()
        BLOB_FILE.write_bytes(blob)
        write_last_sync(result["meta"])
        if input("Unlock restored version into vault/ now? [y/N]: ").lower() == "y":
            action_unlock()


def action_version():
    print(json.dumps(backend_version(), indent=2))


MENU = {
    "1": ("Lock vault/ -> vault.wks", action_lock),
    "2": ("Unlock vault.wks -> vault/", action_unlock),
    "3": ("Validate syntax", action_validate),
    "4": ("Pull from backend", action_pull),
    "5": ("Push to backend (auto-merges line-by-line on conflict)", action_push),
    "6": ("Local merge (offline, no backend)", action_local_merge),
    "7": ("Check backend version", action_version),
    "8": ("Show history (like git log)", action_history),
    "9": ("Restore to a past version (like git checkout)", action_restore),
    "0": ("Quit", None),
}


def main():
    bootstrap()
    while True:
        print("\n--- wks-diary-core ---")
        for k, (label, _) in MENU.items():
            print(f"  {k}) {label}")
        choice = input("> ").strip()
        if choice == "0":
            break
        entry = MENU.get(choice)
        if not entry:
            print("unknown option")
            continue
        try:
            entry[1]()
        except Exception as e:
            print(f"error: {e}")


if __name__ == "__main__":
    main()
