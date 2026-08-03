#!/usr/bin/env python3
"""
wks-diary-core -- single-file interactive client.

Run it, enter your key(s) once, then use the menu for everything:
lock, unlock, validate, local merge, push, pull, and now also a
GitHub-style history view and restore-to-any-past-version.

This client is wire-compatible with the Rust backend: both use
XChaCha20-Poly1305 (24-byte nonce) via libsodium, so blobs produced
here can be pushed to / pulled from the Rust server and merged there,
or merged entirely offline without any server at all.

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
from pathlib import Path

import requests
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as _encrypt_raw,
    crypto_aead_xchacha20poly1305_ietf_decrypt as _decrypt_raw,
)

NONCE_LEN = 24
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


def bootstrap():
    env = load_env_file()

    vault_key_hex = env.get("WKS_VAULT_KEY") or getpass.getpass("Vault key (64 hex chars): ").strip()
    api_key = env.get("WKS_API_KEY") or getpass.getpass("Backend API key (leave empty if offline-only): ").strip()
    backend_url = env.get("WKS_BACKEND_URL") or input("Backend URL (leave empty if offline-only): ").strip()

    key_bytes = bytes.fromhex(vault_key_hex)
    if len(key_bytes) != 32:
        print("ERROR: vault key must decode to exactly 32 bytes.")
        sys.exit(1)

    STATE["vault_key"] = key_bytes
    STATE["api_key"] = api_key
    STATE["backend_url"] = backend_url.rstrip("/")

    if not ENV_PATH.exists():
        if input("Save these values to .env for next time? [y/N]: ").lower() == "y":
            save_env_file({
                "WKS_VAULT_KEY": vault_key_hex,
                "WKS_API_KEY": api_key,
                "WKS_BACKEND_URL": backend_url,
            })
            print("saved .env (make sure it's gitignored!)")


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


DEF_RE = re.compile(r"^\[\*(.+?)\[(.+?)\]\*\]$")
ALIAS_RE = re.compile(r"^\[aliases:\s*(.+?)\]$")
MENTION_RE = re.compile(r"(?<!\\)\*([^*\\]+)\*")
LINK_RE = re.compile(r"\[\[([^\]|#]+)(?:#([^\]|]+))?(?:\|([^\]]+))?\]\]")


def collect_people(vault_dir: Path):
    people_dir = vault_dir / "people"
    people = []
    if not people_dir.is_dir():
        return people
    for path in sorted(people_dir.glob("*.txt")):
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
        for p in sorted(vault_dir.rglob("*.txt"))
    }
    unresolved, broken_links = [], []
    for path in sorted(vault_dir.rglob("*.txt")):
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
    data = {"expected_base_hash": expected_base_hash} if expected_base_hash else {}
    r = requests.post(f"{STATE['backend_url']}/push", headers=backend_headers(), files=files, data=data, timeout=60)
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
    if result.get("mode") == "merged":
        print("server merged your push with a divergent remote version.")
        if result.get("conflicts"):
            print("CONFLICTS (resolve manually in the affected .txt files):")
            for c in result["conflicts"]:
                print(f"  - {c}")
        merged_blob = backend_pull()
        BLOB_FILE.write_bytes(merged_blob)
        write_last_sync(result["meta"])
        action_unlock()
        print("vault/ now contains the merged result (conflict markers included where needed).")
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
        print("no conflicts.")


def action_history():
    """Show the server's full version log, newest first -- like `git log`."""
    log = backend_history()
    if not log:
        print("no history yet.")
        return
    for entry in log:
        print(f"v{entry['version']:<4} {entry['mode']:<12} {entry['updated_at']:<20} "
              f"{entry['size']:>8} bytes  {entry['hash']}")


def action_restore():
    """Restore the server (and then your local vault) to a specific past version."""
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
    "5": ("Push to backend (auto-merges on conflict)", action_push),
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
