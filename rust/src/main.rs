//! wks-diary-core backend (Rust).
//!
//! Always-online server. Stores the encrypted vault, serves it, performs
//! LINE-LEVEL three-way merges (diff3-style, via the `similar` crate) when
//! two pushes diverge, keeps a full version log with pruning, runs syntax
//! validation on every push, rate-limits failed auth attempts, refuses
//! to bind publicly without an explicit opt-in, and allows cross-origin
//! requests (needed for the browser-based PWA client, which sends a
//! custom X-API-KEY header and therefore triggers a CORS preflight).
//!
//! Endpoints:
//!   GET  /version   -> current {hash, updated_at, size, version}
//!   GET  /pull       -> streams current vault.wks (encrypted)
//!   POST /push        -> multipart "file" (+ "expected_base_hash", "device_name")
//!   GET  /history     -> full commit-style log, newest first
//!   POST /restore     -> JSON {"hash": "<hash>"}
//!
//! .env next to the binary -- see env.example.txt for all options.

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    body::Bytes,
    extract::{Multipart, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::TextDiff;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

const NONCE_LEN: usize = 24;
const WEEK_SECS: u64 = 7 * 86_400;

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

struct Config {
    api_key: String,
    vault_key: [u8; 32],
    storage_dir: PathBuf,
    history_dir: PathBuf,
    max_bytes: usize,
    bind_addr: String,
    rate_limit_max_failures: usize,
    rate_limit_window: Duration,
}

fn load_env(path: &str) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path).context("could not read .env")?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    Ok(map)
}

fn derive_key_argon2id(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // Parameters chosen to be in the same ballpark as libsodium's argon2id
    // "moderate" preset (1 GiB memory, 3 iterations), which the Python
    // client's passphrase mode also targets. Exact cross-compatibility
    // between the two implementations is NOT verified -- if you need both
    // clients to derive the identical key from the same passphrase, test
    // it once and compare the resulting vault.wks hashes before relying on it.
    let params = Params::new(1_048_576, 3, 1, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 hashing failed: {e}"))?;
    Ok(out)
}

fn load_config() -> Result<Config> {
    let env = load_env(".env")?;
    let api_key = env
        .get("WKS_API_KEY")
        .ok_or_else(|| anyhow!("WKS_API_KEY missing in .env"))?
        .clone();

    let vault_key: [u8; 32] = if let Some(key_hex) = env.get("WKS_VAULT_KEY") {
        let key_bytes = hex::decode(key_hex).context("WKS_VAULT_KEY is not valid hex")?;
        if key_bytes.len() != 32 {
            bail!("WKS_VAULT_KEY must decode to exactly 32 bytes (64 hex chars)");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&key_bytes);
        k
    } else if let Some(salt_hex) = env.get("WKS_VAULT_SALT") {
        let salt = hex::decode(salt_hex).context("WKS_VAULT_SALT is not valid hex")?;
        print!("Vault passphrase: ");
        std::io::stdout().flush().ok();
        let passphrase = rpassword::read_password().context(
            "failed to read passphrase from stdin -- passphrase mode needs an interactive \
             terminal; use WKS_VAULT_KEY instead for unattended systemd restarts",
        )?;
        derive_key_argon2id(&passphrase, &salt)?
    } else {
        bail!("set either WKS_VAULT_KEY or WKS_VAULT_SALT in .env");
    };

    let storage_dir = PathBuf::from(env.get("STORAGE_DIR").cloned().unwrap_or_else(|| "./storage".into()));
    let history_dir = storage_dir.join("history");
    let max_bytes = env
        .get("MAX_UPLOAD_BYTES")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50 * 1024 * 1024);
    let bind_addr = env.get("BIND_ADDR").cloned().unwrap_or_else(|| "127.0.0.1:8080".into());
    if env.contains_key("RETENTION_DAYS") {
        eprintln!(
            "note: RETENTION_DAYS is ignored since v0.5.0 -- old data is never deleted \
             automatically. Use `wks-server prune --older-than-days N --yes` to delete explicitly."
        );
    }
    let rate_limit_max_failures = env
        .get("RATE_LIMIT_MAX_FAILURES")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let rate_limit_window = Duration::from_secs(
        env.get("RATE_LIMIT_WINDOW_SECS").and_then(|s| s.parse().ok()).unwrap_or(60),
    );

    let allow_public = env.get("WKS_ALLOW_PUBLIC_BIND").map(|s| s == "yes").unwrap_or(false);
    let is_loopback = bind_addr.starts_with("127.0.0.1") || bind_addr.starts_with("localhost") || bind_addr.starts_with("[::1]");
    if !is_loopback && !allow_public {
        bail!(
            "refusing to start: BIND_ADDR '{bind_addr}' is not loopback-only. Put a TLS \
             reverse proxy (Caddy/Nginx) in front and bind this server to 127.0.0.1, or set \
             WKS_ALLOW_PUBLIC_BIND=yes in .env if you really know what you're doing."
        );
    }

    Ok(Config {
        api_key,
        vault_key,
        storage_dir,
        history_dir,
        max_bytes,
        bind_addr,
        rate_limit_max_failures,
        rate_limit_window,
    })
}

/* ------------------------------------------------------------------ */
/* Rate limiter (global, simple sliding window)                        */
/* ------------------------------------------------------------------ */

struct RateLimiter {
    failures: StdMutex<VecDeque<Instant>>,
    max_failures: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(max_failures: usize, window: Duration) -> Self {
        Self { failures: StdMutex::new(VecDeque::new()), max_failures, window }
    }

    fn prune(&self, deque: &mut VecDeque<Instant>) {
        let now = Instant::now();
        while let Some(&front) = deque.front() {
            if now.duration_since(front) > self.window {
                deque.pop_front();
            } else {
                break;
            }
        }
    }

    fn is_limited(&self) -> bool {
        let mut deque = self.failures.lock().unwrap();
        self.prune(&mut deque);
        deque.len() >= self.max_failures
    }

    fn record_failure(&self) {
        let mut deque = self.failures.lock().unwrap();
        self.prune(&mut deque);
        deque.push_back(Instant::now());
    }
}

struct AppState {
    cfg: Config,
    lock: Mutex<()>,
    rate_limiter: RateLimiter,
}

/* ------------------------------------------------------------------ */
/* Crypto + zip <-> in-memory file map                                */
/* ------------------------------------------------------------------ */

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        bail!("blob too short");
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|_| anyhow!("decryption failed: wrong key or corrupted blob"))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

type FileMap = HashMap<String, Vec<u8>>;

fn zip_to_map(zip_bytes: &[u8]) -> Result<FileMap> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))?;
    let mut map = FileMap::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let mut data = Vec::new();
        std::io::copy(&mut file, &mut data)?;
        map.insert(name, data);
    }
    Ok(map)
}

fn map_to_zip(map: &FileMap) -> Result<Vec<u8>> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let options = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        for k in keys {
            writer.start_file(k, options)?;
            writer.write_all(&map[k])?;
        }
        writer.finish()?;
    }
    Ok(buf.into_inner())
}

/* ------------------------------------------------------------------ */
/* Line-level three-way merge (diff3-style, via `similar`)             */
/* ------------------------------------------------------------------ */

#[derive(Clone, Copy, PartialEq)]
enum SegTag {
    Equal,
    Changed,
}

struct Seg {
    end: usize,
    tag: SegTag,
    content: Vec<String>,
}

fn build_segments(base_lines: &[&str], other_lines: &[&str]) -> Vec<Seg> {
    let diff = TextDiff::from_slices(base_lines, other_lines);
    let mut segs = Vec::new();
    let mut pending: Vec<String> = Vec::new();

    for op in diff.ops() {
        let old_range = op.old_range();
        let new_range = op.new_range();
        let content: Vec<String> = other_lines[new_range.clone()].iter().map(|s| s.to_string()).collect();

        if old_range.start == old_range.end {
            pending.extend(content);
            continue;
        }

        let tag = if old_range.len() == new_range.len() && content == base_lines[old_range.clone()] {
            SegTag::Equal
        } else {
            SegTag::Changed
        };
        let mut seg_content = std::mem::take(&mut pending);
        seg_content.extend(content);
        segs.push(Seg { end: old_range.end, tag, content: seg_content });
    }

    if !pending.is_empty() {
        if let Some(last) = segs.last_mut() {
            last.content.extend(pending);
        } else {
            segs.push(Seg { end: base_lines.len(), tag: SegTag::Changed, content: pending });
        }
    }
    segs
}

/// Returns Some((merged_bytes, had_conflict)) for text content with a real
/// common ancestor, or None if the caller should fall back to a whole-file
/// conflict marker (binary content, or no shared ancestor to diff against).
fn merge_lines_3way(base: &[u8], remote: &[u8], incoming: &[u8]) -> Option<(Vec<u8>, bool)> {
    let base_str = std::str::from_utf8(base).ok()?;
    let remote_str = std::str::from_utf8(remote).ok()?;
    let incoming_str = std::str::from_utf8(incoming).ok()?;

    let base_lines: Vec<&str> = base_str.split_inclusive('\n').collect();
    let remote_lines: Vec<&str> = remote_str.split_inclusive('\n').collect();
    let incoming_lines: Vec<&str> = incoming_str.split_inclusive('\n').collect();

    if base_lines.is_empty() {
        return None;
    }

    let r_segs = build_segments(&base_lines, &remote_lines);
    let i_segs = build_segments(&base_lines, &incoming_lines);
    if r_segs.is_empty() || i_segs.is_empty() {
        return None;
    }

    let mut result: Vec<String> = Vec::new();
    let mut had_conflict = false;
    let (mut ir, mut ii) = (0usize, 0usize);
    let mut pos = 0usize;
    let base_len = base_lines.len();

    while pos < base_len {
        let mut r_end_idx = ir;
        let mut i_end_idx = ii;
        loop {
            let r_end = r_segs[r_end_idx].end;
            let i_end = i_segs[i_end_idx].end;
            if r_end == i_end {
                break;
            } else if r_end < i_end {
                r_end_idx += 1;
            } else {
                i_end_idx += 1;
            }
        }
        let end = r_segs[r_end_idx].end;
        let r_group = &r_segs[ir..=r_end_idx];
        let i_group = &i_segs[ii..=i_end_idx];
        ir = r_end_idx + 1;
        ii = i_end_idx + 1;

        let base_slice: Vec<String> = base_lines[pos..end].iter().map(|s| s.to_string()).collect();
        let r_all_equal = r_group.iter().all(|s| s.tag == SegTag::Equal);
        let i_all_equal = i_group.iter().all(|s| s.tag == SegTag::Equal);

        if r_all_equal && i_all_equal {
            result.extend(base_slice);
        } else {
            let r_content: Vec<String> = if r_all_equal {
                base_slice.clone()
            } else {
                r_group.iter().flat_map(|s| s.content.clone()).collect()
            };
            let i_content: Vec<String> = if i_all_equal {
                base_slice.clone()
            } else {
                i_group.iter().flat_map(|s| s.content.clone()).collect()
            };

            if r_content == i_content {
                result.extend(r_content);
            } else if r_all_equal {
                result.extend(i_content);
            } else if i_all_equal {
                result.extend(r_content);
            } else {
                had_conflict = true;
                result.push("<<<<<<< remote\n".to_string());
                result.extend(r_content);
                result.push("=======\n".to_string());
                result.extend(i_content);
                result.push(">>>>>>> incoming\n".to_string());
            }
        }
        pos = end;
    }

    Some((result.join("").into_bytes(), had_conflict))
}

/* ------------------------------------------------------------------ */
/* File-level three-way merge (uses line-level merge where possible)   */
/* ------------------------------------------------------------------ */

struct MergeResult {
    merged: FileMap,
    conflicts: Vec<String>,
}

fn three_way_merge(base: &FileMap, remote: &FileMap, incoming: &FileMap) -> MergeResult {
    let mut keys: HashSet<&String> = HashSet::new();
    keys.extend(base.keys());
    keys.extend(remote.keys());
    keys.extend(incoming.keys());

    let mut merged = FileMap::new();
    let mut conflicts = Vec::new();

    for key in keys {
        let b = base.get(key);
        let r = remote.get(key);
        let i = incoming.get(key);

        match (b, r, i) {
            (_, Some(rv), Some(iv)) if rv == iv => {
                merged.insert(key.clone(), rv.clone());
            }
            (Some(bv), Some(rv), Some(iv)) if bv == rv && bv != iv => {
                merged.insert(key.clone(), iv.clone());
            }
            (Some(bv), Some(rv), Some(iv)) if bv == iv && bv != rv => {
                merged.insert(key.clone(), rv.clone());
            }
            (None, None, Some(iv)) => {
                merged.insert(key.clone(), iv.clone());
            }
            (None, Some(rv), None) => {
                merged.insert(key.clone(), rv.clone());
            }
            (Some(bv), None, Some(iv)) if bv == iv => { /* deleted remotely, keep deleted */ }
            (Some(bv), Some(rv), None) if bv == rv => { /* deleted incoming, keep deleted */ }
            (Some(_), None, None) => { /* stays deleted */ }
            (b_opt, Some(rv), Some(iv)) => {
                let line_merge = b_opt.and_then(|bv| merge_lines_3way(bv, rv, iv));
                if let Some((content, had_conflict)) = line_merge {
                    merged.insert(key.clone(), content);
                    if had_conflict {
                        conflicts.push(key.clone());
                    }
                } else {
                    let mut c = Vec::new();
                    c.extend_from_slice(b"<<<<<<< remote (server)\n");
                    c.extend_from_slice(rv);
                    c.extend_from_slice(b"\n=======\n");
                    c.extend_from_slice(iv);
                    c.extend_from_slice(b"\n>>>>>>> incoming (push)\n");
                    merged.insert(key.clone(), c);
                    conflicts.push(key.clone());
                }
            }
            (Some(_), None, Some(iv)) => {
                merged.insert(key.clone(), iv.clone());
                conflicts.push(format!("{key} (deleted on server, edited in push)"));
            }
            (Some(_), Some(rv), None) => {
                merged.insert(key.clone(), rv.clone());
                conflicts.push(format!("{key} (deleted in push, edited on server)"));
            }
            _ => {}
        }
    }

    MergeResult { merged, conflicts }
}

/* ------------------------------------------------------------------ */
/* Syntax validation (see SYNTAX.md) -- runs server-side on every push */
/* ------------------------------------------------------------------ */

fn validate_map(map: &FileMap) -> serde_json::Value {
    let def_re = Regex::new(r"^\[\*(.+?)\[(.+?)\]\*\]$").unwrap();
    let alias_re = Regex::new(r"^\[aliases:\s*(.+?)\]$").unwrap();
    // Rust's regex crate has no lookbehind, so we capture the preceding
    // character (or start-of-line) and check it isn't a backslash instead.
    let mention_re = Regex::new(r"(?:^|[^\\])\*([^*\\]+)\*").unwrap();
    let link_re = Regex::new(r"\[\[([^\]|#]+)(?:#([^\]|]+))?(?:\|([^\]]+))?\]\]").unwrap();

    let mut alias_table: HashMap<String, Vec<String>> = HashMap::new();
    let mut errors = Vec::new();
    let mut people_count = 0usize;

    for (path, content) in map {
        if !path.starts_with("people/") || !path.ends_with(".md") {
            continue;
        }
        let filename = path.trim_start_matches("people/").to_string();
        let text = match std::str::from_utf8(content) {
            Ok(t) => t,
            Err(_) => {
                errors.push(format!("{path}: not valid utf-8"));
                continue;
            }
        };
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let first = match lines.next() {
            Some(l) => l.trim(),
            None => {
                errors.push(format!("{filename}: empty file"));
                continue;
            }
        };
        let caps = match def_re.captures(first) {
            Some(c) => c,
            None => {
                errors.push(format!("{filename}: missing/invalid definition line"));
                continue;
            }
        };
        let display_name = caps[1].trim().to_string();
        let declared_file = caps[2].trim().to_string();
        if declared_file != filename {
            errors.push(format!("{filename}: self-mismatch ('{declared_file}' != '{filename}')"));
            continue;
        }
        people_count += 1;

        let mut aliases = vec![display_name.clone()];
        if let Some(second) = lines.next() {
            if let Some(c) = alias_re.captures(second.trim()) {
                aliases.extend(c[1].split(',').map(|s| s.trim().to_string()));
            }
        }
        for alias in aliases {
            alias_table.entry(alias).or_default().push(filename.clone());
        }
    }

    for (alias, files) in &alias_table {
        if files.len() > 1 {
            errors.push(format!("duplicate alias '{alias}' in: {}", files.join(", ")));
        }
    }

    let known_paths: HashSet<String> = map
        .keys()
        .filter(|p| p.ends_with(".md"))
        .map(|p| p.trim_end_matches(".md").to_string())
        .collect();

    let mut unresolved = Vec::new();
    let mut broken_links = Vec::new();

    for (path, content) in map {
        if !path.ends_with(".md") {
            continue;
        }
        let text = match std::str::from_utf8(content) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for line in text.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for m in mention_re.captures_iter(line) {
                let token = m[1].trim().to_string();
                if !alias_table.contains_key(&token) {
                    unresolved.push(format!("{path}: unresolved mention *{token}*"));
                }
            }
            for m in link_re.captures_iter(line) {
                let target = m[1].trim().to_string();
                if !known_paths.contains(&target) {
                    broken_links.push(format!("{path}: broken link [[{target}]]"));
                }
            }
        }
    }

    serde_json::json!({
        "people_count": people_count,
        "aliases_count": alias_table.len(),
        "unresolved_mentions": unresolved,
        "broken_links": broken_links,
        "errors": errors,
    })
}

fn validate_blob(key: &[u8; 32], blob: &[u8]) -> Option<serde_json::Value> {
    let zip_bytes = decrypt(key, blob).ok()?;
    let map = zip_to_map(&zip_bytes).ok()?;
    Some(validate_map(&map))
}

/* ------------------------------------------------------------------ */
/* Meta + version log (history / restore / retention)                */
/* ------------------------------------------------------------------ */

#[derive(Serialize, Deserialize, Clone, Default)]
struct Meta {
    hash: Option<String>,
    updated_at: Option<String>,
    size: Option<u64>,
    version: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
struct LogEntry {
    version: u64,
    hash: String,
    size: u64,
    updated_at: String,
    mode: String, // "initial" | "fast-forward" | "merged" | "restore"
    #[serde(default = "default_device_name")]
    device_name: String,
    #[serde(default)]
    pruned: bool,
}

fn default_device_name() -> String {
    "unknown-device".to_string()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn now_iso() -> String {
    format!("unix:{}", now_secs())
}

fn parse_unix_ts(s: &str) -> Option<u64> {
    s.strip_prefix("unix:").and_then(|v| v.parse().ok())
}

/// Crash-safe write: temp file in the same directory, fsync, atomic rename.
/// A crash or full disk can never leave a truncated/half-written target.
async fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let mut f = fs::File::create(&tmp).await?;
    f.write_all(data).await?;
    f.sync_all().await?;
    drop(f);
    if let Err(e) = fs::rename(&tmp, path).await {
        let _ = fs::remove_file(&tmp).await;
        return Err(e.into());
    }
    Ok(())
}

fn atomic_write_sync(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".tmp-{}", rand::random::<u32>()));
    path.with_file_name(name)
}

/// Stores a blob under its hash in history/. Never overwrites an existing
/// blob (content-addressed) and failure is always fatal for the caller:
/// a version is only replaced after it has been safely archived.
async fn archive_blob(history_dir: &Path, hash: &str, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(history_dir).await?;
    let path = history_dir.join(format!("{hash}.wks"));
    if fs::metadata(&path).await.is_ok() {
        return Ok(());
    }
    atomic_write(&path, bytes).await
}

/// Moves a corrupt file aside (never deletes it) so it can be inspected.
async fn quarantine(path: &Path) {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!(".corrupt-{}", now_secs()));
    let _ = fs::copy(path, path.with_file_name(name)).await;
}

/// Loads meta + log and self-heals inconsistencies WITHOUT ever discarding
/// data: a corrupt log.json aborts the request (it is never overwritten with
/// an empty one), a missing/corrupt/stale meta.json is rebuilt from the
/// actual vault.wks, and the vault blob is archived before anything else.
async fn load_state(storage: &Path, history: &Path) -> Result<(Meta, Vec<LogEntry>)> {
    let meta_path = storage.join("meta.json");
    let log_path = storage.join("log.json");
    let vault_path = storage.join("vault.wks");

    let mut log: Vec<LogEntry> = match fs::read_to_string(&log_path).await {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(l) => l,
            Err(e) => {
                quarantine(&log_path).await;
                bail!("log.json is corrupt ({e}); a copy was kept as log.json.corrupt-*; refusing to continue so nothing is overwritten");
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => bail!("cannot read log.json: {e}"),
    };

    let mut meta: Meta = match fs::read_to_string(&meta_path).await {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(m) => m,
            Err(_) => {
                quarantine(&meta_path).await;
                Meta::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Meta::default(),
        Err(e) => bail!("cannot read meta.json: {e}"),
    };

    let vault = match fs::read(&vault_path).await {
        Ok(v) => Some(v),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => bail!("cannot read vault.wks: {e}"),
    };

    match vault {
        None => {
            if meta.hash.is_some() {
                bail!(
                    "vault.wks is missing although meta.json points to {}; refusing to continue. \
                     Restore vault.wks from storage/history/<hash>.wks or from backup",
                    meta.hash.as_deref().unwrap_or("?")
                );
            }
        }
        Some(bytes) => {
            let actual = sha256_hex(&bytes);
            if meta.hash.as_deref() != Some(actual.as_str()) {
                archive_blob(history, &actual, &bytes).await?;
                let version = meta
                    .version
                    .unwrap_or(0)
                    .max(log.last().map(|e| e.version).unwrap_or(0))
                    + 1;
                meta = Meta { hash: Some(actual.clone()), updated_at: Some(now_iso()), size: Some(bytes.len() as u64), version: Some(version) };
                log.push(LogEntry {
                    version,
                    hash: actual,
                    size: bytes.len() as u64,
                    updated_at: meta.updated_at.clone().unwrap(),
                    mode: "recovered".to_string(),
                    device_name: "server-recovery".to_string(),
                    pruned: false,
                });
                atomic_write(&log_path, serde_json::to_string_pretty(&log)?.as_bytes()).await?;
                atomic_write(&meta_path, serde_json::to_string(&meta)?.as_bytes()).await?;
            }
        }
    }
    Ok((meta, log))
}

/// Makes `blob` the current version: vault.wks, then meta.json, then log.json,
/// each written atomically. Callers must have archived the previous current
/// blob (and the incoming one) beforehand.
async fn commit_version(storage: &Path, meta: &Meta, mut log: Vec<LogEntry>, blob: &[u8], mode: &str, device: &str) -> Result<Meta> {
    let hash = sha256_hex(blob);
    atomic_write(&storage.join("vault.wks"), blob).await?;
    let new_meta = Meta {
        hash: Some(hash.clone()),
        updated_at: Some(now_iso()),
        size: Some(blob.len() as u64),
        version: Some(meta.version.unwrap_or(0).max(log.last().map(|e| e.version).unwrap_or(0)) + 1),
    };
    atomic_write(&storage.join("meta.json"), serde_json::to_string(&new_meta)?.as_bytes()).await?;
    log.push(LogEntry {
        version: new_meta.version.unwrap(),
        hash,
        size: blob.len() as u64,
        updated_at: new_meta.updated_at.clone().unwrap(),
        mode: mode.to_string(),
        device_name: device.to_string(),
        pruned: false,
    });
    atomic_write(&storage.join("log.json"), serde_json::to_string_pretty(&log)?.as_bytes()).await?;
    Ok(new_meta)
}

fn server_error(e: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
}

/* ------------------------------------------------------------------ */
/* Explicit pruning (CLI only: `wks-server prune ...`)                 */
/* Nothing is ever deleted automatically.                              */
/* ------------------------------------------------------------------ */

/// Returns the set of blob hashes that may be deleted: entries older than
/// `cutoff`, never the current version, never a blob that is still referenced
/// by a newer log entry, and (optionally) one snapshot per calendar week.
fn plan_prune(log: &[LogEntry], current: Option<&str>, cutoff: u64, keep_weekly: bool) -> HashSet<String> {
    let mut protected: HashSet<String> = HashSet::new();
    if let Some(c) = current {
        protected.insert(c.to_string());
    }
    let mut candidates: Vec<(&LogEntry, u64)> = Vec::new();
    for e in log.iter().filter(|e| !e.pruned) {
        match parse_unix_ts(&e.updated_at) {
            Some(ts) if ts < cutoff => candidates.push((e, ts)),
            _ => {
                protected.insert(e.hash.clone());
            }
        }
    }
    if keep_weekly {
        let mut weeks: HashSet<u64> = HashSet::new();
        for (e, ts) in candidates.iter().rev() {
            if weeks.insert(ts / WEEK_SECS) {
                protected.insert(e.hash.clone());
            }
        }
    }
    candidates
        .into_iter()
        .map(|(e, _)| e.hash.clone())
        .filter(|h| !protected.contains(h))
        .collect()
}

fn run_prune(args: &[String]) -> Result<()> {
    let mut days: Option<u64> = None;
    let mut keep_weekly = false;
    let mut yes = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--older-than-days" => days = it.next().and_then(|v| v.parse().ok()),
            "--keep-weekly" => keep_weekly = true,
            "--yes" => yes = true,
            other => bail!("unknown option '{other}'"),
        }
    }
    let Some(days) = days else {
        bail!("usage: wks-server prune --older-than-days N [--keep-weekly] [--yes]   (without --yes: dry run)");
    };

    let env = load_env(".env")?;
    let storage = PathBuf::from(env.get("STORAGE_DIR").cloned().unwrap_or_else(|| "./storage".into()));
    let history = storage.join("history");
    let log_path = storage.join("log.json");
    let meta: Meta = std::fs::read_to_string(storage.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut log: Vec<LogEntry> = match std::fs::read_to_string(&log_path) {
        Ok(s) => serde_json::from_str(&s).context("log.json is corrupt; refusing to prune")?,
        Err(_) => Vec::new(),
    };

    let cutoff = now_secs().saturating_sub(days * 86_400);
    let doomed = plan_prune(&log, meta.hash.as_deref(), cutoff, keep_weekly);
    println!(
        "{} blob(s) older than {days} days would be deleted{}.",
        doomed.len(),
        if keep_weekly { " (keeping one per week)" } else { "" }
    );
    for h in &doomed {
        println!("  {h}");
    }
    if !yes {
        println!("Dry run -- nothing deleted. Re-run with --yes to delete (stop the server first).");
        return Ok(());
    }
    for h in &doomed {
        match std::fs::remove_file(history.join(format!("{h}.wks"))) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => bail!("failed to delete {h}: {e}"),
        }
    }
    for e in log.iter_mut().filter(|e| doomed.contains(&e.hash)) {
        e.pruned = true;
    }
    atomic_write_sync(&log_path, serde_json::to_string_pretty(&log)?.as_bytes())?;
    println!("Deleted {} blob(s).", doomed.len());
    Ok(())
}

/* ------------------------------------------------------------------ */
/* Auth helper (rate-limited)                                          */
/* ------------------------------------------------------------------ */

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if state.rate_limiter.is_limited() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "too many failed auth attempts, slow down"})),
        )
            .into_response());
    }
    let given = headers.get("x-api-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let expected = &state.cfg.api_key;
    let ok = given.len() == expected.len()
        && given.as_bytes().iter().zip(expected.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !ok {
        state.rate_limiter.record_failure();
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response());
    }
    Ok(())
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async fn version_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let _guard = state.lock.lock().await;
    match load_state(&state.cfg.storage_dir, &state.cfg.history_dir).await {
        Ok((meta, _)) => Json(meta).into_response(),
        Err(e) => server_error(e),
    }
}

async fn history_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let _guard = state.lock.lock().await;
    match load_state(&state.cfg.storage_dir, &state.cfg.history_dir).await {
        Ok((_, mut log)) => {
            log.reverse();
            Json(log).into_response()
        }
        Err(e) => server_error(e),
    }
}

async fn pull_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let current = state.cfg.storage_dir.join("vault.wks");
    match fs::read(&current).await {
        Ok(data) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream"), ("content-disposition", "attachment; filename=\"vault.wks\"")],
            data,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no vault stored yet"}))).into_response(),
    }
}

#[derive(Deserialize)]
struct RestoreRequest {
    hash: String,
}

async fn restore_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RestoreRequest>,
) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }

    let _guard = state.lock.lock().await;

    let storage = &state.cfg.storage_dir;
    let history = &state.cfg.history_dir;
    let current_path = storage.join("vault.wks");
    let (meta, log) = match load_state(storage, history).await {
        Ok(v) => v,
        Err(e) => return server_error(e),
    };

    if meta.hash.as_deref() == Some(req.hash.as_str()) {
        return Json(serde_json::json!({"status": "ok", "mode": "no-op", "meta": meta})).into_response();
    }

    // Hash comes from the client: only accept plain hex so it can't escape history/.
    if req.hash.is_empty() || !req.hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid hash"}))).into_response();
    }

    let target_path = history.join(format!("{}.wks", req.hash));
    let Ok(target_blob) = fs::read(&target_path).await else {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({
                "error": format!(
                    "no stored blob for hash {} -- it was deleted by an explicit `prune` run (metadata still in /history)",
                    req.hash
                )
            })),
        )
            .into_response();
    };

    // Archive the current version first; if that fails, abort -- never overwrite unarchived data.
    if let Some(current_hash) = &meta.hash {
        match fs::read(&current_path).await {
            Ok(cur) => {
                if let Err(e) = archive_blob(history, current_hash, &cur).await {
                    return server_error(e);
                }
            }
            Err(e) => return server_error(e),
        }
    }

    match commit_version(storage, &meta, log, &target_blob, "restore", "server-restore").await {
        Ok(new_meta) => Json(serde_json::json!({"status": "ok", "mode": "restore", "meta": new_meta})).into_response(),
        Err(e) => server_error(e),
    }
}

async fn push_handler(State(state): State<Arc<AppState>>, headers: HeaderMap, mut multipart: Multipart) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }

    let mut file_bytes: Option<Bytes> = None;
    let mut expected_base_hash: Option<String> = None;
    let mut device_name = default_device_name();
    let mut force = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "file" => file_bytes = field.bytes().await.ok(),
            "expected_base_hash" => {
                expected_base_hash = field.text().await.ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
            }
            "force" => force = field.text().await.map(|t| t.trim() == "yes").unwrap_or(false),
            "device_name" => {
                if let Ok(t) = field.text().await {
                    if !t.trim().is_empty() {
                        device_name = t.trim().to_string();
                    }
                }
            }
            _ => {}
        }
    }

    let Some(uploaded) = file_bytes else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "no 'file' field"}))).into_response();
    };
    if uploaded.len() > state.cfg.max_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({"error": "over size limit"}))).into_response();
    }

    // Refuse blobs that can't be read with our key: they would become the current
    // version and make every later merge/restore of the vault fail.
    if decrypt(&state.cfg.vault_key, &uploaded).ok().and_then(|z| zip_to_map(&z).ok()).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "upload is not a valid vault archive for this server's vault key; nothing was stored"})),
        )
            .into_response();
    }

    let _guard = state.lock.lock().await;

    let storage = &state.cfg.storage_dir;
    let history = &state.cfg.history_dir;
    let current_path = storage.join("vault.wks");
    let (meta, log) = match load_state(storage, history).await {
        Ok(v) => v,
        Err(e) => return server_error(e),
    };

    let incoming_hash = sha256_hex(&uploaded);

    // Every upload is kept in history before anything else happens, so even a bad
    // merge can never lose what a device sent.
    if let Err(e) = archive_blob(history, &incoming_hash, &uploaded).await {
        return server_error(e);
    }

    let Some(current_hash) = meta.hash.clone() else {
        return match commit_version(storage, &meta, log, &uploaded, "initial", &device_name).await {
            Ok(new_meta) => {
                let validation = validate_blob(&state.cfg.vault_key, &uploaded);
                Json(serde_json::json!({"status": "ok", "mode": "initial", "meta": new_meta, "validation": validation})).into_response()
            }
            Err(e) => server_error(e),
        };
    };

    if incoming_hash == current_hash {
        let validation = validate_blob(&state.cfg.vault_key, &uploaded);
        return Json(serde_json::json!({"status": "ok", "mode": "no-op", "meta": meta, "validation": validation})).into_response();
    }

    // Archive the current version before it can be replaced; abort if that fails.
    let remote_blob = match fs::read(&current_path).await {
        Ok(b) => b,
        Err(e) => return server_error(e),
    };
    if let Err(e) = archive_blob(history, &current_hash, &remote_blob).await {
        return server_error(e);
    }

    let fast_forward = expected_base_hash.as_deref() == Some(current_hash.as_str());
    if fast_forward || (expected_base_hash.is_none() && force) {
        let mode = if fast_forward { "fast-forward" } else { "forced-overwrite" };
        return match commit_version(storage, &meta, log, &uploaded, mode, &device_name).await {
            Ok(new_meta) => {
                let validation = validate_blob(&state.cfg.vault_key, &uploaded);
                Json(serde_json::json!({"status": "ok", "mode": mode, "meta": new_meta, "validation": validation})).into_response()
            }
            Err(e) => server_error(e),
        };
    }

    let Some(base_hash) = expected_base_hash else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "conflict",
                "message": "the server already has a vault and no expected_base_hash was sent; pull first and push with expected_base_hash (or send force=yes to deliberately overwrite -- the old version stays in history)",
                "current_hash": current_hash
            })),
        )
            .into_response();
    };

    if base_hash.is_empty() || !base_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid expected_base_hash"}))).into_response();
    }
    let base_path = history.join(format!("{base_hash}.wks"));
    let Ok(base_blob) = fs::read(&base_path).await else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "conflict",
                "message": "server does not have the base version (unknown hash, or deleted by an explicit prune); pull the full current version and re-merge manually. Your upload was saved in history.",
                "current_hash": current_hash
            })),
        )
            .into_response();
    };

    let merge_computation = (|| -> Result<(Vec<u8>, Vec<String>, FileMap)> {
        let base_zip = decrypt(&state.cfg.vault_key, &base_blob)?;
        let remote_zip = decrypt(&state.cfg.vault_key, &remote_blob)?;
        let incoming_zip = decrypt(&state.cfg.vault_key, &uploaded)?;
        let base_map = zip_to_map(&base_zip)?;
        let remote_map = zip_to_map(&remote_zip)?;
        let incoming_map = zip_to_map(&incoming_zip)?;
        let merge = three_way_merge(&base_map, &remote_map, &incoming_map);
        let merged_zip = map_to_zip(&merge.merged)?;
        let merged_blob = encrypt(&state.cfg.vault_key, &merged_zip)?;
        Ok((merged_blob, merge.conflicts, merge.merged))
    })();

    let (merged_blob, conflicts, merged_map) = match merge_computation {
        Ok(v) => v,
        Err(e) => return server_error(e),
    };

    let new_meta = match commit_version(storage, &meta, log, &merged_blob, "merged", &device_name).await {
        Ok(m) => m,
        Err(e) => return server_error(e),
    };

    let validation = validate_map(&merged_map);

    Json(serde_json::json!({
        "status": "merged",
        "mode": "line-level-three-way-merge",
        "conflicts": conflicts,
        "meta": new_meta,
        "validation": validation
    }))
    .into_response()
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|a| a.as_str()) == Some("prune") {
        return run_prune(&args[1..]);
    }
    let cfg = load_config()?;
    std::fs::create_dir_all(&cfg.storage_dir)?;
    std::fs::create_dir_all(&cfg.history_dir)?;
    let bind_addr = cfg.bind_addr.clone();
    let rate_limiter = RateLimiter::new(cfg.rate_limit_max_failures, cfg.rate_limit_window);

    let state = Arc::new(AppState { cfg, lock: Mutex::new(()), rate_limiter });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/version", get(version_handler))
        .route("/pull", get(pull_handler))
        .route("/push", post(push_handler))
        .route("/history", get(history_handler))
        .route("/restore", post(restore_handler))
        .layer(cors)
        .with_state(state);

    println!("wks-diary-core backend listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str, ts: u64) -> LogEntry {
        LogEntry { version: 1, hash: hash.into(), size: 1, updated_at: format!("unix:{ts}"), mode: "x".into(), device_name: "d".into(), pruned: false }
    }

    #[test]
    fn prune_never_touches_current_or_recent_or_shared_blobs() {
        let log = vec![entry("old", 100), entry("shared", 200), entry("cur", 300), entry("shared", 10_000), entry("new", 10_000)];
        let doomed = plan_prune(&log, Some("cur"), 5_000, false);
        assert_eq!(doomed, HashSet::from(["old".to_string()]));
    }

    #[test]
    fn prune_keep_weekly_keeps_one_per_week() {
        let w = WEEK_SECS;
        let log = vec![entry("a", w), entry("b", w + 5), entry("c", 2 * w)];
        let doomed = plan_prune(&log, None, 10 * w, true);
        assert_eq!(doomed, HashSet::from(["a".to_string()]));
    }

    #[tokio::test]
    async fn atomic_write_replaces_without_leftovers() {
        let dir = std::env::temp_dir().join(format!("wks-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        atomic_write(&p, b"one").await.unwrap();
        atomic_write(&p, b"two").await.unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn corrupt_log_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("wks-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("log.json"), "{not json").unwrap();
        assert!(load_state(&dir, &dir.join("history")).await.is_err());
        assert_eq!(std::fs::read_to_string(dir.join("log.json")).unwrap(), "{not json");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn missing_meta_is_rebuilt_from_vault_and_archived() {
        let dir = std::env::temp_dir().join(format!("wks-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vault.wks"), b"blob").unwrap();
        let (meta, log) = load_state(&dir, &dir.join("history")).await.unwrap();
        let h = sha256_hex(b"blob");
        assert_eq!(meta.hash.as_deref(), Some(h.as_str()));
        assert_eq!(log.len(), 1);
        assert!(dir.join("history").join(format!("{h}.wks")).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
