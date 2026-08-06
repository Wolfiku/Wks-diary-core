//! wks-diary-core backend (Rust).
//!
//! Always-online server. Stores the encrypted vault, serves it, performs
//! LINE-LEVEL three-way merges (diff3-style, via the `similar` crate) when
//! two pushes diverge, keeps a full version log with pruning, runs syntax
//! validation on every push, rate-limits failed auth attempts, and refuses
//! to bind publicly without an explicit opt-in.
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
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::Mutex;

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
    retention_days: u64,
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
    let retention_days = env.get("RETENTION_DAYS").and_then(|s| s.parse().ok()).unwrap_or(30);
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
        retention_days,
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

async fn read_meta(path: &PathBuf) -> Meta {
    match fs::read_to_string(path).await {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Meta::default(),
    }
}

async fn write_meta(path: &PathBuf, meta: &Meta) -> Result<()> {
    fs::write(path, serde_json::to_string(meta)?).await?;
    Ok(())
}

async fn read_log(path: &PathBuf) -> Vec<LogEntry> {
    match fs::read_to_string(path).await {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

async fn append_log(path: &PathBuf, entry: LogEntry) -> Result<()> {
    let mut log = read_log(path).await;
    log.push(entry);
    fs::write(path, serde_json::to_string_pretty(&log)?).await?;
    Ok(())
}

fn now_iso() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    format!("unix:{now}")
}

fn parse_unix_ts(s: &str) -> Option<u64> {
    s.strip_prefix("unix:").and_then(|v| v.parse().ok())
}

/// Deletes history blobs older than RETENTION_DAYS, keeping at most one
/// snapshot per calendar week beyond that window. Log metadata (hash,
/// timestamp, size) is kept forever regardless -- only the encrypted
/// blob file itself gets removed, marked with `pruned: true`.
async fn prune_history(history_dir: &PathBuf, log_path: &PathBuf, retention_days: u64) {
    let mut log = read_log(log_path).await;
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let cutoff = now_secs.saturating_sub(retention_days * 86_400);

    let mut kept_weeks: HashSet<u64> = HashSet::new();
    let mut changed = false;

    for entry in log.iter_mut().rev() {
        if entry.pruned {
            continue;
        }
        let ts = parse_unix_ts(&entry.updated_at).unwrap_or(now_secs);
        if ts >= cutoff {
            continue;
        }
        let week = ts / WEEK_SECS;
        if kept_weeks.contains(&week) {
            let blob_path = history_dir.join(format!("{}.wks", entry.hash));
            let _ = fs::remove_file(&blob_path).await;
            entry.pruned = true;
            changed = true;
        } else {
            kept_weeks.insert(week);
        }
    }

    if changed {
        let _ = fs::write(log_path, serde_json::to_string_pretty(&log).unwrap_or_default()).await;
    }
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
    let meta_path = state.cfg.storage_dir.join("meta.json");
    Json(read_meta(&meta_path).await).into_response()
}

async fn history_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }
    let log_path = state.cfg.storage_dir.join("log.json");
    let mut log = read_log(&log_path).await;
    log.reverse();
    Json(log).into_response()
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
    let meta_path = storage.join("meta.json");
    let log_path = storage.join("log.json");
    let meta = read_meta(&meta_path).await;

    if meta.hash.as_deref() == Some(req.hash.as_str()) {
        return Json(serde_json::json!({"status": "ok", "mode": "no-op", "meta": meta})).into_response();
    }

    let target_path = history.join(format!("{}.wks", req.hash));
    let Ok(target_blob) = fs::read(&target_path).await else {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({
                "error": format!(
                    "no stored blob for hash {} -- it may have been pruned by retention policy (metadata still in /history)",
                    req.hash
                )
            })),
        )
            .into_response();
    };

    if let Some(current_hash) = &meta.hash {
        let _ = fs::create_dir_all(history).await;
        let _ = fs::copy(&current_path, history.join(format!("{current_hash}.wks"))).await;
    }

    if let Err(e) = fs::write(&current_path, &target_blob).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }

    let new_meta = Meta {
        hash: Some(req.hash.clone()),
        updated_at: Some(now_iso()),
        size: Some(target_blob.len() as u64),
        version: Some(meta.version.unwrap_or(0) + 1),
    };
    let _ = write_meta(&meta_path, &new_meta).await;
    let _ = append_log(
        &log_path,
        LogEntry {
            version: new_meta.version.unwrap(),
            hash: req.hash.clone(),
            size: target_blob.len() as u64,
            updated_at: new_meta.updated_at.clone().unwrap(),
            mode: "restore".to_string(),
            device_name: "server-restore".to_string(),
            pruned: false,
        },
    )
    .await;
    prune_history(history, &log_path, state.cfg.retention_days).await;

    Json(serde_json::json!({"status": "ok", "mode": "restore", "meta": new_meta})).into_response()
}

async fn push_handler(State(state): State<Arc<AppState>>, headers: HeaderMap, mut multipart: Multipart) -> Response {
    if let Err(e) = check_auth(&state, &headers) {
        return e;
    }

    let mut file_bytes: Option<Bytes> = None;
    let mut expected_base_hash: Option<String> = None;
    let mut device_name = default_device_name();

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "file" => file_bytes = field.bytes().await.ok(),
            "expected_base_hash" => expected_base_hash = field.text().await.ok(),
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

    let _guard = state.lock.lock().await;

    let storage = &state.cfg.storage_dir;
    let history = &state.cfg.history_dir;
    let current_path = storage.join("vault.wks");
    let meta_path = storage.join("meta.json");
    let log_path = storage.join("log.json");
    let meta = read_meta(&meta_path).await;

    let incoming_hash = sha256_hex(&uploaded);

    if meta.hash.is_none() {
        if let Err(e) = fs::write(&current_path, &uploaded[..]).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
        let new_meta = Meta { hash: Some(incoming_hash.clone()), updated_at: Some(now_iso()), size: Some(uploaded.len() as u64), version: Some(1) };
        let _ = write_meta(&meta_path, &new_meta).await;
        let _ = append_log(&log_path, LogEntry {
            version: 1, hash: incoming_hash, size: uploaded.len() as u64,
            updated_at: new_meta.updated_at.clone().unwrap(), mode: "initial".to_string(),
            device_name: device_name.clone(), pruned: false,
        }).await;
        let validation = validate_blob(&state.cfg.vault_key, &uploaded);
        return Json(serde_json::json!({"status": "ok", "mode": "initial", "meta": new_meta, "validation": validation})).into_response();
    }

    let current_hash = meta.hash.clone().unwrap();

    if expected_base_hash.as_deref() == Some(current_hash.as_str()) || expected_base_hash.is_none() {
        let _ = fs::create_dir_all(history).await;
        let _ = fs::copy(&current_path, history.join(format!("{current_hash}.wks"))).await;
        if let Err(e) = fs::write(&current_path, &uploaded[..]).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
        let new_meta = Meta {
            hash: Some(incoming_hash.clone()),
            updated_at: Some(now_iso()),
            size: Some(uploaded.len() as u64),
            version: Some(meta.version.unwrap_or(0) + 1),
        };
        let _ = write_meta(&meta_path, &new_meta).await;
        let _ = append_log(&log_path, LogEntry {
            version: new_meta.version.unwrap(), hash: incoming_hash, size: uploaded.len() as u64,
            updated_at: new_meta.updated_at.clone().unwrap(), mode: "fast-forward".to_string(),
            device_name: device_name.clone(), pruned: false,
        }).await;
        prune_history(history, &log_path, state.cfg.retention_days).await;
        let validation = validate_blob(&state.cfg.vault_key, &uploaded);
        return Json(serde_json::json!({"status": "ok", "mode": "fast-forward", "meta": new_meta, "validation": validation})).into_response();
    }

    let base_hash = expected_base_hash.unwrap();
    let base_path = history.join(format!("{base_hash}.wks"));
    let Ok(base_blob) = fs::read(&base_path).await else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "conflict",
                "message": "server no longer has the base version (possibly pruned); pull the full current version and re-merge manually",
                "current_hash": current_hash
            })),
        )
            .into_response();
    };

    let merge_computation = (|| -> Result<(Vec<u8>, Vec<String>, FileMap)> {
        let remote_blob = std::fs::read(&current_path)?;
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
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    let _ = fs::create_dir_all(history).await;
    let _ = fs::copy(&current_path, history.join(format!("{current_hash}.wks"))).await;
    if let Err(e) = fs::write(&current_path, &merged_blob).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }
    let merged_hash = sha256_hex(&merged_blob);
    let new_meta = Meta {
        hash: Some(merged_hash.clone()),
        updated_at: Some(now_iso()),
        size: Some(merged_blob.len() as u64),
        version: Some(meta.version.unwrap_or(0) + 1),
    };
    let _ = write_meta(&meta_path, &new_meta).await;
    let _ = append_log(&log_path, LogEntry {
        version: new_meta.version.unwrap(), hash: merged_hash, size: merged_blob.len() as u64,
        updated_at: new_meta.updated_at.clone().unwrap(), mode: "merged".to_string(),
        device_name: device_name.clone(), pruned: false,
    }).await;
    prune_history(history, &log_path, state.cfg.retention_days).await;

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
    let cfg = load_config()?;
    std::fs::create_dir_all(&cfg.storage_dir)?;
    std::fs::create_dir_all(&cfg.history_dir)?;
    let bind_addr = cfg.bind_addr.clone();
    let rate_limiter = RateLimiter::new(cfg.rate_limit_max_failures, cfg.rate_limit_window);

    let state = Arc::new(AppState { cfg, lock: Mutex::new(()), rate_limiter });

    let app = Router::new()
        .route("/version", get(version_handler))
        .route("/pull", get(pull_handler))
        .route("/push", post(push_handler))
        .route("/history", get(history_handler))
        .route("/restore", post(restore_handler))
        .with_state(state);

    println!("wks-diary-core backend listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
