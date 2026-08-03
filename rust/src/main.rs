//! wks-diary-core backend (Rust).
//!
//! Always-online server. Stores the encrypted vault, serves it, performs
//! file-level three-way merges when two pushes diverge, and keeps a full
//! GitHub-style version log so any past state can be restored.
//!
//! Endpoints:
//!   GET  /version   -> current {hash, updated_at, size, version}
//!   GET  /pull       -> streams current vault.wks (encrypted)
//!   POST /push        -> multipart field "file" (+ "expected_base_hash")
//!                        fast-forwards if base matches current, otherwise
//!                        auto-merges file-by-file and reports conflicts.
//!   GET  /history     -> full commit-style log, newest first
//!   POST /restore     -> JSON {"hash": "<hash>"}, makes that past version
//!                        current again (like `git checkout <commit> --`)
//!
//! .env next to the binary:
//!   WKS_API_KEY=<random string, X-API-KEY header>
//!   WKS_VAULT_KEY=<64 hex chars = 32 raw bytes, same as clients use>
//!   STORAGE_DIR=/path/to/storage
//!   MAX_UPLOAD_BYTES=52428800
//!   BIND_ADDR=0.0.0.0:8080

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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;

const NONCE_LEN: usize = 24;

/* ------------------------------------------------------------------ */
/* Config + shared state                                              */
/* ------------------------------------------------------------------ */

struct Config {
    api_key: String,
    vault_key: [u8; 32],
    storage_dir: PathBuf,
    history_dir: PathBuf,
    max_bytes: usize,
    bind_addr: String,
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

fn load_config() -> Result<Config> {
    let env = load_env(".env")?;
    let api_key = env
        .get("WKS_API_KEY")
        .ok_or_else(|| anyhow!("WKS_API_KEY missing in .env"))?
        .clone();
    let key_hex = env
        .get("WKS_VAULT_KEY")
        .ok_or_else(|| anyhow!("WKS_VAULT_KEY missing in .env"))?;
    let key_bytes = hex::decode(key_hex).context("WKS_VAULT_KEY is not valid hex")?;
    if key_bytes.len() != 32 {
        bail!("WKS_VAULT_KEY must decode to exactly 32 bytes (64 hex chars)");
    }
    let mut vault_key = [0u8; 32];
    vault_key.copy_from_slice(&key_bytes);

    let storage_dir = PathBuf::from(env.get("STORAGE_DIR").cloned().unwrap_or_else(|| "./storage".into()));
    let history_dir = storage_dir.join("history");
    let max_bytes = env
        .get("MAX_UPLOAD_BYTES")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50 * 1024 * 1024);
    let bind_addr = env.get("BIND_ADDR").cloned().unwrap_or_else(|| "0.0.0.0:8080".into());

    Ok(Config {
        api_key,
        vault_key,
        storage_dir,
        history_dir,
        max_bytes,
        bind_addr,
    })
}

struct AppState {
    cfg: Config,
    lock: Mutex<()>,
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
/* File-level three-way merge                                         */
/* ------------------------------------------------------------------ */

struct MergeResult {
    merged: FileMap,
    conflicts: Vec<String>,
}

/// base = common ancestor, remote = server's current, incoming = client's push
fn three_way_merge(base: &FileMap, remote: &FileMap, incoming: &FileMap) -> MergeResult {
    let mut keys: std::collections::HashSet<&String> = std::collections::HashSet::new();
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
            (_, Some(rv), Some(iv)) => {
                let mut c = Vec::new();
                c.extend_from_slice(b"<<<<<<< remote (server)\n");
                c.extend_from_slice(rv);
                c.extend_from_slice(b"\n=======\n");
                c.extend_from_slice(iv);
                c.extend_from_slice(b"\n>>>>>>> incoming (push)\n");
                merged.insert(key.clone(), c);
                conflicts.push(key.clone());
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
/* Meta + version log (GitHub-style history / restore)                */
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("unix:{now}")
}

/* ------------------------------------------------------------------ */
/* Auth helper                                                         */
/* ------------------------------------------------------------------ */

fn check_auth(headers: &HeaderMap, expected: &str) -> Result<(), Response> {
    let given = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ok = given.len() == expected.len()
        && given.as_bytes().iter().zip(expected.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !ok {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response());
    }
    Ok(())
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async fn version_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&headers, &state.cfg.api_key) {
        return e;
    }
    let meta_path = state.cfg.storage_dir.join("meta.json");
    Json(read_meta(&meta_path).await).into_response()
}

async fn history_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&headers, &state.cfg.api_key) {
        return e;
    }
    let log_path = state.cfg.storage_dir.join("log.json");
    let mut log = read_log(&log_path).await;
    log.reverse(); // newest first, like `git log`
    Json(log).into_response()
}

async fn pull_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(e) = check_auth(&headers, &state.cfg.api_key) {
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
    if let Err(e) = check_auth(&headers, &state.cfg.api_key) {
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
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("no stored version with hash {}", req.hash)})),
        )
            .into_response();
    };

    // archive whatever is current right now before overwriting it
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
        },
    )
    .await;

    Json(serde_json::json!({"status": "ok", "mode": "restore", "meta": new_meta})).into_response()
}

async fn push_handler(State(state): State<Arc<AppState>>, headers: HeaderMap, mut multipart: Multipart) -> Response {
    if let Err(e) = check_auth(&headers, &state.cfg.api_key) {
        return e;
    }

    let mut file_bytes: Option<Bytes> = None;
    let mut expected_base_hash: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            "file" => file_bytes = field.bytes().await.ok(),
            "expected_base_hash" => expected_base_hash = field.text().await.ok(),
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
        }).await;
        return Json(serde_json::json!({"status": "ok", "mode": "initial", "meta": new_meta})).into_response();
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
        }).await;
        return Json(serde_json::json!({"status": "ok", "mode": "fast-forward", "meta": new_meta})).into_response();
    }

    let base_hash = expected_base_hash.unwrap();
    let base_path = history.join(format!("{base_hash}.wks"));
    let Ok(base_blob) = fs::read(&base_path).await else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "conflict",
                "message": "server no longer has the base version in history; pull the full current version and re-merge manually",
                "current_hash": current_hash
            })),
        )
            .into_response();
    };

    let merge_computation = (|| -> Result<(Vec<u8>, Vec<String>)> {
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
        Ok((merged_blob, merge.conflicts))
    })();

    let (merged_blob, conflicts) = match merge_computation {
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
    }).await;

    Json(serde_json::json!({
        "status": "merged",
        "mode": "three-way-merge",
        "conflicts": conflicts,
        "meta": new_meta
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

    let state = Arc::new(AppState { cfg, lock: Mutex::new(()) });

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
