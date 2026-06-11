use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;
use std::sync::{OnceLock, Mutex};
use std::fs;

use futures::StreamExt as _;
use lb_core::mantle::ops::channel::{ChannelId, MsgId};
use lb_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::{CommonHttpClient, Slot, ZoneMessage};
use logos_blockchain_zone_sdk::adapter::{Node as _, NodeHttpClient};
use logos_blockchain_zone_sdk::indexer::ZoneIndexer;
use logos_blockchain_zone_sdk::sequencer::{ZoneSequencer, SequencerCheckpoint};
use reqwest::Url;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static TRACING_INIT: OnceLock<()> = OnceLock::new();

fn init_tracing() {
    TRACING_INIT.get_or_init(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
            )
            .with_writer(std::io::stderr)
            .init();
    });
}

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

fn make_node(url: Url) -> NodeHttpClient {
    NodeHttpClient::new(CommonHttpClient::new(None), url)
}

fn sidecar_path(checkpoint_path: &str) -> String {
    format!("{}.channel", checkpoint_path)
}

fn load_checkpoint(path: &str, channel_id_hex: &str) -> Option<SequencerCheckpoint> {
    if path.is_empty() { return None; }
    if !std::path::Path::new(path).exists() { return None; }

    let sidecar = sidecar_path(path);
    if std::path::Path::new(&sidecar).exists() {
        let saved = fs::read(&sidecar).unwrap_or_default();
        let saved_hex = hex::encode(&saved);
        if saved_hex != channel_id_hex {
            eprintln!("load_checkpoint: channel ID changed — discarding stale checkpoint");
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(&sidecar);
            return None;
        }
    } else {
        eprintln!("load_checkpoint: no channel sidecar — adopting checkpoint for current channel");
        if let Ok(channel_bytes) = hex::decode(channel_id_hex) {
            let _ = fs::write(&sidecar, channel_bytes);
        }
    }

    let data = fs::read(path).ok()?;
    let mut cp: SequencerCheckpoint = serde_json::from_slice(&data).ok()?;
    if !cp.pending_txs.is_empty() {
        eprintln!("load_checkpoint: cleared {} stale pending_txs", cp.pending_txs.len());
        cp.pending_txs.clear();
    }
    Some(cp)
}

fn save_checkpoint(path: &str, checkpoint: &SequencerCheckpoint, channel_id_hex: &str) {
    if path.is_empty() { return; }
    if let Ok(data) = serde_json::to_vec(checkpoint) {
        let _ = fs::write(path, data);
    }
    if let Ok(channel_bytes) = hex::decode(channel_id_hex) {
        let _ = fs::write(sidecar_path(path), channel_bytes);
    }
}

fn parse_args(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
) -> Option<(Url, ChannelId, Ed25519Key)> {
    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let channel_bytes: [u8; 32] = hex::decode(channel_id_hex_str).ok()?.try_into().ok()?;
    let url: Url = node_url_str.parse().ok()?;
    Some((url, ChannelId::from(channel_bytes), Ed25519Key::from_bytes(&key_bytes)))
}

/// Publish data to a zone channel.
///
/// Returns heap-allocated hex inscription ID, or NULL on error. Free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_publish(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
    data: *const c_char,
    checkpoint_path: *const c_char,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| zone_publish_inner(node_url, channel_id_hex, signing_key_hex, data, checkpoint_path));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_publish: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_publish: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

/// Bootstrap a sequencer checkpoint for a channel that has no local checkpoint.
///
/// Shared by the stateless (`zone_publish`) and stateful (`zone_sequencer_create`)
/// paths so both resolve the starting parent identically:
///   - `GET {node}/channel/{id}` is the authoritative ledger ChannelState (#1):
///       * tip present  → start from that tip, lib_slot = current LIB.
///       * "channel not found" (genuinely fresh) → start from root, lib_slot =
///         current LIB. Returning `None` here is what broke fresh channels: with
///         no checkpoint the SDK starts at genesis and backfills the WHOLE chain
///         (Slot 1 → LIB) before signalling ready, which on a long chain exceeds
///         `wait_ready`'s timeout and the first publish never lands. A fresh
///         channel has no history to backfill, so pin it at current LIB and skip.
///   - node without `/channel` → bounded chain-scan fallback (honest re limits, #2).
async fn bootstrap_checkpoint(
    url: &Url,
    channel_id_hex_str: &str,
    channel_id: ChannelId,
) -> Option<SequencerCheckpoint> {
    let node = make_node(url.clone());
    let info = match node.consensus_info().await {
        Ok(i) => i,
        Err(e) => {
            eprintln!("bootstrap: consensus_info error: {:?}", e);
            return None;
        }
    };

    let endpoint = format!("{}/channel/{}",
        url.as_str().trim_end_matches('/'), channel_id_hex_str);
    match reqwest::Client::new()
        .get(&endpoint)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let tip = resp.json::<serde_json::Value>().await.ok()
                .and_then(|v| v.get("tip").and_then(|t| t.as_str()).map(String::from))
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            if let Some(tip_bytes) = tip {
                eprintln!("bootstrap: channel tip from node = {}", hex::encode(tip_bytes));
                return Some(SequencerCheckpoint {
                    last_msg_id: MsgId::from(tip_bytes),
                    pending_txs: vec![],
                    lib: info.lib,
                    lib_slot: info.lib_slot,
                });
            }
            eprintln!("bootstrap: /channel response unparseable — falling back to chain scan");
        }
        Ok(resp) => {
            eprintln!("bootstrap: node has no state for this channel (HTTP {}) — fresh channel, starting from root at current LIB (skip genesis backfill)",
                resp.status());
            return Some(SequencerCheckpoint {
                last_msg_id: MsgId::root(),
                pending_txs: vec![],
                lib: info.lib,
                lib_slot: info.lib_slot,
            });
        }
        Err(e) => {
            eprintln!("bootstrap: /channel query failed ({}) — falling back to chain scan", e);
        }
    }

    // Fallback for nodes without /channel: bounded scan. Finding nothing here does
    // NOT prove the channel is empty (#2) — deeper history may exist.
    let tip_slot: u64 = info.slot.into();
    let lookback: u64 = 100_000;
    let start_slot = tip_slot.saturating_sub(lookback);

    let indexer = ZoneIndexer::new(channel_id, node);
    let stream = match indexer.next_messages(Some((MsgId::root(), Slot::new(start_slot)))).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bootstrap: indexer error: {:?}", e);
            return None;
        }
    };

    let mut last: Option<(MsgId, Slot)> = None;
    let mut pinned = std::pin::pin!(stream);
    while let Some((msg, slot)) = pinned.next().await {
        if let ZoneMessage::Block(b) = msg {
            last = Some((b.id, slot));
        }
    }

    if let Some((msg_id, lib_slot_approx)) = last {
        eprintln!("bootstrap: last_msg_id={}", hex::encode(<[u8; 32]>::from(msg_id)));
        Some(SequencerCheckpoint {
            last_msg_id: msg_id,
            pending_txs: vec![],
            lib: info.lib,
            lib_slot: lib_slot_approx,
        })
    } else {
        eprintln!("bootstrap: scan found no messages in last {} slots — deferring to SDK backfill (deeper history may still exist)",
            lookback);
        None
    }
}

fn zone_publish_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
    data: *const c_char,
    checkpoint_path: *const c_char,
) -> Option<CString> {
    if node_url.is_null() || channel_id_hex.is_null() || signing_key_hex.is_null() || data.is_null() {
        eprintln!("zone_publish: null argument");
        return None;
    }

    let (url, channel_id, signing_key) = parse_args(node_url, channel_id_hex, signing_key_hex)?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;
    let data_str = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
    let ckpt_path = if checkpoint_path.is_null() { "" } else {
        unsafe { CStr::from_ptr(checkpoint_path) }.to_str().unwrap_or("")
    };

    let rt = get_runtime();
    let checkpoint = load_checkpoint(ckpt_path, channel_id_hex_str)
        .or_else(|| rt.block_on(bootstrap_checkpoint(&url, channel_id_hex_str, channel_id)));
    eprintln!("zone_publish: node={} channel={} checkpoint={}",
        url, channel_id_hex_str,
        if checkpoint.is_some() { "loaded" } else { "fresh" });

    let data_bytes = data_str.as_bytes().to_vec();
    eprintln!("zone_publish: publishing {} bytes...", data_bytes.len());

    let node = make_node(url);

    let result = rt.block_on(async {
        let (sequencer, mut handle) = ZoneSequencer::init(channel_id, signing_key, node, checkpoint);
        let _task = sequencer.spawn();

        match tokio::time::timeout(Duration::from_secs(60), handle.wait_ready()).await {
            Ok(()) => {}
            Err(_) => {
                eprintln!("zone_publish: timeout waiting for sequencer ready");
                return None;
            }
        }

        let mut attempts = 0;
        loop {
            attempts += 1;
            match handle.publish_message(data_bytes.clone()).await {
                Ok(result) => {
                    let id_bytes: [u8; 32] = result.inscription_id.into();
                    let id_hex = hex::encode(id_bytes);
                    eprintln!("zone_publish: inscription_id={}", id_hex);
                    let mut clean_cp = result.checkpoint.clone();
                    clean_cp.pending_txs.clear();
                    save_checkpoint(ckpt_path, &clean_cp, channel_id_hex_str);
                    return Some(id_hex);
                }
                Err(e) => {
                    if attempts > 5 {
                        eprintln!("zone_publish: failed after {} attempts: {}", attempts, e);
                        return None;
                    }
                    eprintln!("zone_publish: attempt {}: {} — retrying in 1s...", attempts, e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    })?;

    CString::new(result).ok()
}

/// Query inscriptions from a zone channel.
///
/// Returns JSON array string: [{"id":"hex","data":"text"}, ...]
/// or NULL on error. Caller must free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_query_channel(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    limit: i32,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| zone_query_channel_inner(node_url, channel_id_hex, limit));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_query_channel: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_query_channel: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_query_channel_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    limit: i32,
) -> Option<CString> {
    if node_url.is_null() || channel_id_hex.is_null() {
        eprintln!("zone_query_channel: null argument");
        return None;
    }

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;

    let channel_id = ChannelId::from(<[u8; 32]>::try_from(hex::decode(channel_id_hex_str).ok()?).ok()?);
    let url: Url = node_url_str.parse().ok()?;

    eprintln!("zone_query_channel: channel={} limit={}", channel_id_hex_str, limit);

    let rt = get_runtime();
    let node = make_node(url);

    let result = rt.block_on(async {
        let start_cursor = match node.consensus_info().await {
            Ok(info) => {
                let tip_slot: u64 = info.slot.into();
                let lookback: u64 = 50000;
                let start_slot = tip_slot.saturating_sub(lookback);
                eprintln!("zone_query_channel: tip_slot={} start_slot={}", tip_slot, start_slot);
                Some((MsgId::root(), Slot::new(start_slot)))
            }
            Err(e) => {
                eprintln!("zone_query_channel: consensus_info error: {:?} — scanning from genesis", e);
                None
            }
        };

        let indexer = ZoneIndexer::new(channel_id, node);
        let stream = match indexer.next_messages(start_cursor).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("zone_query_channel: next_messages error: {:?}", e);
                return None;
            }
        };

        let messages: Vec<_> = stream
            .filter_map(|(msg, _slot)| async move {
                match msg {
                    ZoneMessage::Block(b) => Some(serde_json::json!({
                        "id": hex::encode(<[u8; 32]>::from(b.id)),
                        "data": String::from_utf8_lossy(&b.data).to_string()
                    })),
                    ZoneMessage::Deposit(_) => None,
                }
            })
            .take(limit as usize)
            .collect()
            .await;

        eprintln!("zone_query_channel: got {} messages", messages.len());
        Some(serde_json::to_string(&messages).ok()?)
    })?;

    CString::new(result).ok()
}

/// Derive the 64-char hex channel ID from an Ed25519 signing key without publishing.
///
/// Returns heap-allocated 64-char hex channel ID, or NULL on error. Free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_derive_channel_id(signing_key_hex: *const c_char) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| zone_derive_channel_id_inner(signing_key_hex));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_derive_channel_id: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_derive_channel_id: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_derive_channel_id_inner(signing_key_hex: *const c_char) -> Option<CString> {
    if signing_key_hex.is_null() {
        eprintln!("zone_derive_channel_id: null argument");
        return None;
    }
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let signing_key = Ed25519Key::from_bytes(&key_bytes);
    let channel_bytes: [u8; 32] = signing_key.public_key().to_bytes();
    CString::new(hex::encode(channel_bytes)).ok()
}

/// Query a zone channel with cursor-based pagination for full history backfill.
///
/// cursor_json format: {"msg_id":"hex64","slot":N} or NULL/empty to start from genesis.
///
/// Returns JSON object:
/// {"messages":[{"id":"hex","data":"text"},...],
///  "cursor":{"msg_id":"hex","slot":N},
///  "cursor_slot":N,
///  "lib_slot":N,
///  "done":bool}
/// or NULL on error. Caller must free with zone_free_string().
#[no_mangle]
pub extern "C" fn zone_query_channel_paged(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    cursor_json: *const c_char,
    limit: i32,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(|| {
        zone_query_channel_paged_inner(node_url, channel_id_hex, cursor_json, limit)
    });
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_query_channel_paged: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_query_channel_paged: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_query_channel_paged_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    cursor_json: *const c_char,
    limit: i32,
) -> Option<CString> {
    if node_url.is_null() || channel_id_hex.is_null() {
        eprintln!("zone_query_channel_paged: null argument");
        return None;
    }

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;

    let channel_id = ChannelId::from(
        <[u8; 32]>::try_from(hex::decode(channel_id_hex_str).ok()?).ok()?
    );
    let url: Url = node_url_str.parse().ok()?;

    let start_cursor: Option<(MsgId, Slot)> = if cursor_json.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(cursor_json) }.to_str().unwrap_or("");
        if cstr.is_empty() || cstr == "null" {
            None
        } else {
            let v: serde_json::Value = serde_json::from_str(cstr).ok()?;
            let msg_id_hex = v["msg_id"].as_str().unwrap_or("");
            let slot_num = v["slot"].as_u64().unwrap_or(0);
            let msg_id_bytes: [u8; 32] = hex::decode(msg_id_hex).ok()?.try_into().ok()?;
            Some((MsgId::from(msg_id_bytes), Slot::new(slot_num)))
        }
    };

    let cursor_slot_hint = start_cursor.as_ref().map(|(_, s)| s.into_inner()).unwrap_or(0);
    eprintln!("zone_query_channel_paged: channel={} cursor_slot={} limit={}",
        channel_id_hex_str, cursor_slot_hint, limit);

    let rt = get_runtime();
    let node = make_node(url);

    let result = rt.block_on(async {
        let lib_slot: u64 = match node.consensus_info().await {
            Ok(info) => {
                let tip: u64 = info.slot.into();
                tip.saturating_sub(600)
            }
            Err(e) => {
                eprintln!("zone_query_channel_paged: consensus_info error: {:?}", e);
                0
            }
        };

        let indexer = ZoneIndexer::new(channel_id, node);
        let stream = match indexer.next_messages(start_cursor).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("zone_query_channel_paged: next_messages error: {:?}", e);
                return None;
            }
        };

        let mut items: Vec<serde_json::Value> = Vec::new();
        let mut last_cursor: Option<(MsgId, Slot)> = None;

        let mut pinned = std::pin::pin!(stream);
        while let Some((msg, slot)) = pinned.next().await {
            if let ZoneMessage::Block(b) = msg {
                items.push(serde_json::json!({
                    "id": hex::encode(<[u8; 32]>::from(b.id)),
                    "data": String::from_utf8_lossy(&b.data).to_string()
                }));
                last_cursor = Some((b.id, slot));
                if items.len() >= limit as usize {
                    break;
                }
            }
        }

        let (new_cursor_slot, cursor_val) = match last_cursor {
            Some((msg_id, slot)) => {
                let s: u64 = slot.into_inner();
                (s, serde_json::json!({
                    "msg_id": hex::encode(<[u8; 32]>::from(msg_id)),
                    "slot": s
                }))
            }
            None => (cursor_slot_hint, serde_json::json!({
                "msg_id": hex::encode([0u8; 32]),
                "slot": cursor_slot_hint
            })),
        };

        let done = lib_slot > 0 && new_cursor_slot >= lib_slot;
        eprintln!("zone_query_channel_paged: got {} messages, cursor_slot={}, lib_slot={}, done={}",
            items.len(), new_cursor_slot, lib_slot, done);

        let out = serde_json::json!({
            "messages": items,
            "cursor": cursor_val,
            "cursor_slot": new_cursor_slot,
            "lib_slot": lib_slot,
            "done": done
        });
        Some(serde_json::to_string(&out).ok()?)
    })?;

    CString::new(result).ok()
}

// ── Persistent sequencer handle ──────────────────────────────────────────────

type SdkHandle = logos_blockchain_zone_sdk::sequencer::SequencerHandle<NodeHttpClient>;

struct ZoneSequencerState {
    handle: SdkHandle,
    _spawn_task: tokio::task::JoinHandle<()>,
    channel_id_hex: String,
    checkpoint_path: String,
    last_checkpoint: Mutex<Option<SequencerCheckpoint>>,
}

/// Create a persistent sequencer handle.
///
/// Returns an opaque handle (caller must NOT free directly), or NULL on error.
#[no_mangle]
pub extern "C" fn zone_sequencer_create(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
    checkpoint_path: *const c_char,
) -> *mut std::ffi::c_void {
    init_tracing();
    let result = std::panic::catch_unwind(|| {
        zone_sequencer_create_inner(node_url, channel_id_hex, signing_key_hex, checkpoint_path)
    });
    match result {
        Ok(Some(ptr)) => ptr,
        Ok(None) => { eprintln!("zone_sequencer_create: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_sequencer_create: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_sequencer_create_inner(
    node_url: *const c_char,
    channel_id_hex: *const c_char,
    signing_key_hex: *const c_char,
    checkpoint_path: *const c_char,
) -> Option<*mut std::ffi::c_void> {
    if node_url.is_null() || channel_id_hex.is_null() || signing_key_hex.is_null() {
        eprintln!("zone_sequencer_create: null argument");
        return None;
    }

    let (url, channel_id, signing_key) = parse_args(node_url, channel_id_hex, signing_key_hex)?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;
    let ckpt_path = if checkpoint_path.is_null() { "" } else {
        unsafe { CStr::from_ptr(checkpoint_path) }.to_str().unwrap_or("")
    };

    let rt = get_runtime();

    let checkpoint = load_checkpoint(ckpt_path, channel_id_hex_str)
        .or_else(|| rt.block_on(bootstrap_checkpoint(&url, channel_id_hex_str, channel_id)));

    eprintln!("zone_sequencer_create: node={} channel={} checkpoint={}",
        url, channel_id_hex_str,
        if checkpoint.is_some() { "loaded" } else { "fresh" });

    let node = make_node(url);
    let last_cp = checkpoint.clone();

    let _guard = rt.enter();
    let (sequencer, handle) = ZoneSequencer::init(channel_id, signing_key, node, checkpoint);
    let spawn_task = sequencer.spawn();

    let state = Box::new(ZoneSequencerState {
        handle,
        _spawn_task: spawn_task,
        channel_id_hex: channel_id_hex_str.to_string(),
        checkpoint_path: ckpt_path.to_string(),
        last_checkpoint: Mutex::new(last_cp),
    });

    Some(Box::into_raw(state) as *mut std::ffi::c_void)
}

/// Publish data using an existing sequencer handle.
/// Returns heap-allocated hex inscription ID, or NULL on error.
/// Caller must free the returned string with `zone_free_string`.
#[no_mangle]
pub extern "C" fn zone_sequencer_publish(
    handle: *mut std::ffi::c_void,
    data: *const c_char,
) -> *mut c_char {
    init_tracing();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        zone_sequencer_publish_inner(handle, data)
    }));
    match result {
        Ok(Some(s)) => s.into_raw(),
        Ok(None) => { eprintln!("zone_sequencer_publish: returned None"); std::ptr::null_mut() }
        Err(e) => { eprintln!("zone_sequencer_publish: panicked: {:?}", e); std::ptr::null_mut() }
    }
}

fn zone_sequencer_publish_inner(
    handle: *mut std::ffi::c_void,
    data: *const c_char,
) -> Option<CString> {
    if handle.is_null() || data.is_null() {
        eprintln!("zone_sequencer_publish: null argument");
        return None;
    }

    let state = unsafe { &*(handle as *const ZoneSequencerState) };
    let data_str = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
    let data_bytes = data_str.as_bytes().to_vec();

    eprintln!("zone_sequencer_publish: publishing {} bytes to channel {}...",
        data_bytes.len(), state.channel_id_hex);

    let rt = get_runtime();
    let result = rt.block_on(async {
        match tokio::time::timeout(Duration::from_secs(120), async {
            let mut handle_clone = state.handle.clone();
            match tokio::time::timeout(Duration::from_secs(60), handle_clone.wait_ready()).await {
                Ok(()) => {}
                Err(_) => {
                    eprintln!("zone_sequencer_publish: timeout waiting for sequencer ready");
                    return None;
                }
            }

            let mut attempts = 0;
            loop {
                attempts += 1;
                match state.handle.publish_message(data_bytes.clone()).await {
                    Ok(result) => {
                        let id_bytes: [u8; 32] = result.inscription_id.into();
                        let id_hex = hex::encode(id_bytes);
                        eprintln!("zone_sequencer_publish: inscription_id={}", id_hex);
                        let mut clean_cp = result.checkpoint.clone();
                        clean_cp.pending_txs.clear();
                        save_checkpoint(&state.checkpoint_path, &clean_cp, &state.channel_id_hex);
                        if let Ok(mut guard) = state.last_checkpoint.lock() {
                            *guard = Some(clean_cp);
                        }
                        return Some(id_hex);
                    }
                    Err(e) => {
                        if attempts > 5 {
                            eprintln!("zone_sequencer_publish: failed after {} attempts: {}", attempts, e);
                            return None;
                        }
                        eprintln!("zone_sequencer_publish: attempt {}: {} — retrying in 1s...", attempts, e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }).await {
            Ok(r) => r,
            Err(_) => {
                eprintln!("zone_sequencer_publish: timed out after 120s");
                None
            }
        }
    })?;

    CString::new(result).ok()
}

/// Get the current checkpoint as JSON (from last successful publish).
/// Caller must free the returned string with `zone_free_string`.
#[no_mangle]
pub extern "C" fn zone_sequencer_checkpoint(handle: *mut std::ffi::c_void) -> *mut c_char {
    init_tracing();
    if handle.is_null() { return std::ptr::null_mut(); }
    let state = unsafe { &*(handle as *const ZoneSequencerState) };
    let result = state.last_checkpoint.lock().ok().and_then(|guard| {
        guard.as_ref().and_then(|cp| serde_json::to_string(cp).ok())
    });
    match result {
        Some(json) => CString::new(json).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Destroy a sequencer handle created by `zone_sequencer_create`.
#[no_mangle]
pub extern "C" fn zone_sequencer_destroy(handle: *mut std::ffi::c_void) {
    if handle.is_null() { return; }
    let state = unsafe { Box::from_raw(handle as *mut ZoneSequencerState) };
    state._spawn_task.abort();
    drop(state);
    eprintln!("zone_sequencer_destroy: handle dropped");
}

/// Free a string returned by zone_publish, zone_query_channel, zone_derive_channel_id,
/// zone_query_channel_paged, zone_sequencer_publish, or zone_sequencer_checkpoint.
#[no_mangle]
pub extern "C" fn zone_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}
