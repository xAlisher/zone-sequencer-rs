use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;
use std::sync::{OnceLock, Mutex};
use std::fs;

use futures::StreamExt as _;
use lb_core::mantle::ops::channel::{ChannelId, MsgId};
use lb_core::mantle::ops::channel::inscribe::Inscription;
use lb_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::{CommonHttpClient, Slot, ZoneMessage};
use logos_blockchain_zone_sdk::adapter::{Node as _, NodeHttpClient};
use logos_blockchain_zone_sdk::indexer::ZoneIndexer;
use logos_blockchain_zone_sdk::sequencer::{ZoneSequencer, SequencerClient, SequencerCheckpoint};
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
            // try_init (not init): under logoscore/Qt another component may already
            // hold the global tracing subscriber; .init() would PANIC across the FFI
            // boundary. Ignore the "already set" error and carry on.
            .try_init()
            .ok();
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
    // v0.2: chain info is nested under cryptarchia_info (was flat in v0.1.2).
    let info = info.cryptarchia_info;

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
    // v0.2: next_messages cursor is slot-only (was (MsgId, Slot) in v0.1.2).
    let stream = match indexer.next_messages(Some(Slot::new(start_slot))).await {
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

    let inscription = match Inscription::try_from(data_bytes) {
        Ok(i) => i,
        Err(e) => { eprintln!("zone_publish: inscription too large/invalid: {:?}", e); return None; }
    };

    let node = make_node(url);

    let result = rt.block_on(async {
        // v0.2: init returns the sequencer alone; publish is routed through the
        // async SequencerClient, but its await only resolves while the drive
        // loop (next_event) is being polled — so spawn a drive task for the
        // lifetime of the publish.
        let mut sequencer = ZoneSequencer::init(channel_id, signing_key, node, checkpoint);
        let client = sequencer.client();
        let mut ready_rx = client.subscribe_ready();
        let drive = tokio::spawn(async move { loop { let _ = sequencer.next_event().await; } });

        let outcome = async {
            if tokio::time::timeout(Duration::from_secs(60), ready_rx.wait_for(|r| *r)).await.is_err() {
                eprintln!("zone_publish: timeout waiting for sequencer ready");
                return None;
            }

            let mut attempts = 0;
            loop {
                attempts += 1;
                match client.publish(inscription.clone()).await {
                    Ok((res, cp)) => {
                        let id_bytes: [u8; 32] = res.inscription_id().into();
                        let id_hex = hex::encode(id_bytes);
                        eprintln!("zone_publish: inscription_id={}", id_hex);
                        let mut clean_cp = cp;
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
        }.await;

        drive.abort();
        outcome
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
                let tip_slot: u64 = info.cryptarchia_info.slot.into();
                let lookback: u64 = 50000;
                let start_slot = tip_slot.saturating_sub(lookback);
                eprintln!("zone_query_channel: tip_slot={} start_slot={}", tip_slot, start_slot);
                Some(Slot::new(start_slot))
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
                        "data": String::from_utf8_lossy(b.data.as_slice()).to_string()
                    })),
                    ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => None,
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

    // v0.2: next_messages cursor is slot-only. The wire cursor still carries a
    // msg_id (C ABI / module contract unchanged) but only the slot is used.
    let start_cursor: Option<Slot> = if cursor_json.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(cursor_json) }.to_str().unwrap_or("");
        if cstr.is_empty() || cstr == "null" {
            None
        } else {
            let v: serde_json::Value = serde_json::from_str(cstr).ok()?;
            let slot_num = v["slot"].as_u64().unwrap_or(0);
            Some(Slot::new(slot_num))
        }
    };

    let cursor_slot_hint = start_cursor.as_ref().map(|s| s.into_inner()).unwrap_or(0);
    eprintln!("zone_query_channel_paged: channel={} cursor_slot={} limit={}",
        channel_id_hex_str, cursor_slot_hint, limit);

    let rt = get_runtime();
    let node = make_node(url);

    let result = rt.block_on(async {
        let lib_slot: u64 = match node.consensus_info().await {
            Ok(info) => {
                let tip: u64 = info.cryptarchia_info.slot.into();
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
                    "data": String::from_utf8_lossy(b.data.as_slice()).to_string()
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

struct ZoneSequencerState {
    // v0.2: cross-task async command surface. The owned sequencer lives in the
    // drive task; publishes route through this client and resolve as the drive
    // loop polls next_event().
    client: SequencerClient,
    _drive_task: tokio::task::JoinHandle<()>,
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
    let mut sequencer = ZoneSequencer::init(channel_id, signing_key, node, checkpoint);
    let client = sequencer.client();
    // The drive loop must run for the lifetime of the handle so client publishes
    // resolve and chain events keep state current.
    let drive_task = tokio::spawn(async move { loop { let _ = sequencer.next_event().await; } });

    let state = Box::new(ZoneSequencerState {
        client,
        _drive_task: drive_task,
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

    let inscription = match Inscription::try_from(data_bytes) {
        Ok(i) => i,
        Err(e) => { eprintln!("zone_sequencer_publish: inscription too large/invalid: {:?}", e); return None; }
    };

    let rt = get_runtime();
    let result = rt.block_on(async {
        match tokio::time::timeout(Duration::from_secs(120), async {
            let mut ready_rx = state.client.subscribe_ready();
            if tokio::time::timeout(Duration::from_secs(60), ready_rx.wait_for(|r| *r)).await.is_err() {
                eprintln!("zone_sequencer_publish: timeout waiting for sequencer ready");
                return None;
            }

            let mut attempts = 0;
            loop {
                attempts += 1;
                match state.client.publish(inscription.clone()).await {
                    Ok((res, cp)) => {
                        let id_bytes: [u8; 32] = res.inscription_id().into();
                        let id_hex = hex::encode(id_bytes);
                        eprintln!("zone_sequencer_publish: inscription_id={}", id_hex);
                        let mut clean_cp = cp;
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
    state._drive_task.abort();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn derive(key_hex: &str) -> Option<String> {
        let c = CString::new(key_hex).ok()?;
        let p = zone_derive_channel_id(c.as_ptr());
        if p.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        zone_free_string(p);
        Some(s)
    }

    #[test]
    fn derive_channel_id_is_deterministic_64_hex() {
        let key = "0000000000000000000000000000000000000000000000000000000000000001";
        let a = derive(key).expect("derive a");
        let b = derive(key).expect("derive b");
        assert_eq!(a, b, "derivation must be deterministic");
        assert_eq!(a.len(), 64, "channel id is 32 bytes hex");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn derive_channel_id_distinct_keys_distinct_ids() {
        let a = derive("00000000000000000000000000000000000000000000000000000000000000aa").unwrap();
        let b = derive("00000000000000000000000000000000000000000000000000000000000000bb").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derive_channel_id_rejects_bad_input() {
        assert!(derive("not-hex").is_none());
        assert!(derive("00").is_none(), "too short");
        assert!(zone_derive_channel_id(std::ptr::null()).is_null());
    }

    #[test]
    fn ffi_null_args_return_null() {
        let n = std::ptr::null();
        assert!(zone_publish(n, n, n, n, n).is_null());
        assert!(zone_query_channel(n, n, 10).is_null());
        assert!(zone_query_channel_paged(n, n, n, 10).is_null());
        assert!(zone_sequencer_create(n, n, n, n).is_null());
        assert!(zone_sequencer_publish(std::ptr::null_mut(), n).is_null());
    }

    #[test]
    fn load_checkpoint_none_for_missing_or_empty_path() {
        assert!(load_checkpoint("", "anything").is_none());
        assert!(load_checkpoint("/nonexistent/zsr/ckpt.json", &"aa".repeat(32)).is_none());
    }

    #[test]
    fn load_checkpoint_discards_on_channel_mismatch() {
        let dir = std::env::temp_dir().join(format!("zsr-test-{}-mismatch", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("ckpt.json");
        let path_str = path.to_str().unwrap();

        fs::write(path_str, b"{}").unwrap();
        // sidecar records channel aa.., but we ask to load for channel bb..
        fs::write(sidecar_path(path_str), hex::decode("aa".repeat(32)).unwrap()).unwrap();

        let got = load_checkpoint(path_str, &"bb".repeat(32));
        assert!(got.is_none(), "stale-channel checkpoint must be rejected");
        assert!(!std::path::Path::new(path_str).exists(), "stale checkpoint file removed");
        assert!(!std::path::Path::new(&sidecar_path(path_str)).exists(), "stale sidecar removed");
        let _ = fs::remove_dir_all(&dir);
    }

    /// End-to-end against a live v0.2 testnet node. Opt-in:
    ///   ZSR_NODE=http://100.108.127.3:8080 ZSR_KEY=<64-hex> \
    ///     cargo test --release e2e_publish_then_query -- --ignored --nocapture
    #[test]
    #[ignore]
    fn e2e_publish_then_query() {
        let node = std::env::var("ZSR_NODE").expect("set ZSR_NODE");
        let key = std::env::var("ZSR_KEY").expect("set ZSR_KEY");
        let cid = derive(&key).expect("derive channel id");

        let nc = CString::new(node).unwrap();
        let cc = CString::new(cid).unwrap();
        let kc = CString::new(key).unwrap();
        let payload = format!("zsr-e2e-{}", std::process::id());
        let dc = CString::new(payload.clone()).unwrap();
        let empty = CString::new("").unwrap();

        let p = zone_publish(nc.as_ptr(), cc.as_ptr(), kc.as_ptr(), dc.as_ptr(), empty.as_ptr());
        assert!(!p.is_null(), "publish returned null");
        let id = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned();
        zone_free_string(p);
        assert_eq!(id.len(), 64, "inscription id is 32 bytes hex");
        eprintln!("e2e: published '{}' -> inscription {}", payload, id);
    }
}
