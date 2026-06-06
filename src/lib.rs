use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;
use std::sync::OnceLock;
use std::fs;

use lb_core::mantle::ops::channel::ChannelId;
use lb_key_management_system_service::keys::Ed25519Key;
use logos_blockchain_zone_sdk::sequencer::{ZoneSequencer, SequencerCheckpoint};
use logos_blockchain_zone_sdk::indexer::ZoneIndexer;
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
        // No sidecar: accept the checkpoint anyway and create the sidecar.
        // Discarding would reset last_msg_id to root, which breaks publishing
        // on channels that already have messages.
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

/// Publish data to a zone channel.
///
/// - node_url: HTTP endpoint e.g. "http://192.168.0.209:8080"
/// - channel_id_hex: 64-char hex channel ID (32 bytes) to publish to
/// - signing_key_hex: 64-char hex (32-byte Ed25519 seed).
/// - data: text to inscribe
/// - checkpoint_path: file to load/save checkpoint ("" to disable). On first publish for a
///   fresh channel, pass a path but it's fine if the file doesn't exist yet.
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

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let data_str = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
    let ckpt_path = if checkpoint_path.is_null() { "" } else {
        unsafe { CStr::from_ptr(checkpoint_path) }.to_str().unwrap_or("")
    };

    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let signing_key = Ed25519Key::from_bytes(&key_bytes);
    let channel_bytes: [u8; 32] = hex::decode(channel_id_hex_str).ok()?.try_into().ok()?;
    let channel_id = ChannelId::from(channel_bytes);
    let url: Url = node_url_str.parse().ok()?;

    let checkpoint = load_checkpoint(ckpt_path, channel_id_hex_str);
    eprintln!("zone_publish: node={} channel={} checkpoint={}",
        url, channel_id_hex_str,
        if checkpoint.is_some() { "loaded" } else { "fresh" });

    let data_bytes = data_str.as_bytes().to_vec();
    eprintln!("zone_publish: publishing {} bytes...", data_bytes.len());

    let rt = get_runtime();

    let result = rt.block_on(async {
        let sequencer = ZoneSequencer::init(channel_id, signing_key, url, None, checkpoint);

        let mut attempts = 0;
        loop {
            attempts += 1;
            match sequencer.publish(data_bytes.clone()).await {
                Ok(result) => {
                    let id_bytes: [u8; 32] = result.inscription_id.into();
                    let id_hex = hex::encode(id_bytes);
                    let cp_last_msg_id = hex::encode(<[u8; 32]>::from(result.checkpoint.last_msg_id));
                    eprintln!("zone_publish: inscription_id={id_hex} checkpoint.last_msg_id={cp_last_msg_id}");
                    // Save checkpoint with pending_txs cleared + channel sidecar.
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
/// - node_url: HTTP endpoint e.g. "http://192.168.0.209:8080"
/// - channel_id_hex: 64-char hex channel ID (32 bytes)
/// - limit: max number of inscriptions to return
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
    let url_for_indexer = url.clone();
    let indexer = ZoneIndexer::new(channel_id, url_for_indexer, None);

    eprintln!("zone_query_channel: channel={} limit={}", channel_id_hex_str, limit);

    let rt = get_runtime();
    let result = rt.block_on(async {
        // Get current chain tip to start from recent blocks only
        // Scanning from genesis is too slow — start from (tip - lookback) instead
        let http_client = lb_common_http_client::CommonHttpClient::new(None);
        let start_cursor = match http_client.consensus_info(url.clone()).await {
            Ok(info) => {
                let tip_slot: u64 = info.slot.into();
                let lookback: u64 = 50000; // scan last 50k slots (~14 hours at 1s slots)
                let start_slot = tip_slot.saturating_sub(lookback);
                eprintln!("zone_query_channel: tip_slot={} start_slot={}", tip_slot, start_slot);
                serde_json::from_str::<logos_blockchain_zone_sdk::indexer::Cursor>(
                        &format!(r#"{{"slot":{},"last_id":null}}"#, start_slot)
                    ).ok()
            }
            Err(e) => {
                eprintln!("zone_query_channel: consensus_info error: {:?} — scanning from genesis", e);
                None // fall back to genesis if we can't get tip
            }
        };

        let poll = match indexer.next_messages(start_cursor, limit as usize).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("zone_query_channel: next_messages error: {:?}", e);
                return None;
            }
        };
        eprintln!("zone_query_channel: got {} messages", poll.messages.len());
        let items: Vec<serde_json::Value> = poll.messages.iter().map(|b| {
            serde_json::json!({
                "id": hex::encode(<[u8; 32]>::from(b.id)),
                "data": String::from_utf8_lossy(&b.data).to_string()
            })
        }).collect();
        Some(serde_json::to_string(&items).ok()?)
    })?;

    CString::new(result).ok()
}

/// Derive the 64-char hex channel ID from an Ed25519 signing key without publishing.
///
/// - signing_key_hex: 64-char hex (32-byte Ed25519 seed)
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
/// - node_url: HTTP endpoint e.g. "http://192.168.0.209:8080"
/// - channel_id_hex: 64-char hex channel ID (32 bytes)
/// - cursor_json: JSON cursor from previous call, or NULL to start from genesis
/// - limit: max number of inscriptions to return per page
///
/// Returns JSON object:
/// {"messages":[{"id":"hex","data":"text"},...],
///  "cursor":{"slot":N,"last_id":null},
///  "cursor_slot":N,
///  "lib_slot":N,
///  "done":bool}
/// or NULL on error. Caller must free with zone_free_string().
/// "done" is true when cursor_slot >= lib_slot (reached LIB — all finalized history scanned).
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

    // Parse optional incoming cursor (NULL or empty = from genesis)
    let start_cursor: Option<logos_blockchain_zone_sdk::indexer::Cursor> = if cursor_json.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(cursor_json) }.to_str().unwrap_or("");
        if cstr.is_empty() || cstr == "null" {
            None
        } else {
            serde_json::from_str(cstr).ok()
        }
    };

    let cursor_slot_hint = start_cursor.as_ref().map(|c| {
        // Extract slot from cursor JSON for progress reporting
        serde_json::to_value(c).ok()
            .and_then(|v| v["slot"].as_u64())
            .unwrap_or(0)
    }).unwrap_or(0);

    eprintln!("zone_query_channel_paged: channel={} cursor_slot={} limit={}",
        channel_id_hex_str, cursor_slot_hint, limit);

    let indexer = ZoneIndexer::new(channel_id, url.clone(), None);
    let rt = get_runtime();

    let result = rt.block_on(async {
        // Get LIB slot for progress / done detection
        let http_client = lb_common_http_client::CommonHttpClient::new(None);
        let lib_slot: u64 = match http_client.consensus_info(url.clone()).await {
            Ok(info) => {
                // consensus_info returns tip; LIB is typically ~600 slots behind
                let tip: u64 = info.slot.into();
                tip.saturating_sub(600)
            }
            Err(e) => {
                eprintln!("zone_query_channel_paged: consensus_info error: {:?}", e);
                0
            }
        };

        let poll = match indexer.next_messages(start_cursor, limit as usize).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("zone_query_channel_paged: next_messages error: {:?}", e);
                return None;
            }
        };

        let items: Vec<serde_json::Value> = poll.messages.iter().map(|b| {
            serde_json::json!({
                "id": hex::encode(<[u8; 32]>::from(b.id)),
                "data": String::from_utf8_lossy(&b.data).to_string()
            })
        }).collect();

        let cursor_val = serde_json::to_value(&poll.cursor).unwrap_or(serde_json::Value::Null);
        let new_cursor_slot = cursor_val["slot"].as_u64().unwrap_or(0);
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

struct SequencerHandle {
    sequencer: ZoneSequencer,
    channel_id_hex: String,
    checkpoint_path: String,
}

/// Create a persistent sequencer handle.  The background actor connects to the
/// node and stays alive until `zone_sequencer_destroy` is called.
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

    let node_url_str = unsafe { CStr::from_ptr(node_url) }.to_str().ok()?;
    let channel_id_hex_str = unsafe { CStr::from_ptr(channel_id_hex) }.to_str().ok()?;
    let signing_key_str = unsafe { CStr::from_ptr(signing_key_hex) }.to_str().ok()?;
    let ckpt_path = if checkpoint_path.is_null() { "" } else {
        unsafe { CStr::from_ptr(checkpoint_path) }.to_str().unwrap_or("")
    };

    let key_bytes: [u8; 32] = hex::decode(signing_key_str).ok()?.try_into().ok()?;
    let signing_key = Ed25519Key::from_bytes(&key_bytes);
    let channel_bytes: [u8; 32] = hex::decode(channel_id_hex_str).ok()?.try_into().ok()?;
    let channel_id = ChannelId::from(channel_bytes);
    let url: Url = node_url_str.parse().ok()?;

    let rt = get_runtime();

    // Scan the channel for its latest on-chain message ID, starting from
    // `start_slot`.  Returns the last MsgId found, or `fallback` if the scan
    // finds nothing or fails.
    let scan_channel_tip = |start_slot: u64,
                             fallback: Option<lb_core::mantle::ops::channel::MsgId>|
     -> Option<lb_core::mantle::ops::channel::MsgId> {
        rt.block_on(async {
            let indexer = ZoneIndexer::new(channel_id, url.clone(), None);
            let http_client = lb_common_http_client::CommonHttpClient::new(None);

            let tip_slot: u64 = match http_client.consensus_info(url.clone()).await {
                Ok(i) => i.slot.into(),
                Err(e) => {
                    eprintln!("zone_sequencer_create: consensus_info failed: {e}");
                    return fallback;
                }
            };

            let cursor = serde_json::from_str::<logos_blockchain_zone_sdk::indexer::Cursor>(
                &format!(r#"{{"slot":{},"last_id":null}}"#, start_slot)
            ).ok();

            eprintln!("zone_sequencer_create: scan_channel_tip start_slot={start_slot} tip_slot={tip_slot}");
            let mut last_msg_id = fallback;
            let mut cursor_opt = cursor;
            let mut pages = 0u32;
            loop {
                let poll = match indexer.next_messages(cursor_opt, 1000).await {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("zone_sequencer_create: channel scan error: {e}");
                        break;
                    }
                };
                pages += 1;
                let msg_count = poll.messages.len();
                if let Some(last) = poll.messages.last() {
                    let id_hex = hex::encode(<[u8; 32]>::from(last.id));
                    eprintln!("zone_sequencer_create: scan page {pages}: {msg_count} msgs, latest id={id_hex}");
                    last_msg_id = Some(last.id);
                } else {
                    eprintln!("zone_sequencer_create: scan page {pages}: 0 msgs (gap)");
                }
                let cursor_slot = serde_json::to_value(&poll.cursor)
                    .ok()
                    .and_then(|v| v["slot"].as_u64())
                    .unwrap_or(0);
                // Stop when cursor has reached tip, regardless of whether this
                // page was empty.  Do NOT break on empty pages — the channel
                // may have writes in later slot ranges separated by gaps.
                eprintln!("zone_sequencer_create: scan cursor_slot={cursor_slot} tip_slot={tip_slot}");
                if cursor_slot >= tip_slot {
                    break;
                }
                cursor_opt = Some(poll.cursor);
            }
            let final_id = last_msg_id.map(|id| hex::encode(<[u8; 32]>::from(id))).unwrap_or_else(|| "none".to_string());
            eprintln!("zone_sequencer_create: scan complete after {pages} pages, last_msg_id={final_id}");
            last_msg_id
        })
    };

    let checkpoint = if let Some(mut cp) = load_checkpoint(ckpt_path, channel_id_hex_str) {
        // Checkpoint loaded — verify its last_msg_id against the actual on-chain
        // channel tip.  If the channel advanced while we were offline (another
        // sequencer instance wrote to it, or we missed blocks), our stored
        // last_msg_id is stale.  Using it as the parent causes every publish to
        // be rejected by block producers with InvalidParent; the tx is silently
        // dropped from the mempool and the channel write never lands on-chain.
        let start_slot: u64 = cp.lib_slot.into();
        eprintln!("zone_sequencer_create: verifying checkpoint last_msg_id from slot {start_slot}...");
        if let Some(on_chain) = scan_channel_tip(start_slot, Some(cp.last_msg_id)) {
            let stale = <[u8; 32]>::from(on_chain) != <[u8; 32]>::from(cp.last_msg_id);
            if stale {
                eprintln!(
                    "zone_sequencer_create: checkpoint stale — advancing last_msg_id: {} → {}",
                    hex::encode(<[u8; 32]>::from(cp.last_msg_id)),
                    hex::encode(<[u8; 32]>::from(on_chain))
                );
                cp.last_msg_id = on_chain;
            } else {
                eprintln!("zone_sequencer_create: checkpoint is current");
            }
        }
        Some(cp)
    } else {
        // No checkpoint — bootstrap by scanning the channel for the latest
        // inscription.  Without this, the sequencer starts with MsgId::root()
        // as parent, which is only valid for brand-new channels.  On existing
        // channels the node rejects inscriptions with a duplicate root parent.
        eprintln!("zone_sequencer_create: bootstrapping last_msg_id from chain...");
        let info = rt.block_on(lb_common_http_client::CommonHttpClient::new(None)
            .consensus_info(url.clone()));
        let info = info.ok()?;
        let tip_slot: u64 = info.slot.into();
        let lookback: u64 = 100_000;
        let start_slot = tip_slot.saturating_sub(lookback);
        if let Some(msg_id) = scan_channel_tip(start_slot, None) {
            eprintln!("zone_sequencer_create: bootstrapped last_msg_id={}",
                hex::encode(<[u8; 32]>::from(msg_id)));
            Some(SequencerCheckpoint {
                last_msg_id: msg_id,
                pending_txs: vec![],
                lib: info.lib,
                lib_slot: info.slot,
            })
        } else {
            eprintln!("zone_sequencer_create: no existing inscriptions — starting from root");
            None
        }
    };

    eprintln!("zone_sequencer_create: node={} channel={} checkpoint={}",
        url, channel_id_hex_str,
        if checkpoint.is_some() { "loaded" } else { "fresh" });

    let _guard = rt.enter();
    let sequencer = ZoneSequencer::init(channel_id, signing_key, url, None, checkpoint);

    let handle = Box::new(SequencerHandle {
        sequencer,
        channel_id_hex: channel_id_hex_str.to_string(),
        checkpoint_path: ckpt_path.to_string(),
    });

    Some(Box::into_raw(handle) as *mut std::ffi::c_void)
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

    let h = unsafe { &*(handle as *const SequencerHandle) };
    let data_str = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
    let data_bytes = data_str.as_bytes().to_vec();

    eprintln!("zone_sequencer_publish: publishing {} bytes to channel {}...",
        data_bytes.len(), h.channel_id_hex);

    let rt = get_runtime();
    let result = rt.block_on(async {
        // Wrap in a timeout so a stuck actor (e.g. still connecting to the
        // blocks stream) doesn't block the calling thread forever.
        match tokio::time::timeout(Duration::from_secs(120), async {
            let mut attempts = 0;
            loop {
                attempts += 1;
                match h.sequencer.publish(data_bytes.clone()).await {
                    Ok(result) => {
                        let id_bytes: [u8; 32] = result.inscription_id.into();
                        let id_hex = hex::encode(id_bytes);
                        let cp_last_msg_id = hex::encode(<[u8; 32]>::from(result.checkpoint.last_msg_id));
                        eprintln!("zone_sequencer_publish: inscription_id={id_hex} checkpoint.last_msg_id={cp_last_msg_id}");
                        let mut clean_cp = result.checkpoint.clone();
                        clean_cp.pending_txs.clear();
                        save_checkpoint(&h.checkpoint_path, &clean_cp, &h.channel_id_hex);
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
                eprintln!("zone_sequencer_publish: timed out after 120s — sequencer actor may be stuck initializing");
                None
            }
        }
    })?;

    CString::new(result).ok()
}

/// Get the current checkpoint as JSON.
/// Caller must free the returned string with `zone_free_string`.
#[no_mangle]
pub extern "C" fn zone_sequencer_checkpoint(handle: *mut std::ffi::c_void) -> *mut c_char {
    init_tracing();
    if handle.is_null() { return std::ptr::null_mut(); }
    let h = unsafe { &*(handle as *const SequencerHandle) };
    let rt = get_runtime();
    let result = rt.block_on(async {
        match h.sequencer.checkpoint().await {
            Ok(cp) => serde_json::to_string(&cp).ok(),
            Err(e) => { eprintln!("zone_sequencer_checkpoint: {}", e); None }
        }
    });
    match result {
        Some(json) => CString::new(json).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Destroy a sequencer handle created by `zone_sequencer_create`.
/// The background actor is stopped when the handle is dropped.
#[no_mangle]
pub extern "C" fn zone_sequencer_destroy(handle: *mut std::ffi::c_void) {
    if handle.is_null() { return; }
    unsafe { drop(Box::from_raw(handle as *mut SequencerHandle)); }
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
