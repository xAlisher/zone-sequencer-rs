# zone-sequencer-rs

Rust `cdylib` that wraps the [logos-blockchain zone-sdk](https://github.com/logos-blockchain/logos-blockchain/tree/main/zone-sdk) and exposes a simple C FFI for zone inscription.

Used by [logos-zone-sequencer-module](https://github.com/jimmy-claw/logos-zone-sequencer-module) — a Logos Core Qt plugin.

## C API

```c
// Publish data to a zone channel.
//
// - node_url:        HTTP endpoint of the blockchain node, e.g. "http://localhost:8080"
// - signing_key_hex: Ed25519 seed as 64-char hex (32 bytes).
//                    Channel ID is derived automatically from the public key.
// - data:            Text to inscribe.
// - checkpoint_path: File path to load/save the sequencer checkpoint.
//                    Pass "" to disable persistence.
//                    On first call for a fresh channel, the file need not exist.
//
// Returns a heap-allocated hex string of the local inscription ID on success,
// or NULL on error. Caller must free with zone_free_string().
char* zone_publish(
    const char* node_url,
    const char* signing_key_hex,
    const char* data,
    const char* checkpoint_path
);

// Free a string returned by zone_publish.
void zone_free_string(char* s);
```

## Checkpoint

The zone-sdk requires a checkpoint for chain continuity. Without it, inscriptions are rejected by validators. This library:

1. **Loads** the checkpoint from `checkpoint_path` at the start of each `zone_publish` call
2. **Saves** the updated checkpoint after a successful inscription

For a **fresh channel** (no prior inscriptions), omit or leave the checkpoint file absent — the first inscription bootstraps it automatically.

## Channel ID derivation

Channel ID = Ed25519 public key of the signing key. To derive deterministically from a name:

```bash
# Derive signing key from channel name
SIGNING_KEY=$(echo -n "my-channel" | sha256sum | cut -d" " -f1)
```

## Building

```bash
cargo build --release
# Output: target/release/libzone_sequencer_rs.so
```

Requires Rust + the logos-blockchain git dependency (pulled automatically via Cargo).

## Usage example (C)

```c
#include "zone_sequencer.h"

char* id = zone_publish(
    "http://192.168.0.209:8080",
    "0151f7d1d029b6c40390f45640006430978940f1af9267c9a831d17b75a7bf27",
    "hello world",
    "/tmp/my-channel.checkpoint"
);
if (id) {
    printf("inscription_id: %s\n", id);
    zone_free_string(id);
}
```

## Related

- [logos-zone-sequencer-module](https://github.com/jimmy-claw/logos-zone-sequencer-module) — Logos Core Qt plugin using this library
- [zone-inscribe](https://github.com/jimmy-claw/zone-inscribe) — standalone CLI tool using zone-sdk directly

## Building against logos-blockchain v0.2

The crate is a drop-in FFI replacement for the v0.1.x build — the C ABI in
`zone_sequencer.h` is unchanged. `cargo build` / `cargo test` work out of the box.

Dependencies are pinned to **`xAlisher/logos-blockchain@39e29398`** — a fork of
logos-blockchain v0.2 (testnet rev `8784b837` == tag `0.2.0`) with one cleanup commit.

> ℹ️ **Why a fork.** The upstream v0.2 rev (and every v0.2 tag) ships a stray committed
> gitlink `.claude/worktrees/wf_d6259406-6a4-9` with **no `.gitmodules` entry**, which
> makes `cargo`'s submodule walk abort on any git-dependency build
> (`no URL configured for submodule ...; class=Submodule (17)`). Reported upstream as
> logos-blockchain#3062. Our fork branch `v0.2-nogitlink` just removes that gitlink.
> **Once #3062 is merged upstream, repoint the four `logos-blockchain-*` deps back to
> `logos-blockchain/logos-blockchain` at the fixed rev.**

```sh
cargo test --lib        # builds the full v0.2 workspace from the fork; 6/6 pass
```

Live end-to-end test (opt-in, against a v0.2 node):

```sh
ZSR_NODE=http://<node>:8080 ZSR_KEY=<64-hex-signing-key> \
  cargo test --release e2e_publish_then_query -- --ignored --nocapture
```
