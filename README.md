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

Dependencies are pinned to logos-blockchain rev `8784b837` (== tag `0.2.0`, the v0.2
testnet). The crate is a drop-in FFI replacement for the v0.1.x build — the C ABI in
`zone_sequencer.h` is unchanged.

> ⚠️ **Upstream build blocker.** That rev (and every v0.2 tag) contains a stray
> committed gitlink `.claude/worktrees/wf_d6259406-6a4-9` with **no `.gitmodules`
> entry**, which makes `cargo`'s submodule walk abort on any git-dependency build:
>
> ```
> no URL configured for submodule '.claude/worktrees/wf_d6259406-6a4-9'; class=Submodule (17)
> ```
>
> Until upstream removes the gitlink (`git rm --cached .claude/worktrees/...`), build
> via a local path override:

```sh
# full checkout of logos-blockchain at the pinned rev, next to this repo
git clone --filter=blob:none https://github.com/logos-blockchain/logos-blockchain lb-v0.2
( cd lb-v0.2 && git checkout 8784b837c558b037bf691b0cb720d1c0c20db245 )

# temporarily point the four logos-blockchain-* deps at local paths, e.g.
#   logos-blockchain-zone-sdk                       = { path = "../lb-v0.2/zone-sdk" }
#   logos-blockchain-core                           = { path = "../lb-v0.2/core" }
#   logos-blockchain-key-management-system-service  = { path = "../lb-v0.2/services/key-management-system" }
#   logos-blockchain-common-http-client             = { path = "../lb-v0.2/nodes/node/http-client" }
cargo test --lib
```

Live end-to-end test (opt-in, against a v0.2 node):

```sh
ZSR_NODE=http://<node>:8080 ZSR_KEY=<64-hex-signing-key> \
  cargo test --release e2e_publish_then_query -- --ignored --nocapture
```
