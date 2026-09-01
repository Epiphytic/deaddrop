# Deaddrop Feasibility Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an evidence-backed go/no-go decision for the selected Rust Marmot-to-WASM architecture and prove browser, Node, and native onion connectivity before production implementation begins.

**Architecture:** A pinned upstream MDK is exercised first through native conformance tests and then through a deliberately small WASM wrapper backed by a serializable in-memory store. A native Rust onion echo service, `tor-js` Node transport, and browser KPS transport form an independent network probe; one final runner combines cryptographic and transport evidence into a machine-readable decision.

**Tech Stack:** Rust 1.97.1, Cargo workspace, current Marmot MDK/OpenMLS, `wasm-bindgen`, `wasm-bindgen-test`, `wasm-pack` 0.15.0, Node.js 22+, npm workspaces, TypeScript 5.9.3, Vitest 4.1.11, Playwright Chromium 1.62.1, `tor-js` 0.4.1, KPS, `hypertor` 0.3.0, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-31-deaddrop-design.md`

## Global Constraints

- The GitHub destination is the public repository `Epiphytic/deaddrop`; the default branch is `main`.
- Every repository file is Apache-2.0 licensed; imported MIT upstream code retains its notices.
- Production networking must never silently fall back to a direct connection; loopback is allowed only in explicit probes/debug mode.
- The POC protocol scope is one-to-one Marmot messaging with current account identity proofs, kind `30443` KeyPackages, kind `1059` gift-wrapped welcomes, kind `445` group transport, and kind `9` chat payloads.
- Every relay connection will eventually require NIP-42, but kind-445 and kind-1059 outer authors are ephemeral and are not required to equal the connection key.
- Browser Tor uses Arti WASM through KPS; Node uses direct sockets through embedded Arti/`tor-js` and does not require KPS.
- Browser and CLI state must support a versioned export/import boundary so IndexedDB and filesystem vault adapters can be added later.
- This plan is a feasibility milestone, not production relay or UI implementation. A failed mandatory probe stops execution and triggers a design revision rather than a silent switch to `marmot-ts`.

## Scope and decision rules

The approved design contains multiple independently testable subsystems. This plan covers only its mandatory feasibility gate. If it passes, create separate implementation plans in this order:

1. native relay core, NIP-42 authorization, SQLite, and debug mode;
2. embedded onion service and static application hosting;
3. reusable client core, vault, and `npx` CLI;
4. browser application and KPS deployment;
5. MCP permissions, end-to-end verification, and release hardening.

The final gate is `PASS` only when all mandatory checks below pass:

```ts
export const mandatoryChecks = [
  "mdk_native_current_profile",
  "mdk_wasm_compiles",
  "identity_proof_v2",
  "key_package_30443",
  "welcome_1059",
  "group_event_445",
  "chat_payload_9",
  "wasm_state_round_trip",
  "native_wasm_interop",
  "node_onion_fetch",
  "native_onion_service",
  "browser_kps_onion_fetch",
] as const;
```

Snowflake availability is reported as an optional capability because the pinned `tor-js` browser path requires KPS. A Snowflake failure does not override a successful KPS onion fetch.

If a mandatory check fails, preserve its command, exit code, sanitized stderr, dependency revision, and platform in `artifacts/feasibility/results.json`, set the overall decision to `FAIL`, skip production planning, and write the exact design assumption that must change.

## File map

```text
.
├── .github/workflows/feasibility.yml       # deterministic compile/unit gate; live Tor is manual
├── .gitignore                              # generated, secret, Tor, gateway, and browser artifacts
├── Cargo.toml                              # feasibility Rust workspace
├── LICENSE                                 # Apache License 2.0
├── NOTICE                                  # Deaddrop attribution and imported-source policy
├── README.md                               # project status and feasibility commands
├── package.json                            # npm workspace scripts and Node version floor
├── package-lock.json                       # exact JavaScript dependency graph
├── rust-toolchain.toml                     # exact Rust toolchain and WASM target
├── upstream-pins.toml                      # human- and machine-readable source revisions
├── artifacts/feasibility/.gitkeep          # stable output location; result JSON is committed
├── crates/
│   ├── marmot-wasm-probe/
│   │   ├── Cargo.toml
│   │   ├── src/error.rs                    # stable probe error codes
│   │   ├── src/lib.rs                      # wasm-bindgen MarmotProbe API
│   │   ├── src/snapshot.rs                 # versioned state envelope
│   │   ├── src/storage/
│   │   │   ├── mod.rs                      # StorageProvider aggregate and transactions
│   │   │   ├── kv.rs                       # typed namespace/key encoding
│   │   │   ├── groups.rs                   # group and route storage traits
│   │   │   ├── messages.rs                 # message, dedupe, and snapshot traits
│   │   │   ├── outbound.rs                 # intent and fanout traits
│   │   │   └── lifecycle.rs                # welcome/capability/convergence/device traits
│   │   ├── tests/
│   │       ├── native_flow.rs              # two-party current-profile reference flow
│   │       ├── storage_contract.rs         # atomic and round-trip storage behavior
│   │       └── web.rs                      # wasm-bindgen browser tests
│   │   └── examples/
│   │       └── generate_fixture.rs          # writes deterministic native interop fixture
│   └── onion-probe/
│       ├── Cargo.toml
│       ├── src/lib.rs                      # onion app and JSON startup record
│       ├── src/main.rs                     # process lifecycle only
│       └── tests/config.rs                 # persistent identity and no-clearnet defaults
├── packages/transport-probe/
│   ├── package.json
│   ├── tsconfig.json
│   ├── playwright.config.ts
│   ├── src/browser.ts                      # browser/KPS probe entry
│   ├── src/node.ts                         # Node/direct-Arti probe entry
│   ├── src/result.ts                       # shared result schema writer
│   ├── test/node-onion.test.ts
│   ├── test/browser-kps.spec.ts
│   └── web/index.html                      # local, self-contained browser fixture
├── scripts/build-marmot-wasm.sh
├── scripts/install-kps-gateway.sh
├── scripts/run-feasibility.mjs
├── scripts/run-live-node-probe.mjs
├── scripts/run-live-browser-probe.mjs
└── schemas/feasibility-result.schema.json
```

---

### Task 1: Repository foundation, licensing, and immutable upstream pins

**Files:**
- Create: `.gitignore`
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `package.json`
- Create: `LICENSE`
- Create: `NOTICE`
- Create: `README.md`
- Create: `upstream-pins.toml`
- Create: `artifacts/feasibility/.gitkeep`

**Interfaces:**
- Consumes: approved repository name and Apache-2.0 choice from the spec.
- Produces: a reproducible Rust/npm workspace and `upstream-pins.toml` consumed by every later task.

- [ ] **Step 1: Write the failing pin-validation test**

Create `scripts/validate-pins.mjs` with exact full-SHA and version validation:

```js
import { readFile } from "node:fs/promises";

const text = await readFile(new URL("../upstream-pins.toml", import.meta.url), "utf8");
const required = {
  mdk_rev: /^[0-9a-f]{40}$/,
  openmls_rev: /^[0-9a-f]{40}$/,
  tor_js_gateway_rev: /^[0-9a-f]{40}$/,
  tor_js_npm: /^0\.4\.1$/,
  hypertor: /^0\.3\.0$/,
};

for (const [name, pattern] of Object.entries(required)) {
  const match = text.match(new RegExp(`^${name} = "([^"]+)"$`, "m"));
  if (!match || !pattern.test(match[1])) {
    throw new Error(`invalid or missing pin: ${name}`);
  }
}
```

- [ ] **Step 2: Run the validation and verify it fails**

Run: `node scripts/validate-pins.mjs`

Expected: FAIL with `ENOENT` for `upstream-pins.toml` or `invalid or missing pin`.

- [ ] **Step 3: Create the pinned workspace metadata**

Use these exact values in `upstream-pins.toml`:

```toml
mdk_repo = "https://github.com/marmot-protocol/mdk.git"
mdk_rev = "876bdf3c408df0658c158da6a6521745cd0abde5"
openmls_repo = "https://github.com/erskingardner/openmls.git"
openmls_rev = "59e7d3b27a7e95237879dd5478de1fd90eff7ada"
tor_js_repo = "https://github.com/ethereum/tor-js.git"
tor_js_gateway_rev = "dfa2096ec2067b063e873525f7ac6beaba5be966"
tor_js_npm = "0.4.1"
hypertor = "0.3.0"
```

Create the root Cargo workspace:

```toml
[workspace]
resolver = "3"
members = []

[workspace.package]
edition = "2024"
license = "Apache-2.0"
rust-version = "1.97"

[workspace.dependencies]
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
tokio = { version = "1.47", features = ["macros", "rt-multi-thread", "signal", "time"] }
```

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.97.1"
components = ["clippy", "rustfmt"]
targets = ["wasm32-unknown-unknown"]
profile = "minimal"
```

Create the root `package.json`:

```json
{
  "name": "@epiphytic/deaddrop-workspace",
  "private": true,
  "license": "Apache-2.0",
  "engines": { "node": ">=22.0.0" },
  "workspaces": ["packages/*"],
  "scripts": {
    "check:pins": "node scripts/validate-pins.mjs",
    "test": "npm run test --workspaces --if-present",
    "feasibility": "node scripts/run-feasibility.mjs --live",
    "feasibility:offline": "node scripts/run-feasibility.mjs --offline"
  }
}
```

Add the unmodified Apache License 2.0 text from `https://www.apache.org/licenses/LICENSE-2.0.txt` as `LICENSE`. In `NOTICE`, state `Deaddrop Copyright 2026 Epiphytic` and that vendored MDK remains MIT-licensed under its upstream notice. Ignore `.DS_Store`, `.superpowers/`, `target/`, `node_modules/`, Playwright output, Tor state directories, KPS private keys, generated WASM packages, and live probe logs.

- [ ] **Step 4: Verify workspace and pins pass**

Run: `node scripts/validate-pins.mjs`

Expected: PASS with exit code 0.

Run: `cargo metadata --no-deps --format-version 1`

Expected: PASS with an empty member list. Tasks 2 and 5 add their crates only when each crate exists.

Install the pinned WASM builder:

```bash
cargo install wasm-pack --version 0.15.0 --locked
```

Run: `wasm-pack --version`

Expected: `wasm-pack 0.15.0`.

- [ ] **Step 5: Commit and create the GitHub repository**

```bash
git add .gitignore Cargo.toml rust-toolchain.toml package.json LICENSE NOTICE README.md upstream-pins.toml artifacts/feasibility/.gitkeep scripts/validate-pins.mjs
git commit -m "chore: initialize deaddrop feasibility workspace"
```

Run `gh repo view Epiphytic/deaddrop`. If it returns not found, run:

```bash
gh repo create Epiphytic/deaddrop --public --source=. --remote=origin --push
```

If it already exists, inspect `git remote -v`, add `origin` only if missing, and push `main` without overwriting any remote history.

---

### Task 2: Fail-fast MDK native and WASM compile surface

**Files:**
- Create: `crates/marmot-wasm-probe/Cargo.toml`
- Create: `crates/marmot-wasm-probe/src/lib.rs`
- Create: `crates/marmot-wasm-probe/tests/native_surface.rs`
- Create: `scripts/build-marmot-wasm.sh`
- Create: `artifacts/feasibility/mdk-build.json`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: pinned MDK Git revision from `upstream-pins.toml`.
- Produces: `probe_build_info() -> String` and a compile-result artifact used by the final decision runner.

- [ ] **Step 1: Write a native test that forces the current MDK surface to link**

```rust
use marmot_wasm_probe::probe_build_info;

#[test]
fn reports_pinned_current_profile_surface() {
    let info: serde_json::Value = serde_json::from_str(&probe_build_info()).unwrap();
    assert_eq!(info["mdk_rev"], "876bdf3c408df0658c158da6a6521745cd0abde5");
    assert_eq!(info["profile"], "current");
    assert_eq!(info["kinds"], serde_json::json!([9, 445, 1059, 30443]));
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `cargo test -p marmot-wasm-probe --test native_surface`

Expected: FAIL because the crate/API does not exist.

- [ ] **Step 3: Add the smallest crate that links the selected engine and Nostr peeler**

Add `"crates/marmot-wasm-probe"` to the root workspace member list and use exact Git dependencies on the pinned revision:

```toml
[package]
name = "marmot-wasm-probe"
version = "0.0.0"
edition.workspace = true
license.workspace = true
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
cgka-engine = { git = "https://github.com/marmot-protocol/mdk.git", rev = "876bdf3c408df0658c158da6a6521745cd0abde5" }
cgka-traits = { git = "https://github.com/marmot-protocol/mdk.git", rev = "876bdf3c408df0658c158da6a6521745cd0abde5" }
transport-nostr-peeler = { git = "https://github.com/marmot-protocol/mdk.git", rev = "876bdf3c408df0658c158da6a6521745cd0abde5" }
serde.workspace = true
serde_json.workspace = true
wasm-bindgen = "0.2.125"

[dev-dependencies]
serde_json.workspace = true
```

Implement `probe_build_info()` while referencing upstream constants so Cargo cannot omit those crates:

```rust
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP};

pub fn probe_build_info() -> String {
    let _suite = cgka_engine::DEFAULT_CIPHERSUITE;
    serde_json::json!({
        "mdk_rev": "876bdf3c408df0658c158da6a6521745cd0abde5",
        "profile": "current",
        "kinds": [9, KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP, 30443],
    })
    .to_string()
}
```

- [ ] **Step 4: Verify native linkage passes**

Run: `cargo test -p marmot-wasm-probe --test native_surface`

Expected: PASS.

- [ ] **Step 5: Write and run the WASM compile probe**

Create `scripts/build-marmot-wasm.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cargo build --locked -p marmot-wasm-probe --target wasm32-unknown-unknown
```

Run: `bash scripts/build-marmot-wasm.sh`

Expected: either PASS, or a reproducible compiler error that names the incompatible crate/API. Do not add broad `cfg` exclusions merely to make the command green; `cgka-engine` and `transport-nostr-peeler` must remain real WASM dependencies.

- [ ] **Step 6: Record the result and apply the stop rule**

Write `artifacts/feasibility/mdk-build.json` with this exact shape:

```json
{
  "check": "mdk_wasm_compiles",
  "status": "PASS",
  "command": "cargo build --locked -p marmot-wasm-probe --target wasm32-unknown-unknown",
  "mdk_rev": "876bdf3c408df0658c158da6a6521745cd0abde5",
  "target": "wasm32-unknown-unknown",
  "sanitized_stderr": ""
}
```

For a failure, set `status` to `FAIL`, preserve sanitized compiler output, commit the artifact, and stop this plan. The design must then choose between maintaining an MDK fork/port or revisiting `marmot-ts`.

- [ ] **Step 7: Commit**

```bash
git add crates/marmot-wasm-probe scripts/build-marmot-wasm.sh artifacts/feasibility/mdk-build.json Cargo.lock
git commit -m "spike: verify mdk native and wasm compile surface"
```

---

### Task 3: Serializable WASM storage adapter

**Files:**
- Create: `crates/marmot-wasm-probe/src/error.rs`
- Create: `crates/marmot-wasm-probe/src/snapshot.rs`
- Create: `crates/marmot-wasm-probe/src/storage/mod.rs`
- Create: `crates/marmot-wasm-probe/src/storage/kv.rs`
- Create: `crates/marmot-wasm-probe/src/storage/groups.rs`
- Create: `crates/marmot-wasm-probe/src/storage/messages.rs`
- Create: `crates/marmot-wasm-probe/src/storage/outbound.rs`
- Create: `crates/marmot-wasm-probe/src/storage/lifecycle.rs`
- Create: `crates/marmot-wasm-probe/tests/storage_contract.rs`
- Modify: `crates/marmot-wasm-probe/Cargo.toml`

**Interfaces:**
- Consumes: all synchronous storage traits required by `cgka_traits::StorageProvider` and OpenMLS `MemoryStorage` at the pinned revision.
- Produces: `WasmStorage::new()`, `WasmStorage::export() -> Result<Vec<u8>, ProbeError>`, and `WasmStorage::import(&[u8]) -> Result<Self, ProbeError>`.

- [ ] **Step 1: Record the upstream backend-enum compatibility gap**

The pinned MDK's `Backend` enum contains only `Sqlite`, although `StorageProvider` is otherwise generic. Implement `backend()` with the only available sentinel `Backend::Sqlite`, exercise the complete one-to-one trace in Task 4 to confirm the engine does not branch on that diagnostic, and record `backend_enum_gap: "requires upstream Backend::Memory variant before production"` in the feasibility result. This compatibility shim is permitted only in `marmot-wasm-probe`; production planning must include an upstream change or a maintained patch and may not ship the false diagnostic.

- [ ] **Step 2: Write failing atomicity and snapshot tests**

```rust
use cgka_traits::storage::{GroupStorage, StorageProvider};
use marmot_wasm_probe::storage::WasmStorage;

#[test]
fn transaction_rolls_back_every_namespace() {
    let store = WasmStorage::new();
    let result: Result<(), cgka_traits::StorageError> = store.with_transaction(|tx| {
        tx.test_put_raw("groups", b"g", b"one")?;
        tx.test_put_raw("messages", b"m", b"two")?;
        Err(cgka_traits::StorageError::Backend("rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(store.test_get_raw("groups", b"g").unwrap(), None);
    assert_eq!(store.test_get_raw("messages", b"m").unwrap(), None);
}

#[test]
fn exported_state_round_trips_byte_for_byte() {
    let store = WasmStorage::new();
    store.test_put_raw("probe", b"key", b"value").unwrap();
    let encoded = store.export().unwrap();
    let restored = WasmStorage::import(&encoded).unwrap();
    assert_eq!(restored.test_get_raw("probe", b"key").unwrap(), Some(b"value".to_vec()));
    assert_eq!(restored.export().unwrap(), encoded);
}
```

- [ ] **Step 3: Run the tests and verify they fail**

Run: `cargo test -p marmot-wasm-probe --test storage_contract`

Expected: FAIL because `WasmStorage` does not exist.

- [ ] **Step 4: Implement one typed key/value core and versioned envelope**

Add these exact dependencies to `crates/marmot-wasm-probe/Cargo.toml`:

```toml
openmls_memory_storage = { git = "https://github.com/erskingardner/openmls.git", rev = "59e7d3b27a7e95237879dd5478de1fd90eff7ada", features = ["extensions-draft"] }
postcard = { version = "1.1", features = ["alloc"] }
```

Use a deterministic `BTreeMap<Vec<u8>, Vec<u8>>` behind `Arc<RwLock<_>>`. Every logical key is `namespace || 0x00 || key`. JSON-encode MDK records. OpenMLS `MemoryStorage::values` is public but internally a `HashMap`; copy it into a `BTreeMap` before serialization so repeated exports are byte-identical. The envelope is:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("snapshot exceeds 16777216 bytes")]
    SnapshotTooLarge,
    #[error("unsupported snapshot version {0}")]
    SnapshotVersion(u16),
    #[error("nested transactions are not supported")]
    NestedTransaction,
    #[error("storage serialization failed")]
    Serialization,
    #[error("marmot operation failed")]
    Marmot,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotV1 {
    version: u16,
    app_entries: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    openmls_entries: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
}

const SNAPSHOT_VERSION: u16 = 1;
```

Serialize `SnapshotV1` with `postcard = "1.1"`. Reject every version except `1`, reject trailing bytes, and cap imported snapshots at 16 MiB. Implement transactions by cloning both maps before the closure and restoring both clones on `Err`; nested transactions return `ProbeError::NestedTransaction`.

- [ ] **Step 5: Implement the complete MDK aggregate contract by namespace**

Use these stable namespaces and keys; no method may silently return success without performing its documented operation:

| Trait family | Namespace/key |
|---|---|
| `GroupStorage` | `group/<group_id>`, `route/<transport_group_id>/<epoch>` |
| `MessageStorage` | `message/<message_id>`, `pending-event/<event_id>`, `dedup/<message_id>`, `snapshot/<group_id>/<name>` |
| `OutboundIntentStorage` | `intent/<message_id>` |
| `OutboundFanoutStorage` | `fanout/<message_id>` |
| `LeaveRequestStorage` | `leave/<group_id>` |
| `DisbandRequestStorage` | `disband-request/<group_id>` |
| `DisbandCandidateStorage` | `disband-candidate/<group_id>/<candidate_id>` |
| `DisbandTombstoneStorage` | `disband-tombstone/<group_id>` |
| `WelcomeStorage` | `welcome/<message_id>` |
| `CapabilityStorage` | `feature/<feature_id>`, `member-capability/<group_id>/<member_id>` |
| `ConvergencePolicyStorage` | `convergence-policy/<group_id>` |
| `ConvergencePassStorage` | `convergence-pass/<group_id>` |
| `DeferredPeelGenerationStorage` | `deferred-peel/<group_id>` |
| `MemberValidationCacheStorage` | `validation/<group_id>` |
| `AccountDeviceSignerStorage` | `account-signer/<marmot_identity>` |
| `KeyPackageBundleStorage` | `key-package-bundle/<storage_key>` |

List operations scan only their namespace prefix and sort decoded records by their typed identifier before returning them. `take_welcome` is atomic. Snapshot/rollback copies both application entries for the group and the OpenMLS map. For this probe alone, `backend()` returns the documented `Backend::Sqlite` compatibility sentinel because the pinned enum has no memory variant. `maintenance_storage()` returns `None`.

- [ ] **Step 6: Verify storage behavior and WASM compilation**

Run: `cargo test -p marmot-wasm-probe --test storage_contract`

Expected: PASS.

Run: `bash scripts/build-marmot-wasm.sh`

Expected: PASS with the real storage adapter linked.

- [ ] **Step 7: Commit**

```bash
git add crates/marmot-wasm-probe artifacts/feasibility Cargo.lock
git commit -m "spike: add serializable wasm storage for mdk"
```

---

### Task 4: Current-profile two-party Marmot flow and WASM state restoration

**Files:**
- Modify: `crates/marmot-wasm-probe/src/lib.rs`
- Modify: `crates/marmot-wasm-probe/src/error.rs`
- Create: `crates/marmot-wasm-probe/tests/native_flow.rs`
- Create: `crates/marmot-wasm-probe/tests/web.rs`
- Create: `crates/marmot-wasm-probe/examples/generate_fixture.rs`
- Create: `artifacts/feasibility/marmot-native-fixture.json`
- Create: `scripts/build-marmot-wasm.sh`
- Modify: `crates/marmot-wasm-probe/Cargo.toml`

**Interfaces:**
- Consumes: `WasmStorage`, `cgka_engine::Engine`, `transport_nostr_peeler::NostrMlsPeeler`.
- Produces the JS-facing class below:

```ts
class MarmotProbe {
  static create(secretKeyHex: string): MarmotProbe;
  static fromState(state: Uint8Array): MarmotProbe;
  createKeyPackage(relayUrl: string, nowSeconds: bigint): Promise<string>;
  createConversation(keyPackageEventJson: string, groupHHex: string): Promise<string>;
  joinWelcome(giftWrapJson: string): Promise<string>;
  sendChat(groupIdHex: string, content: string, createdAt: bigint): Promise<string>;
  ingest(eventJson: string): Promise<string>;
  exportState(): Uint8Array;
}
```

Every returned string is canonical JSON with an explicit `type` discriminator. No secret key or decrypted content appears in errors.

- [ ] **Step 1: Write the native end-to-end test**

The test uses fixed Alice/Bob Nostr secrets, a fixed relay URL `ws://deaddrop.invalid`, and a random 32-byte `h`. It must assert:

```rust
assert_eq!(key_package_event.kind, 30443);
assert!(key_package_event.verify().is_ok());
assert!(key_package_has_current_identity_proof_v2(&key_package_event));
assert_eq!(welcome_event.kind, 1059);
assert_ne!(welcome_event.pubkey, sender_account_pubkey);
assert_eq!(group_event.kind, 445);
assert_ne!(group_event.pubkey, sender_account_pubkey);
assert_eq!(group_event.single_tag("h"), Some(group_h_hex.as_str()));
assert_eq!(received_inner_event.kind, 9);
assert_eq!(received_inner_event.content, "hello from a disposable sender");
```

After Bob joins and receives the message, export both clients, reconstruct both with `from_state`, send Bob's reply, and assert Alice decrypts it. This proves identity proof, KeyPackage, Welcome, group transport, chat payload, and state restoration in one trace.

- [ ] **Step 2: Run the native test and verify it fails**

Run: `cargo test -p marmot-wasm-probe --test native_flow -- --nocapture`

Expected: FAIL because `MarmotProbe` operations are absent.

- [ ] **Step 3: Implement the smallest current-profile wrapper**

Construct the upstream engine with:

```rust
let peeler = NostrMlsPeeler::new().with_welcome_signer(nostr_keys.clone());
let engine = EngineBuilder::new(storage.clone())
    .identity(nostr_keys.public_key().to_bytes().to_vec())
    .account_identity_proof_signer(proof_signer)
    .protocol_profile(ProtocolProfile::Current)
    .peeler(Box::new(peeler))
    .build()?;
```

Use upstream `fresh_key_package`, `create_group`, `join_welcome`, `send(SendIntent::AppMessage { group_id, payload })`, `ingest`, and publish-confirmation APIs exactly as required by the pinned `CgkaEngine` trait. Build application messages as unsigned kind-9 Nostr events. Convert upstream `NostrTransportEvent` values to canonical event JSON without altering signatures or tags. Refuse a caller-supplied `h` unless it decodes to exactly 32 bytes.

- [ ] **Step 4: Verify the native flow passes**

Run: `cargo test -p marmot-wasm-probe --test native_flow -- --nocapture`

Expected: PASS with all event-kind, author, identity-proof, and restart assertions.

- [ ] **Step 5: Generate a checked-in native interop fixture from fixed scenario inputs**

`generate_fixture.rs` runs the same fixed-key native flow and accepts exactly one output path argument. It atomically writes RFC 8785 canonical JSON containing the public events, exported Bob state, expected group id, expected plaintext, upstream revisions, and a conspicuous `test_keys_only: true` marker. It must refuse paths outside `artifacts/feasibility/` and must never accept runtime/user keys.

OpenMLS and the Nostr wrappers draw fresh system entropy for KeyPackages, group construction, nonces, and ephemeral transport authors. The checked-in fixture is therefore the authoritative cross-runtime artifact; regenerating it intentionally produces different cryptographic bytes even though the scenario keys, timestamps, relay, `h`, and plaintext are fixed. Browser CI consumes the committed artifact and validates its revisions and protocol fields. Regeneration is an explicit fixture update, not a byte-for-byte reproducibility check.

Run:

```bash
cargo run -p marmot-wasm-probe --example generate_fixture -- artifacts/feasibility/marmot-native-fixture.json
```

Expected: PASS, with kind `30443`, `1059`, and `445` events and a version-1 state blob generated by the native build.

- [ ] **Step 6: Add the browser WASM test**

Use `wasm_bindgen_test_configure!(run_in_browser)` and call only exported `MarmotProbe` methods. First load `include_str!("../../../artifacts/feasibility/marmot-native-fixture.json")`, restore Bob from the native state blob, ingest the native kind-1059 and kind-445 events, and assert the native plaintext is recovered. Then repeat a complete two-party trace in WASM, export Bob before the first receive, restore him, and assert he decrypts the message after restoration. The test must not use Node polyfills, filesystem APIs, SQLite, or direct sockets.

- [ ] **Step 7: Build and run WASM tests**

Update `scripts/build-marmot-wasm.sh` to run:

```bash
wasm-pack build crates/marmot-wasm-probe --target web --out-dir ../../artifacts/feasibility/marmot-wasm
wasm-pack test --headless --chrome crates/marmot-wasm-probe
```

Expected: both commands PASS. Record the uncompressed and gzip WASM sizes in the result artifact; size is informational for this gate.

- [ ] **Step 8: Commit**

```bash
git add crates/marmot-wasm-probe scripts/build-marmot-wasm.sh artifacts/feasibility
git commit -m "spike: prove marmot one-to-one flow in wasm"
```

---

### Task 5: Embedded native Arti onion service

**Files:**
- Create: `crates/onion-probe/Cargo.toml`
- Create: `crates/onion-probe/src/lib.rs`
- Create: `crates/onion-probe/src/main.rs`
- Create: `crates/onion-probe/tests/config.rs`
- Create: `crates/onion-probe/tests/health.rs`
- Create: `crates/onion-probe/tests/live_persistence.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: a writable Tor state directory and virtual port 80.
- Produces: `OnionProbeConfig::production(state_dir)`, a `/health` JSON route, and one serialized `StartupRecord { onion_url: String, state_dir: PathBuf }` line.

- [x] **Step 1: Write failing configuration tests**

```rust
#[test]
fn production_has_no_clearnet_listener() {
    let cfg = OnionProbeConfig::production("/tmp/deaddrop-onion-probe".into());
    assert_eq!(cfg.virtual_port, 80);
    assert_eq!(cfg.clearnet_bind, None);
    assert_eq!(cfg.nickname, "deaddrop-feasibility");
}

#[test]
fn state_directory_is_required() {
    assert!(OnionProbeConfig::try_new(None).is_err());
}
```

- [x] **Step 2: Run and verify failure**

Run: `cargo test -p onion-probe --test config`

Expected: FAIL because the crate does not exist.

- [x] **Step 3: Implement the minimal onion application**

Add `"crates/onion-probe"` to the root Cargo workspace member list. Use:

```toml
hypertor = { version = "=0.3.0", default-features = false, features = ["server", "rustls", "static-sqlite"] }
```

Build the app without a localhost reverse proxy:

```rust
let app = hypertor::OnionApp::new().get("/health", |_request| async {
    hypertor::ServeResponse::json(&serde_json::json!({
        "service": "deaddrop-feasibility",
        "status": "ok"
    }))
});

let onion = hypertor::OnionService::builder()
    .nickname(config.nickname.clone())?
    .state_dir(&config.state_dir)
    .port(config.virtual_port)
    .launch()
    .await?;
let url = format!("http://{}", onion.onion_address());
let running = app.serve_on(onion).await?;
```

Print the startup record to stdout and structured diagnostics to stderr. Never print onion private keys.

- [x] **Step 4: Verify unit tests and native build**

Run: `cargo test -p onion-probe`

Expected: PASS.

Run: `cargo build --release -p onion-probe`

Expected: PASS.

- [x] **Step 5: Run the live persistence probe**

With `DEADDROP_LIVE_TOR=1`, start the service twice against the same temporary state directory, capture the first startup JSON line each time, and assert both onion URLs are identical. Inspect listening sockets and assert the process has no TCP listener; Arti's outbound sockets and onion rendezvous streams are allowed.

- [x] **Step 6: Commit**

```bash
git add crates/onion-probe Cargo.lock artifacts/feasibility
git commit -m "spike: host an http service with embedded arti"
```

---

### Task 6: Node direct-Arti onion fetch

**Files:**
- Create: `packages/transport-probe/package.json`
- Create: `packages/transport-probe/tsconfig.json`
- Create: `packages/transport-probe/src/node.ts`
- Create: `packages/transport-probe/src/result.ts`
- Create: `packages/transport-probe/test/node-onion.test.ts`
- Create: `scripts/run-live-node-probe.mjs`
- Modify: `package-lock.json`

**Interfaces:**
- Consumes: `onion-probe` startup JSON and `tor-js@0.4.1` with no gateway option.
- Produces: `fetchOnionFromNode(onionUrl: string): Promise<ProbeResult>`.

- [ ] **Step 1: Write the failing live Node test**

```ts
import { expect, test } from "vitest";
import { fetchOnionFromNode } from "../src/node.js";

test.runIf(process.env.DEADDROP_LIVE_TOR === "1")(
  "fetches the embedded onion service without KPS",
  async () => {
    const result = await fetchOnionFromNode(process.env.DEADDROP_ONION_URL!);
    expect(result.status).toBe("PASS");
    expect(result.transport).toBe("tor-js-node-direct");
    expect(result.body).toEqual({ service: "deaddrop-feasibility", status: "ok" });
  },
  180_000,
);
```

- [ ] **Step 2: Run it and verify the implementation failure**

Run with a temporary fake URL: `DEADDROP_LIVE_TOR=1 DEADDROP_ONION_URL=http://example.onion npm test -w packages/transport-probe -- node-onion`

Expected: FAIL because `fetchOnionFromNode` is absent.

- [ ] **Step 3: Implement direct Node transport**

Create `packages/transport-probe/package.json` with exact dependency versions:

```json
{
  "name": "@epiphytic/deaddrop-transport-probe",
  "private": true,
  "type": "module",
  "license": "Apache-2.0",
  "scripts": {
    "test": "vitest run",
    "test:browser": "playwright test"
  },
  "dependencies": { "tor-js": "0.4.1" },
  "devDependencies": {
    "@playwright/test": "1.62.1",
    "ajv": "8.20.0",
    "esbuild": "0.28.2",
    "typescript": "5.9.3",
    "vitest": "4.1.11"
  }
}
```

Run `npm install` at the repository root and commit the resulting lockfile.

Create `src/result.ts` with the shared transport result:

```ts
export type ProbeTransport = "tor-js-node-direct" | "tor-js-browser-kps";

export interface ProbeResult {
  status: "PASS";
  transport: ProbeTransport;
  body: { service: string; status: string };
  durationMs: number;
}
```

```ts
import { TorClient, storage } from "tor-js/wasm-file";

export async function fetchOnionFromNode(onionUrl: string): Promise<ProbeResult> {
  if (!/^http:\/\/[a-z2-7]{56}\.onion\/?$/.test(new URL(onionUrl).origin + "/")) {
    throw new Error("onionUrl must be a v3 onion HTTP origin");
  }
  const started = performance.now();
  const client = new TorClient({ storage: new storage.MemoryStorage() });
  try {
    const response = await client.fetch(new URL("/health", onionUrl).href, {
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok) throw new Error(`onion health returned ${response.status}`);
    return {
      status: "PASS",
      transport: "tor-js-node-direct",
      body: await response.json(),
      durationMs: Math.round(performance.now() - started),
    };
  } finally {
    client.close();
  }
}
```

Do not set `gateway` or provide a clearnet fallback URL.

- [ ] **Step 4: Run the real live probe**

`scripts/run-live-node-probe.mjs` starts `onion-probe`, parses its JSON startup line, runs the Vitest case, terminates the child cleanly, and writes `artifacts/feasibility/node-onion.json`.

Run: `DEADDROP_LIVE_TOR=1 node scripts/run-live-node-probe.mjs`

Expected: PASS within 180 seconds and a result whose transport is `tor-js-node-direct`.

- [ ] **Step 5: Commit**

```bash
git add packages/transport-probe scripts/run-live-node-probe.mjs package-lock.json artifacts/feasibility/node-onion.json
git commit -m "spike: fetch an onion service from node arti"
```

---

### Task 7: Browser Arti/KPS onion fetch

**Files:**
- Create: `packages/transport-probe/playwright.config.ts`
- Create: `packages/transport-probe/src/browser.ts`
- Create: `packages/transport-probe/test/browser-kps.spec.ts`
- Create: `packages/transport-probe/web/index.html`
- Create: `scripts/install-kps-gateway.sh`
- Create: `scripts/run-live-browser-probe.mjs`
- Modify: `packages/transport-probe/package.json`
- Modify: `package-lock.json`

**Interfaces:**
- Consumes: onion URL plus a KPS address in `ip:port:certhash` format.
- Produces: `fetchOnionFromBrowser(onionUrl, gateway): Promise<ProbeResult>` and `artifacts/feasibility/browser-kps.json`.

- [ ] **Step 1: Write the failing Playwright test**

```ts
import { expect, test } from "@playwright/test";

test("browser builds Tor locally and reaches the onion through KPS", async ({ page }) => {
  await page.goto(`/index.html#${encodeURIComponent(JSON.stringify({
    onionUrl: process.env.DEADDROP_ONION_URL,
    gateway: process.env.DEADDROP_KPS_GATEWAY,
  }))}`);
  await expect(page.locator("[data-result]"))
    .toHaveAttribute("data-result", "PASS", { timeout: 180_000 });
  await expect(page.locator("pre")).toContainText('"status":"ok"');
});
```

- [ ] **Step 2: Run it and verify failure**

Run: `npm run test:browser --workspace packages/transport-probe -- browser-kps.spec.ts`

Expected: FAIL because the fixture and browser function do not exist.

- [ ] **Step 3: Pin and install the gateway**

`scripts/install-kps-gateway.sh` must verify the checked-out commit equals `dfa2096ec2067b063e873525f7ac6beaba5be966`, then run:

```bash
cargo install --git https://github.com/ethereum/tor-js.git --rev dfa2096ec2067b063e873525f7ac6beaba5be966 --locked tor-js-gateway --root artifacts/tools/tor-js-gateway
```

Generate gateway keys only under an ignored temporary directory. Parse the KPS address from startup output; never commit the gateway private key.

- [ ] **Step 4: Implement the self-contained browser fixture**

Use `tor-js/wasm-base64` so the browser never fetches WASM from a CDN:

```ts
import { TorClient, storage } from "tor-js/wasm-base64";

export async function fetchOnionFromBrowser(
  onionUrl: string,
  gateway: string,
): Promise<ProbeResult> {
  const started = performance.now();
  const client = new TorClient({
    gateway,
    storage: new storage.IndexedDBStorage("deaddrop-feasibility-tor"),
  });
  try {
    await client.ready();
    const response = await client.fetch(new URL("/health", onionUrl).href, {
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok) throw new Error(`onion health returned ${response.status}`);
    return {
      status: "PASS",
      transport: "tor-js-browser-kps",
      body: await response.json(),
      durationMs: Math.round(performance.now() - started),
    };
  } finally {
    client.close();
  }
}
```

Bundle locally with esbuild. The page may contact only the configured KPS IP/UDP port as part of WebRTC and the local fixture origin. Add no analytics, fonts, STUN/TURN defaults, CDN imports, or alternate HTTP URL.

- [ ] **Step 5: Run the orchestrated live browser probe**

`scripts/run-live-browser-probe.mjs` starts `onion-probe`, the pinned KPS gateway, and a loopback static fixture server; passes the onion and gateway addresses to Playwright; collects browser console/network errors; and terminates every child in `finally`.

Run: `DEADDROP_LIVE_TOR=1 node scripts/run-live-browser-probe.mjs`

Expected: PASS within 180 seconds and `artifacts/feasibility/browser-kps.json` with transport `tor-js-browser-kps`.

- [ ] **Step 6: Record Snowflake capability separately**

Inspect the pinned `tor-js` public API and write:

```json
{
  "check": "snowflake_transport",
  "status": "UNSUPPORTED",
  "mandatory": false,
  "reason": "tor-js 0.4.1 exposes browser relay access through KPS; no Snowflake option is present in the pinned public API"
}
```

If the pinned revision actually exposes a tested Snowflake provider, replace `UNSUPPORTED` with the live result and exact command. Do not describe public Snowflake as providing the KPS gateway.

- [ ] **Step 7: Commit**

```bash
git add packages/transport-probe scripts/install-kps-gateway.sh scripts/run-live-browser-probe.mjs package-lock.json artifacts/feasibility
git commit -m "spike: fetch an onion service from browser arti over kps"
```

---

### Task 8: Machine-readable gate, CI, and recommendation

**Files:**
- Create: `schemas/feasibility-result.schema.json`
- Create: `scripts/run-feasibility.mjs`
- Create: `.github/workflows/feasibility.yml`
- Create: `artifacts/feasibility/results.json`
- Create: `docs/feasibility/2026-08-31-results.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: every per-probe JSON artifact.
- Produces: schema-valid `results.json` and a one-page human recommendation with overall `PASS` or `FAIL`.

- [ ] **Step 1: Write the failing aggregator test**

Create `scripts/run-feasibility.test.mjs`:

```js
import assert from "node:assert/strict";
import { decide } from "./run-feasibility.mjs";

const pass = Object.fromEntries([
  "mdk_native_current_profile", "mdk_wasm_compiles", "identity_proof_v2",
  "key_package_30443", "welcome_1059", "group_event_445", "chat_payload_9",
  "wasm_state_round_trip", "native_wasm_interop", "node_onion_fetch", "native_onion_service",
  "browser_kps_onion_fetch",
].map((name) => [name, { status: "PASS" }]));

assert.equal(decide(pass), "PASS");
assert.equal(decide({ ...pass, mdk_wasm_compiles: { status: "FAIL" } }), "FAIL");
assert.equal(decide({ ...pass, snowflake_transport: { status: "UNSUPPORTED" } }), "PASS");
```

- [ ] **Step 2: Run it and verify failure**

Run: `node --test scripts/run-feasibility.test.mjs`

Expected: FAIL because `decide` is absent.

- [ ] **Step 3: Implement strict aggregation**

Export `mandatoryChecks` exactly as listed at the top of this plan. `decide(records)` returns `PASS` only when every mandatory name exists and equals `PASS`; missing, `FAIL`, `ERROR`, or `UNSUPPORTED` mandatory checks return `FAIL`. Validate the final JSON against `schemas/feasibility-result.schema.json` with `ajv` before writing it atomically.

The final JSON contains:

```json
{
  "schema_version": 1,
  "decision": "PASS",
  "generated_at": "2026-08-31T16:00:00Z",
  "platform": { "os": "linux", "arch": "x64", "rust": "1.97.1", "node": "22.22.2" },
  "pins": { "mdk_rev": "876bdf3c408df0658c158da6a6521745cd0abde5", "tor_js_npm": "0.4.1" },
  "checks": { "mdk_wasm_compiles": { "status": "PASS" }, "browser_kps_onion_fetch": { "status": "PASS" } },
  "next_action": "write the native relay implementation plan"
}
```

The writer supplies the actual UTC generation time, detected OS/architecture/Node version, complete pin set, and all mandatory and optional check records; the concrete values above illustrate schema-valid output rather than hard-coded runtime metadata.

For `FAIL`, `next_action` names the failed design assumption and requests a design revision. The human Markdown report links the JSON, lists timings and WASM size, explains KPS versus optional Snowflake, and contains no secrets or full capability tags.

- [ ] **Step 4: Add CI without pretending live Tor is deterministic**

`.github/workflows/feasibility.yml` runs formatting, Clippy, Rust unit/native-flow tests, WASM compilation/browser unit tests, npm tests, and pin/schema validation on pushes and pull requests. Live onion/KPS probes run only under `workflow_dispatch` on a dedicated Linux runner with a 15-minute job timeout. CI uploads sanitized logs and JSON artifacts even on failure.

`--offline` runs deterministic checks and writes `artifacts/feasibility/offline-results.json` without claiming an overall gate decision. `--live` runs every deterministic and network check and is the only mode allowed to write the final `results.json`.

- [ ] **Step 5: Run the complete local gate**

Run: `npm run feasibility`

Expected: all deterministic and live checks pass and `artifacts/feasibility/results.json` reports `PASS`. If any mandatory check fails, the command exits nonzero after writing the `FAIL` report. For a deterministic-only run, use `npm run feasibility:offline`; it must not write or preserve a stale final decision.

- [ ] **Step 6: Verify repository quality**

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo test --workspace`

Expected: PASS.

Run: `npm test`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 7: Commit and push the gate result**

```bash
git add schemas scripts .github/workflows/feasibility.yml artifacts/feasibility docs/feasibility README.md
git commit -m "docs: record deaddrop feasibility decision"
git push origin main
```

If the decision is `PASS`, stop and create the native relay implementation plan. If it is `FAIL`, stop and return to the design document with the captured evidence; do not begin relay or UI implementation.
