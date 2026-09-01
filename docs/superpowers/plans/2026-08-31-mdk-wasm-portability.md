# MDK Browser-WASM Portability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a reviewed four-commit `Epiphytic/mdk` portability series that makes the real MDK engine and Nostr peeler compile for `wasm32-unknown-unknown` without `tokio_unstable`, then pin Deaddrop's feasibility probe to that exact fork revision.

**Architecture:** Keep one Rust Marmot engine for native and browser clients. Four independent upstream-quality commits add portable clocks, a target-specific cancellable deadline, WASM-local non-`Send` async futures, and explicit OpenMLS/randomness WASM features; Deaddrop then consumes the exact reviewed fork SHA and records the corrected compile result. Browser runtime and serializable storage acceptance continue in Tasks 3-4 of the existing feasibility plan and remain required before claiming browser support.

**Tech Stack:** Rust 1.97.1, Cargo resolver 3, MDK at upstream base `876bdf3c408df0658c158da6a6521745cd0abde5`, OpenMLS at `59e7d3b27a7e95237879dd5478de1fd90eff7ada`, `web-time` 1.1, `gloo-timers` 0.3, `async-trait` 0.1, `wasm32-unknown-unknown`, Homebrew LLVM on macOS, GitHub CLI.

**Spec:** `docs/superpowers/specs/2026-08-31-mdk-wasm-portability-design.md`

## Global Constraints

- Create `Epiphytic/mdk` as a GitHub fork of `marmot-protocol/mdk`; preserve MDK's MIT license and notices.
- Begin the integration branch exactly at `876bdf3c408df0658c158da6a6521745cd0abde5` and preserve that SHA as `mdk_upstream_base_rev`.
- The integration branch carries exactly four ordered implementation commits: portable time, portable deadline/Tokio features, target-dependent async `Send`, and WASM feature hygiene.
- Native APIs retain `Send` futures and existing runtime behavior; only `target_arch = "wasm32"` futures become non-`Send`.
- Production WASM builds may not use `--cfg tokio_unstable`, a Tokio runtime, native filesystem APIs, or a clearnet fallback.
- A successful Cargo WASM build is a compile guard only. Do not claim browser support until the existing feasibility plan's real browser engine, storage, signer, peeler, and restart tests pass.
- Use a dedicated external MDK worktree at `/Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability`; do not add worktree bookkeeping to the fork's patch series.
- Run targeted tests after every commit and `just fast-ci` plus the full WASM compile guard before pushing the series.

## File Structure

```text
Epiphytic/mdk
├── Cargo.toml                                  # portable workspace dependency/features
├── Cargo.lock                                  # exact resolved dependency graph
├── crates/cgka-engine/Cargo.toml                # web-time, native Tokio, WASM timer/features
├── crates/cgka-engine/src/deadline.rs           # target-specific cancellable timeout
├── crates/cgka-engine/src/convergence_clock.rs  # portable monotonic/wall clock
├── crates/cgka-engine/src/engine.rs             # portable wall clock + WASM async impl
├── crates/cgka-engine/src/identity.rs           # portable identity timestamp
├── crates/cgka-engine/src/message_processor/
│   ├── mod.rs                                  # portable timing + deadline call
│   └── store.rs                                # WASM test peeler async attribute
├── crates/cgka-engine/src/openmls_projection.rs # WASM test peeler async attribute
├── crates/cgka-engine/tests/async_send.rs        # native future-Send compile assertions
├── crates/traits/src/engine.rs                  # CgkaEngine target-dependent async trait
├── crates/traits/src/peeler.rs                  # TransportPeeler target-dependent async trait
├── crates/traits/src/transport_adapter.rs       # TransportAdapter target-dependent async trait
├── crates/transport-nostr-peeler/Cargo.toml      # web-time dependency
├── crates/transport-nostr-peeler/src/event.rs    # portable event timestamp
├── crates/transport-nostr-peeler/src/peeler.rs   # portable timestamp + WASM async impl
├── crates/transport-nostr-adapter/src/lib.rs     # matching adapter WASM async impl
└── crates/marmot-forensics/
    ├── Cargo.toml                               # web-time dependency
    └── src/audit.rs                             # portable audit timestamp

Epiphytic/deaddrop
├── upstream-pins.toml                           # upstream base + exact fork provenance
├── scripts/validate-pins.mjs                    # fork/base/full-SHA validation
├── scripts/build-marmot-wasm.sh                 # clears both Cargo Rust flag channels; no-tokio_unstable guard
├── crates/marmot-wasm-probe/Cargo.toml           # single fork revision, no feature workaround
└── artifacts/feasibility/mdk-build.json          # corrected PASS/FAIL evidence
```

---

### Task 1: Fork provenance and isolated integration branch

**Files:**
- External state: GitHub repository `Epiphytic/mdk`
- Create worktree: `/Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability`
- No tracked source changes

**Interfaces:**
- Consumes: upstream repository and exact base SHA.
- Produces: `origin = Epiphytic/mdk`, `upstream = marmot-protocol/mdk`, and branch `deaddrop/wasm-portability` rooted at the approved base.

- [ ] **Step 1: Verify the upstream base and fork state**

Run:

```bash
gh repo view marmot-protocol/mdk --json nameWithOwner,url
gh repo view Epiphytic/mdk --json nameWithOwner,url,isFork,parent 2>/dev/null || true
git -C /Users/newuser/.cargo/git/checkouts/mdk-7d5a3a2420b194f5/876bdf3 rev-parse HEAD
```

Expected: the cached checkout prints exactly `876bdf3c408df0658c158da6a6521745cd0abde5`; an existing fork, if present, names `marmot-protocol/mdk` as parent.

- [ ] **Step 2: Create or reuse the fork and clone it**

If the fork is absent, run:

```bash
gh repo fork marmot-protocol/mdk --org Epiphytic --clone=false
```

Clone only if `/Users/newuser/repos/Epiphytic/mdk/.git` is absent:

```bash
git clone https://github.com/Epiphytic/mdk.git /Users/newuser/repos/Epiphytic/mdk
git -C /Users/newuser/repos/Epiphytic/mdk remote add upstream https://github.com/marmot-protocol/mdk.git
```

If `upstream` already exists, verify its URL instead of replacing it. Fetch both remotes without pruning or deleting refs.

- [ ] **Step 3: Create the external worktree from the exact base**

Run:

```bash
mkdir -p /Users/newuser/repos/Epiphytic/mdk-worktrees
git -C /Users/newuser/repos/Epiphytic/mdk worktree add -b deaddrop/wasm-portability /Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability 876bdf3c408df0658c158da6a6521745cd0abde5
```

Expected: `git merge-base --is-ancestor 876bdf3c... HEAD` succeeds and `git rev-list --count 876bdf3c...HEAD` prints `0`.

- [ ] **Step 4: Run baseline native tests**

Run:

```bash
cargo test -p cgka-traits -p cgka-engine -p transport-nostr-peeler -p marmot-forensics
```

Expected: PASS. Record any pre-existing failure verbatim before changing source; do not hide it in the portability commits.

---

### Task 2: Patch A — portable time primitives

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/cgka-engine/Cargo.toml`
- Modify: `crates/cgka-engine/src/convergence_clock.rs`
- Modify: `crates/cgka-engine/src/engine.rs`
- Modify: `crates/cgka-engine/src/identity.rs`
- Modify: `crates/cgka-engine/src/message_processor/mod.rs`
- Modify: `crates/transport-nostr-peeler/Cargo.toml`
- Modify: `crates/transport-nostr-peeler/src/event.rs`
- Modify: `crates/transport-nostr-peeler/src/peeler.rs`
- Modify: `crates/marmot-forensics/Cargo.toml`
- Modify: `crates/marmot-forensics/src/audit.rs`

**Interfaces:**
- Consumes: `web_time::{Instant, SystemTime, UNIX_EPOCH}`.
- Produces: browser-safe clock reads with native-equivalent semantics and no public API change.

- [ ] **Step 1: Run the failing source portability check**

Run this exact literal audit over only browser-reachable hot paths:

```bash
rg -n 'use std::time::\{.*(Instant|SystemTime|UNIX_EPOCH)|std::time::(Instant|SystemTime|UNIX_EPOCH)' \
  crates/cgka-engine/src/convergence_clock.rs \
  crates/cgka-engine/src/engine.rs \
  crates/cgka-engine/src/identity.rs \
  crates/cgka-engine/src/message_processor/mod.rs \
  crates/transport-nostr-peeler/src/event.rs \
  crates/transport-nostr-peeler/src/peeler.rs \
  crates/marmot-forensics/src/audit.rs
```

Expected: FAIL the portability condition by printing every unsupported clock occurrence.

- [ ] **Step 2: Add the dependency without changing native behavior**

Add to `[workspace.dependencies]`:

```toml
web-time = "1.1"
```

Add `web-time.workspace = true` to the normal dependencies of `cgka-engine`, `transport-nostr-peeler`, and `marmot-forensics`.

- [ ] **Step 3: Replace only clock types, leaving `Duration` native/core**

Use these imports:

```rust
use web_time::{Instant, SystemTime, UNIX_EPOCH};
```

Where only wall time is used, import `SystemTime` and `UNIX_EPOCH`; where only monotonic time is used, import `Instant`. Replace fully qualified `std::time::SystemTime` and `std::time::UNIX_EPOCH` in `identity.rs` and `peeler.rs`. Do not change timestamp units, error handling, saturation, or public signatures.

- [ ] **Step 4: Verify the literal audit and native behavior**

Re-run Step 1. Expected: no matches and exit code 1 from `rg`.

Run:

```bash
cargo fmt --all --check
cargo test -p cgka-engine -p transport-nostr-peeler -p marmot-forensics
```

Expected: PASS.

- [ ] **Step 5: Commit Patch A**

```bash
git add Cargo.toml Cargo.lock crates/cgka-engine crates/transport-nostr-peeler crates/marmot-forensics
git commit -m "fix: use browser-safe time primitives"
```

---

### Task 3: Patch B — target-appropriate Tokio and cancellable deadline

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/cgka-engine/Cargo.toml`
- Create: `crates/cgka-engine/src/deadline.rs`
- Modify: `crates/cgka-engine/src/lib.rs`
- Modify: `crates/cgka-engine/src/message_processor/mod.rs`
- Modify: `crates/transport-nostr-peeler/Cargo.toml`
- Modify: `crates/marmot-c/Cargo.toml`
- Modify: `crates/cli/Cargo.toml`
- Modify: `crates/transport-quic-broker/Cargo.toml`
- Test: `crates/cgka-engine/tests/deferred_peel_lifecycle.rs`

**Interfaces:**
- Consumes: `deadline::timeout(Duration, Future)` and the existing `ForegroundPeelBudget::remaining()`.
- Produces: `pub(crate) async fn timeout<F>(duration: Duration, future: F) -> Result<F::Output, DeadlineElapsed>` with cancellation on both native and browser targets.

- [ ] **Step 1: Add a failing deadline contract test**

In `deadline.rs`, start with the native test module and a declared but unimplemented `timeout` function so the first run fails:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeadlineElapsed;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancels_a_pending_future() {
        let result = timeout(Duration::from_millis(1), std::future::pending::<()>()).await;
        assert_eq!(result, Err(DeadlineElapsed));
    }

    #[tokio::test]
    async fn returns_a_ready_value() {
        assert_eq!(timeout(Duration::from_secs(1), async { 7 }).await, Ok(7));
    }
}
```

Add `mod deadline;` in `lib.rs`, run `cargo test -p cgka-engine deadline::tests`, and expect FAIL because `timeout` is absent.

- [ ] **Step 2: Implement native and WASM deadline backends**

Implement this signature:

```rust
pub(crate) async fn timeout<F>(duration: Duration, future: F) -> Result<F::Output, DeadlineElapsed>
where
    F: Future,
```

For `not(target_arch = "wasm32")`, delegate to `tokio::time::timeout` and map elapsed to `DeadlineElapsed`. For `target_arch = "wasm32"`, fuse and pin `future` with a `gloo_timers::future::TimeoutFuture`; use `futures::select_biased!` with the operation branch first, returning `Ok(output)` when the operation wins and `Err(DeadlineElapsed)` when the timer wins. Operation-first bias matches Tokio when both branches are ready on the same poll.

Convert the duration to integer milliseconds without expiring a nonzero budget early: round any nonzero fractional millisecond up with a saturating addition, then cap at `i32::MAX` milliseconds before converting to the browser timer's `u32` argument. The signed cap is required because the browser timer implementation casts its delay to `i32`.

Declare dependencies as:

```toml
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
tokio = { workspace = true, features = ["time"] }

[target.'cfg(target_arch = "wasm32")'.dependencies]
gloo-timers = { version = "0.3", features = ["futures"] }
```

Add `futures.workspace = true` to `cgka-engine`; the version remains controlled by the existing workspace dependency.

- [ ] **Step 3: Preserve the foreground cancellation contract**

Replace only this call:

```rust
tokio::time::timeout(remaining, reingest).await
```

with:

```rust
crate::deadline::timeout(remaining, reingest).await
```

Keep the timeout branch's `timed_out = true; break;` behavior unchanged. This is required by `foreground_send_budget_queues_47_and_64_row_notify_gated_backlogs`; a between-row-only deadline would hang on its deliberately pending peeler.

- [ ] **Step 4: Make multithread runtime features local to runtime owners**

Change the workspace Tokio declaration to:

```toml
tokio = { version = "1", features = ["sync", "macros", "rt", "time"] }
```

Add `"rt-multi-thread"` to the existing Tokio feature lists in `crates/marmot-c/Cargo.toml`, `crates/cli/Cargo.toml`, and `crates/transport-quic-broker/Cargo.toml`. Other known multithread owners already declare it explicitly; verify with:

For `cgka-engine` and `transport-nostr-peeler` tests, keep only `"macros"` on the unconditional Tokio dev-dependency and add `"rt-multi-thread"` under `[target.'cfg(not(target_arch = "wasm32"))'.dev-dependencies]`. This preserves native test runtimes without enabling the multithread runtime while resolving WASM test/dev targets.

```bash
rg -n 'new_multi_thread|#\[tokio::main|flavor = "multi_thread"' crates integrations --glob '*.rs'
rg -n 'rt-multi-thread' . --glob 'Cargo.toml'
```

- [ ] **Step 5: Run targeted behavioral tests**

Run:

```bash
cargo test -p cgka-engine deadline::tests
cargo test -p cgka-engine --test deferred_peel_lifecycle cancelled_sweep_keeps_untried_rows_eligible_and_reuses_enumeration
cargo test -p cgka-engine --test deferred_peel_lifecycle foreground_send_budget_queues_47_and_64_row_notify_gated_backlogs
cargo check -p marmot-c -p wn-cli -p transport-quic-broker
```

Expected: PASS; the notify-gated foreground test must terminate and report budget exhaustion. The deadline unit tests must also cover operation-first ready ties, cancellation when the timer wins, zero/exact/fractional millisecond conversion, nonzero submillisecond ceiling, and the `i32::MAX` cap.

- [ ] **Step 6: Commit Patch B**

```bash
git add Cargo.toml Cargo.lock crates/cgka-engine crates/transport-nostr-peeler/Cargo.toml crates/marmot-c/Cargo.toml crates/cli/Cargo.toml crates/transport-quic-broker/Cargo.toml
git commit -m "fix: make engine deadlines portable across runtimes"
```

---

### Task 4: Patch C — target-dependent async future `Send`

**Files:**
- Modify: `crates/traits/src/engine.rs`
- Modify: `crates/traits/src/peeler.rs`
- Modify: `crates/traits/src/transport_adapter.rs`
- Modify: `crates/cgka-engine/src/engine.rs`
- Modify: `crates/cgka-engine/src/openmls_projection.rs`
- Modify: `crates/cgka-engine/src/message_processor/store.rs`
- Modify: `crates/transport-nostr-peeler/src/peeler.rs`
- Modify: `crates/transport-nostr-adapter/src/lib.rs`
- Create: `crates/traits/tests/async_send.rs`

**Interfaces:**
- Consumes: `async_trait` and `async_trait(?Send)`.
- Produces: native `Pin<Box<dyn Future + Send>>` and WASM-local `Pin<Box<dyn Future>>` from the same public traits while retaining `Send + Sync` trait objects.

- [ ] **Step 1: Add native compile-time future assertions**

Create `crates/traits/tests/async_send.rs`:

```rust
#![cfg(not(target_arch = "wasm32"))]

use cgka_traits::engine::CgkaEngine;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::TransportMessage;
use cgka_traits::transport_adapter::TransportAdapter;

fn assert_send<T: Send>(_: T) {}

#[allow(dead_code)]
fn engine_ingest_future_is_send(engine: &mut dyn CgkaEngine, msg: TransportMessage) {
    assert_send(engine.ingest(msg));
}

#[allow(dead_code)]
fn peeler_welcome_future_is_send(peeler: &dyn TransportPeeler, msg: &TransportMessage) {
    assert_send(peeler.peel_welcome(msg));
}

#[allow(dead_code)]
fn adapter_receive_future_is_send(adapter: &dyn TransportAdapter) {
    assert_send(adapter.receive());
}
```

Run `cargo test -p cgka-traits --test async_send`; expected PASS on the unmodified native contract. This is a regression guard, not the WASM red test.

- [ ] **Step 2: Capture the failing WASM async boundary**

Using Deaddrop's existing pinned consumer and WebAssembly-capable compiler, run its current WASM probe against the MDK worktree without editing either repository:

```bash
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
  cargo --manifest-path /Users/newuser/repos/liamhelmer/deaddrop/.worktrees/feasibility-gate/Cargo.toml \
  --config 'patch."https://github.com/marmot-protocol/mdk.git".cgka-engine.path="/Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability/crates/cgka-engine"' \
  --config 'patch."https://github.com/marmot-protocol/mdk.git".cgka-traits.path="/Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability/crates/traits"' \
  --config 'patch."https://github.com/marmot-protocol/mdk.git".transport-nostr-peeler.path="/Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability/crates/transport-nostr-peeler"' \
  build --locked -p marmot-wasm-probe --target wasm32-unknown-unknown
```

Expected: FAIL with the four `transport-nostr-peeler` errors reporting that Nostr signer futures are not `Send` on `wasm32`. The consumer's already-recorded direct OpenMLS/getrandom features isolate this boundary; the `--config` values are process-local and are not committed.

- [ ] **Step 3: Apply matching target attributes**

Replace each relevant plain `#[async_trait]` with:

```rust
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
```

Apply it to `CgkaEngine`, `TransportPeeler`, `TransportAdapter`, `CgkaEngine for Engine<S>`, `TransportPeeler for NostrMlsPeeler`, `TransportAdapter for NostrTransportAdapter`, and the two in-crate peeler implementations compiled by WASM tests. Trait and implementation attributes must match. Do not remove `Send + Sync` supertraits.

- [ ] **Step 4: Verify native contracts and implementations**

Run:

```bash
cargo test -p cgka-traits --test async_send
cargo test -p cgka-engine -p transport-nostr-peeler -p transport-nostr-adapter
```

Expected: PASS.

- [ ] **Step 5: Commit Patch C**

```bash
git add crates/traits crates/cgka-engine/src/engine.rs crates/cgka-engine/src/openmls_projection.rs crates/cgka-engine/src/message_processor/store.rs crates/transport-nostr-peeler/src/peeler.rs crates/transport-nostr-adapter/src/lib.rs
git commit -m "fix: allow local async futures on wasm"
```

---

### Task 5: Patch D — explicit WASM feature hygiene and full compile guard

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/cgka-engine/Cargo.toml`

**Interfaces:**
- Consumes: the single workspace OpenMLS revision and `getrandom` 0.4.3.
- Produces: a full engine/traits/peeler WASM build with no consumer feature-unification workaround.

- [ ] **Step 1: Run the failing full build without workarounds**

Run with a WebAssembly-capable compiler after clearing both Cargo Rust flag channels:

```bash
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
  cargo build --locked --target wasm32-unknown-unknown \
  -p cgka-engine -p cgka-traits -p transport-nostr-peeler
```

Expected: FAIL before this patch because OpenMLS's `js` feature and explicit randomness backend are absent.

- [ ] **Step 2: Declare exact target features inside MDK**

Set the workspace randomness version to:

```toml
getrandom = "0.4.3"
```

Add to `crates/cgka-engine/Cargo.toml`:

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { workspace = true, features = ["wasm_js"] }
openmls = { workspace = true, features = ["js"] }
```

Keep the normal `openmls.workspace = true` dependency and its `extensions-draft` workspace feature so native resolution is unchanged. Do not add a second OpenMLS source or revision.

- [ ] **Step 3: Prove target-specific feature resolution**

Run:

```bash
cargo tree -e features -i openmls -p cgka-engine
cargo tree --target wasm32-unknown-unknown -e features -i openmls -p cgka-engine
```

Expected: native includes the existing default/`extensions-draft` features and not `js`; WASM additionally includes `js`.

- [ ] **Step 4: Run the full compile and native regression guards**

Run:

```bash
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
  cargo build --locked --target wasm32-unknown-unknown \
  -p cgka-engine -p cgka-traits -p transport-nostr-peeler
cargo test -p cgka-traits -p cgka-engine -p transport-nostr-peeler -p transport-nostr-adapter -p marmot-forensics
cargo fmt --all --check
```

Expected: PASS. Inspect the verbose Cargo command or environment log and confirm `--cfg tokio_unstable` is absent.

- [ ] **Step 5: Commit Patch D**

```bash
git add Cargo.toml Cargo.lock crates/cgka-engine/Cargo.toml
git commit -m "fix: declare wasm crypto features in mdk"
```

---

### Task 6: Review, publish the fork series, and pin Deaddrop

**Files:**
- Modify in Deaddrop: `upstream-pins.toml`
- Modify in Deaddrop: `scripts/validate-pins.mjs`
- Modify in Deaddrop: `scripts/build-marmot-wasm.sh`
- Modify in Deaddrop: `crates/marmot-wasm-probe/Cargo.toml`
- Modify in Deaddrop: `Cargo.lock`
- Modify in Deaddrop: `artifacts/feasibility/mdk-build.json`
- Modify in Deaddrop: `.superpowers/sdd/2026-08-31-deaddrop-feasibility-gate/progress.md`
- External state: fork branch and four upstream PRs

**Interfaces:**
- Consumes: reviewed four-commit MDK integration branch.
- Produces: immutable Deaddrop provenance fields `mdk_upstream_repo`, `mdk_upstream_base_rev`, `mdk_fork_repo`, and `mdk_fork_rev`, plus a reproducible compile artifact.

- [ ] **Step 1: Verify the four-commit shape and full gates**

Run in MDK:

```bash
git rev-list --count 876bdf3c408df0658c158da6a6521745cd0abde5..HEAD
git log --reverse --format='%H %s' 876bdf3c408df0658c158da6a6521745cd0abde5..HEAD
just fast-ci
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
  cargo build --locked --target wasm32-unknown-unknown \
  -p cgka-engine -p cgka-traits -p transport-nostr-peeler
```

Expected: exactly four commits in A/B/C/D order and every gate passes.

- [ ] **Step 2: Push the integration branch after review**

```bash
git push -u origin deaddrop/wasm-portability
```

Capture `git rev-parse HEAD` as the 40-character `mdk_fork_rev`.

- [ ] **Step 3: Add immutable fork provenance to Deaddrop**

Replace the old MDK fields with:

```toml
mdk_upstream_repo = "https://github.com/marmot-protocol/mdk.git"
mdk_upstream_base_rev = "876bdf3c408df0658c158da6a6521745cd0abde5"
mdk_fork_repo = "https://github.com/Epiphytic/mdk.git"
```

Set `mdk_fork_rev` to the exact lowercase 40-character stdout from `git -C /Users/newuser/repos/Epiphytic/mdk-worktrees/deaddrop-wasm-portability rev-parse HEAD`; never write a symbolic branch, sentinel, or abbreviated SHA.

Update `validate-pins.mjs` to require all four fields, reject sentinel text, and run:

```bash
git merge-base --is-ancestor "$mdk_upstream_base_rev" "$mdk_fork_rev"
```

against a fetched `Epiphytic/mdk` checkout. The validator must also reject multiple OpenMLS source revisions in `cargo metadata`.

- [ ] **Step 4: Remove the consumer compile trick**

Point all three probe dependencies (`cgka-engine`, `cgka-traits`, `transport-nostr-peeler`) at `https://github.com/Epiphytic/mdk.git` and the exact `mdk_fork_rev`. Remove the temporary direct OpenMLS dependency, direct getrandom feature-unification dependency, and any `tokio_unstable` flags. The build wrapper must unset both `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` before invoking Cargo so callers cannot reintroduce unsupported cfgs through either channel. Keep automatic Homebrew LLVM selection on macOS.

- [ ] **Step 5: Re-run and record the corrected feasibility check**

Run in Deaddrop:

```bash
node scripts/validate-pins.mjs
cargo test -p marmot-wasm-probe --test native_surface
bash scripts/build-marmot-wasm.sh
```

Write `artifacts/feasibility/mdk-build.json` with `status: "PASS"`, the exact fork/base SHAs, target, compiler path/version, command, and empty sanitized stderr. State explicitly that this is a compile guard, not browser-runtime acceptance. Update the SDD ledger: Task 2 is remediated and Tasks 3-4 of `2026-08-31-deaddrop-feasibility-gate.md` are now unblocked.

- [ ] **Step 6: Commit Deaddrop provenance and evidence**

```bash
git add upstream-pins.toml scripts/validate-pins.mjs scripts/build-marmot-wasm.sh crates/marmot-wasm-probe/Cargo.toml Cargo.lock artifacts/feasibility/mdk-build.json .superpowers/sdd/2026-08-31-deaddrop-feasibility-gate/progress.md
git commit -m "build: pin browser-portable mdk fork"
```

- [ ] **Step 7: Prepare one upstream branch and PR per patch**

From the fork clone, create four branches rooted at the approved upstream base and cherry-pick exactly one reviewed patch commit onto each:

```text
upstream/wasm-time        -> Patch A only
upstream/wasm-deadline    -> Patch B only
upstream/wasm-async-send  -> Patch C only
upstream/wasm-features    -> Patch D only
```

Run the patch-specific isolated checks before pushing: Patch A's source audit and native crate tests; Patch B's deadline/deferred-peel/runtime-owner tests; Patch C's native `Send` assertion and three crate tests; Patch D's native tests plus native/WASM `cargo tree` feature comparison. The full WASM build is expected to require all four patches and therefore runs only on the integration branch. Push each isolated branch to `Epiphytic/mdk`, and open a PR to `marmot-protocol/mdk:main`. Each PR body must include the failing pre-patch evidence, exact verification commands, native-semantics statement, known independent blockers not solved by that PR, and a link to the corresponding Deaddrop design section. If a patch is not independently cherry-pickable, fix the integration series so it is independent; do not submit a cumulative four-patch PR as a substitute.

---

## Completion Boundary

This plan is complete when the reviewed fork is pushed, Deaddrop is pinned to its full SHA, and the native plus full WASM compile guards pass without `tokio_unstable`. That result unblocks—but does not replace—the existing feasibility plan's serializable `WasmStorage` and real headless-browser two-party/restart tests. Those runtime tests are the next execution tasks and remain the threshold for saying MDK works in a browser.
