# MDK Browser-WASM Portability Design

**Status:** Approved in conversation; awaiting written-spec review

**Date:** 2026-08-31

**Repositories:** `Epiphytic/deaddrop`, proposed `Epiphytic/mdk` fork of `marmot-protocol/mdk`

**License:** Preserve MDK's MIT license and notices; Deaddrop remains Apache-2.0

## 1. Purpose

Deaddrop will retain a single Rust Marmot engine across native and browser clients. The pinned MDK revision `876bdf3c408df0658c158da6a6521745cd0abde5` can be forced to compile without source changes, but that build is not browser-correct: it retains unsupported wall-clock and Tokio timer paths and the Nostr peeler cannot compile with WebAssembly's non-`Send` signer futures.

Deaddrop will therefore maintain a small, upstream-oriented MDK fork until equivalent changes merge upstream. It will not switch the browser client to `marmot-ts` merely to avoid this patch. Each fork change is an independent, rebaseable commit with its own tests and upstream pull request.

## 2. Corrected Feasibility Finding

The feasibility record distinguishes three states:

1. **Native linkage:** passes at the pinned upstream revision.
2. **Compile-only WebAssembly guard:** the engine without `transport-nostr-peeler` builds for `wasm32-unknown-unknown` when the consumer enables `getrandom 0.4.3/wasm_js`, OpenMLS `js`, a WebAssembly-capable C compiler, and `--cfg tokio_unstable`.
3. **Browser-capable Marmot engine:** fails at the upstream revision. The full peeler requires non-`Send` WebAssembly futures, and engine/peeler hot paths use time facilities that panic on `wasm32-unknown-unknown`.

The compile-only configuration remains useful as a regression guard, but it is never reported as browser support. Task 2 remains a feasibility `FAIL` with a bounded remediation, not an unexplained blocker.

## 3. Fork and Provenance Policy

Create `Epiphytic/mdk` as a GitHub fork of `marmot-protocol/mdk`. The implementation branch begins exactly at upstream revision `876bdf3c408df0658c158da6a6521745cd0abde5`.

The fork carries four ordered commits:

1. portable time primitives;
2. target-appropriate Tokio and deferred-peel timing;
3. target-dependent async future `Send` semantics;
4. explicit WebAssembly feature hygiene.

After the patch series exists, `upstream-pins.toml` will replace the upstream MDK dependency with the exact fork commit and preserve its provenance. `mdk_upstream_repo` remains `https://github.com/marmot-protocol/mdk.git`, `mdk_upstream_base_rev` remains `876bdf3c408df0658c158da6a6521745cd0abde5`, and `mdk_fork_repo` is `https://github.com/Epiphytic/mdk.git`. `mdk_fork_rev` is populated with the real 40-character lowercase hexadecimal SHA produced by the reviewed patch series; the pin validator rejects descriptions and sentinel values.

All Deaddrop MDK dependencies use the single pinned fork revision. CI rejects a fork revision that is not descended from `mdk_upstream_base_rev` or a dependency set that resolves two incompatible OpenMLS revisions.

## 4. Patch A: Portable Time Primitives

Add `web-time = "1.1"` to the MDK workspace and to the crates that read wall-clock or monotonic time. Replace `std::time::{Instant, SystemTime, UNIX_EPOCH}` with `web_time` equivalents in:

- `crates/cgka-engine/src/convergence_clock.rs`;
- `crates/cgka-engine/src/engine.rs`;
- `crates/cgka-engine/src/identity.rs`;
- `crates/cgka-engine/src/message_processor/mod.rs`;
- `crates/transport-nostr-peeler/src/event.rs`;
- `crates/transport-nostr-peeler/src/peeler.rs`;
- `crates/marmot-forensics/src/audit.rs`.

`Duration` remains from `core` or `std`. On native targets, `web-time` re-exports native time behavior; native event timestamps and convergence behavior must remain unchanged. Browser tests must prove `EngineBuilder::new()`, identity-proof creation, event construction, and ingest no longer panic on time access.

## 5. Patch B: Tokio and Deferred-Peel Timing

Remove `rt-multi-thread` from the MDK workspace-wide Tokio feature set. Add it explicitly only to native binaries, agents, brokers, CLIs, and native test targets that construct a multithread runtime. Library crates used by the browser may depend only on Tokio features supported by WebAssembly.

Remove the browser engine's dependency on `tokio::time::timeout` in the deferred-peel reingest sweep. The first implementation uses the already-injected convergence clock to check the sweep deadline between bounded rows. Existing native lifecycle tests must demonstrate that the total sweep budget and progress guarantees remain intact. If those tests prove mid-row cancellation is a required contract, replace the between-row check with a small injected deadline abstraction: native uses Tokio timeout and WebAssembly uses a browser timer future. The implementation may not retain `--cfg tokio_unstable` as production support.

After this patch, downstream WebAssembly consumers compile without `tokio_unstable`. Native multithreaded applications retain their existing runtime behavior.

## 6. Patch C: Target-Dependent Async `Send`

MDK traits and implementations that await Nostr signer futures use:

```rust
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
```

Apply matching attributes to the trait and every implementation compiled for the target, including:

- `cgka_traits::TransportPeeler`;
- `cgka_traits::CgkaEngine`;
- `cgka_traits::TransportAdapter`;
- `CgkaEngine for Engine<S>`;
- `TransportPeeler for NostrMlsPeeler`;
- WebAssembly-compiled test implementations.

Native returned futures remain `Send`; WebAssembly returned futures do not. Trait objects remain `Send + Sync` where currently required. Add a native compile-time assertion that an engine ingest future remains `Send`, and add browser coverage that exercises both NIP-59 welcome peeling and group-message peeling through the real Nostr signer path.

## 7. Patch D: WebAssembly Feature Hygiene

MDK declares its own target-specific WebAssembly requirements rather than depending on consumer feature unification:

- enable OpenMLS `js` for `target_arch = "wasm32"` at the same pinned OpenMLS revision;
- enable the applicable `getrandom/wasm_js` backend explicitly;
- keep native feature resolution unchanged;
- remove misleading or unused randomness declarations where the resolved graph demonstrates they are not consumed.

This patch eliminates Deaddrop's temporary direct OpenMLS dependency and ensures consumers cannot accidentally build a compile-only configuration missing WebAssembly randomness or time support.

## 8. Browser Runtime and Storage Boundary

The browser engine runs in a dedicated Web Worker. This provides the execution boundary expected by the synchronous MDK storage traits and keeps cryptographic work off the UI thread.

The feasibility adapter may continue using deterministic synchronous in-memory state with an explicit versioned export/import envelope. Production persistence will use synchronous OPFS access from the Worker, directly or through SQLite-WASM over OPFS. IndexedDB may store exported vault envelopes and UI metadata, but it is not presented as a synchronous implementation of MDK's `StorageProvider` traits.

No browser path uses system Tor, a clearnet fallback, native filesystem APIs, or a Tokio runtime.

## 9. Testing and Acceptance

Each fork commit follows test-first development and passes the existing native workspace suite. The patch series is accepted only when all of these pass:

1. `cargo test --workspace` on a supported native host.
2. `cargo build --target wasm32-unknown-unknown -p cgka-engine -p cgka-traits -p transport-nostr-peeler` without `tokio_unstable`.
3. Browser `wasm-bindgen-test` coverage in headless Chromium and Firefox for:
   - `EngineBuilder::new()` without a panic;
   - identity proof and KeyPackage creation;
   - two-party group creation;
   - kind-1059 Welcome wrap and peel;
   - kind-445 group wrap, peel, and ingest;
   - state export, Worker restart, import, and reply.
4. Native static assertions preserve `Send` futures for engine and transport APIs.
5. Deaddrop native-to-browser fixtures preserve exact kind `30443`, `1059`, `445`, and `9` wire events and signatures.

A WebAssembly build alone is insufficient. Browser execution of real engine, peeler, time, randomness, storage, and signer paths is the support claim.

## 10. Upstreaming and Fork Retirement

Open one upstream PR per patch so maintainers can review and merge independent concerns. The Deaddrop fork remains pinned by full SHA while any patch is outstanding. As patches land, rebase the remaining series and update both base and fork pins through reviewed commits.

Retire the fork when an upstream revision passes the same native, WebAssembly, browser-runtime, and Deaddrop wire-interoperability tests. Do not retire it merely because upstream compiles for WebAssembly.

## 11. Risks

- Replacing mid-await Tokio cancellation with between-row deadline checks may alter deferred-peel scheduling. Existing lifecycle tests are the deciding contract; use an injected deadline abstraction if necessary.
- `async_trait(?Send)` must be applied consistently across traits and target-compiled implementations or it will create opaque type errors.
- Browser timers and `web-time::Instant` require a Worker environment with a performance clock.
- The synchronous storage surface makes the Web Worker and OPFS boundary architectural, not optional.
- Maintaining a fork creates rebase work, but the measured patch is smaller and safer than maintaining wire conformance across independent Rust and TypeScript Marmot engines.

## 12. Decision

Proceed with the four-commit `Epiphytic/mdk` fork, upstream each commit immediately, and resume the Deaddrop feasibility gate against the pinned fork. Keep the no-fork build only as a compile regression guard. Do not adopt `marmot-ts` for the browser client.
