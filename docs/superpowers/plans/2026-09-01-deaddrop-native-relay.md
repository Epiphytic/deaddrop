# Deaddrop Native Relay Core Implementation Plan

> Execute this plan task-by-task with test-driven development and a review checkpoint after each commit.

**Goal:** Build the first production Deaddrop application slice: a strict Nostr relay core with NIP-42 authentication, non-enumerable inbox/group authorization, SQLite persistence and retention, and an explicit loopback-only debug WebSocket server.

**Architecture:** `protocol-core` converts untrusted Nostr events and filters into closed, typed authorization decisions. `relay-core` owns the socket-independent NIP-01/NIP-42 session state machine and accepts only typed storage operations. `relay-sqlite` implements those operations on a dedicated native worker. `server` owns CLI parsing, bounded WebSockets, and loopback debug listening. Both core crates remain WASM-compatible for the later Cloudflare adapter. The proven `onion-probe` remains unchanged until the next plan wraps this relay engine with raw `hypertor::OnionService` streams.

**Pinned stack:** Rust 1.97.1, `nostr` 0.44.8, Tokio, `tokio-tungstenite` 0.28, `rusqlite` 0.39, Serde, and the repository's pinned MDK profile. Repository-wide license: Apache-2.0.

## Scope and invariants

In scope:

- strict Nostr client-message parsing and bounded wire limits;
- NIP-42 challenge/authentication for every read and write;
- public kind `0` and kind `30443` discovery;
- authenticated kind `1059` inbox reads by exact `p` recipient;
- kind `445` reads by exact random `h` capability;
- signature, author-binding, route-shape, replacement, expiration, and quota enforcement;
- SQLite persistence and loopback-only WebSocket debug mode.

Out of scope for this plan:

- embedded Arti/onion listener and static browser assets;
- client vaults, CLI client commands, browser UI, KPS deployment, MCP, Cloudflare, and multi-user UX;
- MLS plaintext inspection or relay-side MLS membership tracking.

Security invariants:

- Raw `Filter` values never cross the storage boundary. Storage receives only a closed `AuthorizedQuery`.
- Raw events never reach persistence. Storage receives only a signature-checked `ValidatedEvent`.
- A `REQ` containing any unauthorized OR-filter is rejected in full.
- Kind `1059` and `445` outer authors are not bound to the authenticated key; kind `0` and `30443` authors are.
- Every historical and live-delivery path applies the same authorization decision.
- Production relay mode does not open a clearnet listener. Debug mode requires an explicit loopback address unless a separately named unsafe override is present.

---

### Task 1: Production crate boundaries and strict wire parser

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/protocol-core/Cargo.toml`
- Create: `crates/protocol-core/src/lib.rs`
- Create: `crates/protocol-core/src/kinds.rs`
- Create: `crates/relay-core/Cargo.toml`
- Create: `crates/relay-core/src/lib.rs`
- Create: `crates/relay-core/src/wire.rs`
- Create: `crates/relay-core/tests/wire.rs`

**Interfaces:**

```rust
pub const KIND_KEY_PACKAGE: u16 = 30_443;

pub struct WireLimits {
    pub max_frame_bytes: usize,
    pub max_subscription_id_bytes: usize,
    pub max_filters_per_req: usize,
}

pub enum StrictClientMessage {
    Event(nostr::Event),
    Req { subscription_id: nostr::SubscriptionId, filters: Vec<nostr::Filter> },
    Close(nostr::SubscriptionId),
    Auth(nostr::Event),
}

pub fn parse_client_message(raw: &[u8], limits: &WireLimits)
    -> Result<StrictClientMessage, WireError>;
```

- [x] **Step 1: Write failing wire tests**

Test valid `EVENT`, `REQ`, `CLOSE`, and `AUTH` messages plus rejection of non-UTF-8, oversized raw frames, unknown message names, wrong/excess array elements, malformed event/filter objects, empty or oversized subscription IDs, empty/excess filter lists, and unknown top-level filter fields.

- [x] **Step 2: Verify RED**

Run: `cargo test -p deaddrop-relay-core --test wire`

Expected: FAIL because the crates and parser do not exist.

- [x] **Step 3: Implement the minimum strict parser**

Validate raw JSON shape and byte limits before converting with `nostr` types. Do not rely on `ClientMessage::from_json` alone because the pinned parser accepts trailing array elements and permissive filters.

- [x] **Step 4: Verify native and WASM boundaries**

Run:

```bash
cargo test -p deaddrop-relay-core --test wire
cargo build -p deaddrop-protocol-core --target wasm32-unknown-unknown
cargo build -p deaddrop-relay-core --target wasm32-unknown-unknown
```

Expected: PASS without Tokio, Hyper, Hypertor, or SQLite entering either core dependency graph.

- [x] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/protocol-core crates/relay-core
git commit -m "feat: add strict relay protocol boundary"
```

---

### Task 2: Pure read authorization

**Files:**

- Create: `crates/protocol-core/src/filter_policy.rs`
- Create: `crates/protocol-core/src/query.rs`
- Create: `crates/protocol-core/tests/filter_policy.rs`
- Modify: `crates/protocol-core/src/lib.rs`

**Interfaces:**

```rust
pub struct AuthorizedQuery(AuthorizedQueryInner); // inner type and constructor are private

pub fn authorize_filters(
    authenticated_keys: &BTreeSet<nostr::PublicKey>,
    filters: &[nostr::Filter],
) -> Result<Vec<AuthorizedQuery>, PolicyError>;
```

- [ ] **Step 1: Write table and property tests**

Cover public `{0, 30443}` queries, exact authenticated `1059/#p`, exact lowercase 64-hex `445/#h`, optional IDs/authors/time/limit constraints, and rejection of mixed public/private kinds, missing/multiple `p` or `h` values, unknown tags, `search`, prefixes, unsupported kinds, and any unauthorized member of an OR-filter list. Property tests must generate malformed private filters and prove none become an authorized scope.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p deaddrop-protocol-core --test filter_policy`

- [ ] **Step 3: Implement closed typed queries**

Parse exact route tags, retain only safe secondary constraints, and reject ambiguous filters instead of broadening them. Keep constructors and fields private; expose read-only accessors for storage so another crate cannot forge an authorization result.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p deaddrop-protocol-core`

Commit: `feat: authorize relay reads by identity or capability`

---

### Task 3: Write validation, replacement, and retention decisions

**Files:**

- Create: `crates/protocol-core/src/event_policy.rs`
- Create: `crates/protocol-core/src/retention.rs`
- Create: `crates/protocol-core/tests/event_policy.rs`
- Modify: `crates/protocol-core/src/lib.rs`

**Interfaces:**

```rust
pub enum EventClass {
    Metadata,
    KeyPackage { d: String },
    Inbox { recipient: nostr::PublicKey },
    Group { h: [u8; 32] },
}

pub struct ValidatedEvent {
    /* all fields private; read-only accessors only */
}

pub fn validate_write(
    authenticated_keys: &BTreeSet<nostr::PublicKey>,
    received_at: u64,
    event: nostr::Event,
) -> Result<ValidatedEvent, PolicyError>;
```

- [ ] **Step 1: Write failing real-signature tests**

Use distinct authenticated, recipient, and disposable keys. Require valid ID/signature; bind kind `0` and `30443` to an authenticated author; permit valid ephemeral outer authors for `1059` and `445`; require exactly one valid `d`, `p`, or `h` route as appropriate; reject unknown kinds, malformed/duplicate routes, expired-on-arrival events, future-invalid retention, and oversized content.

Cross-test `1059`/`445` route acceptance against pinned `NostrTransportEvent` behavior so relay policy cannot silently diverge from Marmot.

- [ ] **Step 2: Verify RED**

Run: `cargo test -p deaddrop-protocol-core --test event_policy`

- [ ] **Step 3: Implement policy**

Use `Event::verify()`. Default encrypted retention is seven days from trusted `received_at`; requested NIP-40 expiration may shorten it; the server caps storage at 30 days. Do not apply ordinary freshness windows to NIP-59 gift-wrap `created_at`. Seal `ValidatedEvent` construction inside policy code so persistence cannot accept a caller-fabricated validation proof.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p deaddrop-protocol-core`

Commit: `feat: validate deaddrop relay event classes`

---

### Task 4: NIP-42 authentication and socket-independent session engine

**Files:**

- Create: `crates/relay-core/src/auth.rs`
- Create: `crates/relay-core/src/session.rs`
- Create: `crates/relay-core/src/hub.rs`
- Create: `crates/relay-core/src/store.rs`
- Create: `crates/relay-core/tests/auth.rs`
- Create: `crates/relay-core/tests/session.rs`
- Create: `crates/relay-core/tests/hub.rs`
- Modify: `crates/relay-core/src/lib.rs`

**Interfaces:**

```rust
pub trait Clock { fn now_seconds(&self) -> u64; }
pub trait ChallengeSource { fn fill(&mut self, output: &mut [u8]); }

pub struct Session<S, C, R> { /* one connection only */ }
pub struct RelayHub<S> { /* cross-connection subscriptions and bounded fan-out */ }

pub enum SessionOutput {
    Send(nostr::RelayMessage),
    Subscribe(AuthorizedSubscription),
    Unsubscribe(nostr::SubscriptionId),
    Publish(ValidatedEvent),
    Close(CloseReason),
}
```

- [ ] **Step 1: Write failing authentication tests**

Prove unique connection challenges; exact configured relay URL; exact single `relay` and `challenge` tags; kind `22242`; valid ID/signature; ±10-minute freshness; cross-connection replay rejection; multiple sequential authenticated pubkeys on one connection as required by NIP-42; and that auth events are never persisted or broadcast. An invalid AUTH after successful authentication must clear authenticated keys and subscriptions, rotate the challenge, and require a new successful AUTH before further reads or writes.

- [ ] **Step 2: Write failing session tests**

Before AUTH, `REQ` returns `CLOSED auth-required:` and `EVENT` returns `OK false auth-required:`. After AUTH, reads/writes call only typed policy/store ports. Test `REQ`, subscription replacement, `CLOSE`, `EVENT`, `OK`, `EOSE`, idempotency, per-connection limits, bounded pending output, and slow-consumer closure.

- [ ] **Step 3: Implement with deterministic clock/RNG and fake store**

Keep a set of authenticated pubkeys for the connection. The challenge lasts for that connection until deliberately rotated; an AUTH event from one connection cannot migrate to another.

- [ ] **Step 4: Test historical and live authorization**

Seed unauthorized records into the fake store before negative tests. Add a `RelayHub` that owns the cross-session subscription registry and routes validated publishes to bounded per-session outputs using the same sealed `AuthorizedQuery` values as historical reads. Exercise stored queries and cross-connection live fan-out, including an OR-filter whose later member is unauthorized, subscription removal on disconnect/re-auth failure, deduplication across the history/live handoff, and slow-client isolation.

- [ ] **Step 5: Verify and commit**

Run:

```bash
cargo test -p deaddrop-relay-core
cargo build -p deaddrop-relay-core --target wasm32-unknown-unknown
```

Commit: `feat: add authenticated relay session engine`

---

### Task 5: SQLite storage adapter

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/relay-sqlite/Cargo.toml`
- Create: `crates/relay-sqlite/src/lib.rs`
- Create: `crates/relay-sqlite/src/migrations.rs`
- Create: `crates/relay-sqlite/src/worker.rs`
- Create: `crates/relay-sqlite/migrations/0001_events.sql`
- Create: `crates/relay-sqlite/tests/store.rs`

**Storage shape:**

Store canonical event JSON with denormalized `kind`, `pubkey`, `created_at`, `received_at`, `d_tag`, `p_tag`, `h_tag`, `expires_at`, and replacement coordinate. Index only public, recipient, capability, replacement, and expiry access paths.

- [ ] **Step 1: Write failing migration/store tests**

Cover fresh migration, reopen/restart, permission restriction, idempotent event IDs, exact public/inbox/group queries, no raw-filter API, transactional replacement, rollback, expiration-on-read, and compaction.

- [ ] **Step 2: Write replacement-order tests**

Kind `0` replaces by `(pubkey, kind)` and `30443` by `(pubkey, kind, d)`. Newer `created_at` wins; equal timestamps use the NIP-01 event-ID ordering. Test both arrival orders.

- [ ] **Step 3: Implement a dedicated DB worker**

Use a bounded command channel and oneshot responses around one `rusqlite::Connection`; never share `Arc<Connection>` or block Tokio executor threads. Enable foreign keys and busy timeout. Make writes and replacement decisions transactional.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p deaddrop-relay-sqlite`

Commit: `feat: persist authorized relay events in sqlite`

---

### Task 6: Loopback-only debug WebSocket server

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/server/Cargo.toml`
- Create: `crates/server/src/main.rs`
- Create: `crates/server/src/config.rs`
- Create: `crates/server/src/connection.rs`
- Create: `crates/server/src/debug.rs`
- Create: `crates/server/src/maintenance.rs`
- Create: `crates/server/src/shutdown.rs`
- Create: `crates/server/tests/config.rs`
- Create: `crates/server/tests/debug_ws.rs`

- [ ] **Step 1: Write failing bind-policy tests**

Require `deaddrop debug --bind <SocketAddr> --data-dir <path>`. Accept IPv4/IPv6 loopback. Reject wildcard, LAN, and public addresses unless `--unsafe-debug-bind` is also present. Verify the unsafe warning on stderr and the actual bound socket address.

- [ ] **Step 2: Write failing WebSocket tests**

Use real clients over loopback. Verify challenge-first NIP-42, frame byte limits, text-only protocol, bounded channels, clean close/shutdown, and structured logs with no secrets, content, full `h`, or auth challenge.

- [ ] **Step 3: Implement server shell**

Use `tokio-tungstenite` for the debug listener and feed frames into the socket-independent session engine and shared `RelayHub`. Persist through `relay-sqlite`. Start a bounded, shutdown-aware maintenance loop that invokes expiry compaction on an interval through an injected clock; this phase must not expose a production TCP listener.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p deaddrop-server`

The integration suite must advance the fake clock and prove the maintenance loop physically removes expired rows without waiting for an explicit test call.

Commit: `feat: serve authenticated relay on loopback debug websocket`

---

### Task 7: Adversarial relay acceptance and CI

**Files:**

- Create: `crates/server/tests/relay_acceptance.rs`
- Create: `scripts/check-listeners.sh`
- Modify: `.github/workflows/feasibility.yml`
- Modify: `README.md`

- [ ] **Step 1: Build the end-to-end loopback test**

Use a temporary SQLite database and real keys A, B, and disposable C. Prove:

- A and B authenticate independently;
- C publishes a valid ephemeral-author gift wrap for A;
- A receives it and B cannot query it historically or live;
- exact `h` receives kind `445`, while absent/wrong/list/prefix `h` fails;
- profile/KeyPackage author mismatch fails;
- valid `1059`/`445` outer-author mismatch succeeds;
- restart, replacement, deduplication, expiration, and compaction preserve the same rules.

- [ ] **Step 2: Add listener and WASM regression guards**

CI builds both core crates for `wasm32-unknown-unknown`, runs all native tests, and audits that only the explicit debug test process opens a TCP listener. No test may pass merely because no private fixture was stored.

- [ ] **Step 3: Document the phase boundary**

Document debug usage and warn that it is not the production Tor endpoint. Link the next plan: raw embedded Arti onion WebSocket/static hosting over the same relay engine.

- [ ] **Step 4: Run full verification**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p deaddrop-protocol-core --target wasm32-unknown-unknown
cargo build -p deaddrop-relay-core --target wasm32-unknown-unknown
npm test
npm run check:pins
git diff --check
```

- [ ] **Step 5: Request code review and commit**

Commit: `test: prove authenticated relay isolation`

## Completion condition

This phase is complete only when untrusted wire values cannot reach storage, every socket operation requires NIP-42, inbox and group data are non-enumerable on both historical and live paths, SQLite survives restart with correct replacement/retention behavior, and the only clearnet listener is an explicitly requested loopback debug server. Then write and execute the embedded Arti onion/static-hosting plan.
