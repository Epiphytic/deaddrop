# Deaddrop Embedded Onion and Static Hosting Implementation Plan

> Execute this plan task by task with test-first checkpoints and independent review before each commit.

**Goal:** Add a production `deaddrop relay` role that persists one embedded Arti v3 onion identity, serves the authenticated Nostr relay at `ws://<service>.onion/relay`, and hosts a self-contained browser landing shell at `http://<service>.onion/` without opening any TCP listener.

**Architecture:** `hypertor::OnionService` supplies raw inbound `OnionStream`s on virtual port 80. A bounded Hyper HTTP/1 layer serves a finite compile-time asset manifest and upgrades only `/relay`; the upgraded stream enters the same socket-independent session driver used by debug mode. A shared native runtime owns SQLite, the `RelayHub`, accepted `SessionTask`s, maintenance, connection shutdown, and final draining. Production configuration has no bind address or clearnet fallback.

**Technology:** Rust 1.97, Tokio, Hyper 1, hyper-util, http-body-util, tokio-tungstenite, hypertor 0.3.0 / Arti 0.45, rusqlite, plain HTML/CSS/ES modules, Node's built-in test runner, lsof.

---

## Scope and invariants

In scope:

- `deaddrop relay --data-dir <path>` with fixed virtual port 80 and fixed service nickname;
- persistent owner-only Arti state under `<data-dir>/tor` and relay SQLite at `<data-dir>/relay.sqlite3`;
- one canonical HTTP onion origin and `ws://<onion>/relay` NIP-42 relay URL;
- finite embedded static assets, a health route, and bounded HTTP/1 WebSocket upgrades;
- shared relay lifecycle and session behavior across debug TCP and onion streams;
- offline HTTP/upgrade/security tests and a gated live Tor persistence/WebSocket test;
- zero production TCP listeners, SOCKS proxies, reverse proxies, or clearnet fallbacks.

Out of scope:

- the reduced Marmot/OpenMLS client engine, KeyPackage processing, vaults, or message composition;
- browser Arti/KPS destination transport, public gateway configuration, or Snowflake;
- native browser `fetch`/`WebSocket` access to onion destinations;
- full NIP-19 decoding, QR codes, Node/npx client behavior, MCP, Cloudflare, or multi-user UI;
- proof-of-work, because the pinned optional implementation adds LGPL-only dependencies; this phase uses stream, connection, task, and introduction rate limits instead.

This phase proves the WebSocket through an independent native `hypertor::TorClient`/`TorWebSocket`. The pinned browser `tor-js` API currently proves only onion HTTP `fetch()` and exposes neither an arbitrary destination stream nor WebSocket connection API. The next client plan must feasibility-gate an explicit tor-js extension or equivalent Arti-WASM destination-stream API before claiming browser chat; native browser `WebSocket("ws://...onion")` is forbidden as a shortcut.

The static shell must state that messaging is not enabled yet. It may recognize a `#nprofile...` fragment locally and render future CLI instructions, but it must not transmit, decode, or persist the fragment.

---

### Task 1: Make the WebSocket relay driver transport-independent

**Files:**

- Modify: `crates/server/src/connection.rs`
- Modify: `crates/server/src/debug.rs`
- Create: `crates/server/src/connection/tests.rs`

- [x] **Step 1: Write a failing in-memory WebSocket test**

Use a source-unit test with `tokio::io::duplex` and `WebSocketStream::from_raw_socket` to prove an already-upgraded server-role stream receives `AUTH` first, accepts an exact NIP-42 relay URL, and completes a publish/query round trip through real SQLite. The test must not construct a `TcpStream`; do not widen the connection driver's production visibility solely for testing.

- [x] **Step 2: Split handshake from session driving**

Keep the debug-only `accept_async_with_config(TcpStream, ...)` wrapper, then pass the resulting socket into a generic `serve_websocket<S>` where `S: AsyncRead + AsyncWrite + Unpin`; require `Send + 'static` only at the spawn/registrar boundary. Preserve frame/message caps, text-only handling, periodic live-output draining, idle and handshake deadlines, redacted diagnostics, and server-owned `SessionTask` handoff. An onion HTTP upgrade must use `from_raw_socket(Role::Server)` and must never perform a second WebSocket handshake.

- [x] **Step 3: Bound stalled output independently of shutdown**

Add a Tor-tolerant per-write deadline in addition to the shutdown race. Test a peer that stops reading and prove its generic driver terminates without impeding a second driver or global shutdown. Task 2 proves registrar permit release.

- [x] **Step 4: Verify and commit**

Run `cargo test --locked -p deaddrop-server` so the new source-unit test and existing debug/acceptance suites all execute; do not rely on a name filter that can match zero tests.

Commit: `refactor: share relay websocket driver across transports`

---

### Task 2: Extract the shared native relay runtime

**Files:**

- Create: `crates/server/src/runtime.rs`
- Create: `crates/server/src/runtime/tests.rs`
- Modify: `crates/server/src/lib.rs`
- Modify: `crates/server/src/debug.rs`
- Modify: `crates/server/src/connection.rs`

- [x] **Step 1: Write failing lifecycle tests**

In source-unit tests, exercise startup failure after SQLite opens, maintenance failure, half-open connection shutdown, a disconnected publisher whose accepted write is still pending, a saturated connection/task queue, and shutdown while generic connection/session work is being admitted. Assert no accepted database write or hub fan-out is abandoned. The upgrade-specific admission race belongs to Task 4.

- [x] **Step 2: Introduce one shared runtime owner**

Move SQLite opening, `RelayHub`, bounded session-task supervision, maintenance, shutdown signaling, and capacities out of `debug.rs`. Expose only narrow handles for registering connection work and handing off `SessionTask`s; do not expose raw store writes to transports.

- [x] **Step 3: Preserve strict shutdown ordering**

Stop transport admission, notify and await connection/upgrade tasks, close session-task admission, drain all accepted tasks, stop and await maintenance, then call `SqliteStore::shutdown()` last. If submission closes during handoff, finish already-accepted session work inline. Bound handshakes, socket writes, idle connections, and transport close; the complete already-accepted `SessionTask -> store -> hub fan-out -> store shutdown` chain is intentionally non-cancellable. Surface unexpected supervisor/maintenance termination as a server error.

- [x] **Step 4: Rewire debug mode without behavior changes**

Keep `DebugServer::{start,bound_addr,shutdown,run_until_ctrl_c}` and every Task 6/7 test green. `debug` remains the only role allowed to construct a `TcpListener`.

- [x] **Step 5: Verify and commit**

Run `cargo test -p deaddrop-server` and strict package Clippy.

Commit: `refactor: centralize native relay lifecycle`

---

### Task 3: Build the self-contained browser landing shell

**Files:**

- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `apps/web/package.json`
- Create: `apps/web/index.html`
- Create: `apps/web/app.js`
- Create: `apps/web/styles.css`
- Create: `apps/web/test/shell.test.mjs`

- [x] **Step 1: Write failing pure shell tests**

Test `#nprofile...` recognition, exact `npx deaddrop chat '<full-bootstrap-url>'` rendering, and safe `textContent` output. Assert the fragment is never placed in a request, log, cookie, storage API, or HTML sink.

- [x] **Step 2: Add a deterministic source-policy test**

Reject external URLs and runtime assets, inline script/style, `fetch`, `XMLHttpRequest`, native `WebSocket`, `EventSource`, service workers, storage, analytics, fonts, CDN, STUN, and TURN. The shell must have no install-time or runtime dependency.

- [x] **Step 3: Implement the minimal intentional UI**

Show the onion-hosted relay status, the same-origin future relay path, bootstrap-link detection, copyable future CLI instructions, and an explicit “messaging arrives in the next client phase” boundary. Use accessible semantic HTML, responsive local CSS, and no fake compose/chat controls.

- [x] **Step 4: Join the root workspace and verify**

Add `apps/*` to npm workspaces so `npm test` runs the shell tests. Update the lockfile with npm, then run `npm test` and `npm ci` validation.

Commit: `feat: add self-contained deaddrop landing shell`

---

### Task 4: Serve embedded HTTP and WebSocket routes over raw streams

**Files:**

- Modify: `crates/server/Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/server/src/static_app.rs`
- Create: `crates/server/src/onion_http.rs`
- Create: `crates/server/src/onion_http/tests.rs`
- Modify: `crates/server/src/lib.rs`

- [x] **Step 1: Write failing route and header tests over `duplex`**

In source-unit tests, serve the actual Hyper connection over an in-memory stream. Cover `GET|HEAD /`, `/app.js`, `/styles.css`, `GET /health`, `GET /relay` without upgrade (`426`), unknown paths (`404`), unsupported methods (`405`), query-string rejection, request bodies/transfer encoding rejection, and malformed/oversized/slow headers. Before route dispatch, require exactly one canonical onion `Host` on every request; reject missing/duplicate/malformed Host, absolute-form authorities, and any authority that conflicts with the canonical origin. Task 5 proves raw-stream admission against the supervisor introduced here.

- [x] **Step 2: Enforce the static security envelope on every application response**

Embed a finite build-time asset manifest; never accept an operator web root. Apply `Cache-Control: no-store`, `Content-Security-Policy` with `connect-src 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, COOP/COEP/CORP, restrictive `Permissions-Policy`, and `frame-ancestors 'none'` to application success and error responses. Emit no `Date`, `Server`, HSTS, CORS, or framework header. Hyper owns malformed input rejected before it constructs a request; keep those parser responses bounded and bodyless and disable its automatic `Date` header.

- [x] **Step 3: Implement the exact `/relay` upgrade**

Use Hyper HTTP/1 with upgrades, strict header/body/buffer/time limits, and one bounded transport-independent HTTP/upgrade supervisor. Configure `http1::Builder::timer(TokioTimer::new())` before `header_read_timeout`, disable automatic Date with `auto_date_header(false)`, and call `serve_connection(...).with_upgrades()`. Allow no body or exact `Content-Length: 0`; reject positive content length plus any `Transfer-Encoding` or `Expect` without draining. After global Host/request-target validation, apply WebSocket Origin policy: if `Origin` is present require exact `http://<onion>`, while allowing no `Origin` for CLI clients. Parse `Connection` and `Upgrade` as comma-separated case-insensitive tokens, require WebSocket version `13`, validate that `Sec-WebSocket-Key` decodes to exactly 16 bytes, and reject `null`/foreign origins plus unrequested extensions/subprotocols. Do not hand-write RFC6455 acceptance: validate and construct the `101` with tungstenite's server handshake primitives, call `hyper::upgrade::on(&mut request)`, await it in tracked work, wrap `hyper_util::rt::TokioIo::new(upgraded)` once with `WebSocketStream::from_raw_socket(Role::Server, ...)`, then enter the shared driver with the immutable server-derived `ws://<onion>/relay` URL. The supervisor owns the permit across both the Hyper request and upgraded WebSocket task rather than releasing it at `101`; saturated `try_submit` fails closed and drops the stream.

- [x] **Step 4: Prove full relay behavior through the HTTP seam**

Over one in-memory upgraded route, verify challenge-first NIP-42, authenticated `REQ`/`EOSE`, successful publish, authorized live/history delivery, binary/oversize policy, upgrade admission during shutdown, and accepted publish completion after disconnect. Do not bypass the HTTP upgrade or store. Separately prove wrong Host/path/query/scheme fail at HTTP before a session exists, while valid upgrades with wrong NIP-42 relay-tag scheme/host/port/path/query/trailing-slash variants receive authentication rejection.

- [x] **Step 5: Verify and commit**

Run `cargo test --locked -p deaddrop-server` and strict package Clippy so source-unit and integration coverage both execute.

Commit: `feat: serve embedded app and relay over http streams`

---

### Task 5: Launch the production embedded Arti onion service

**Files:**

- Modify: `crates/server/Cargo.toml`
- Create: `crates/server/src/onion.rs`
- Create: `crates/server/src/state.rs`
- Modify: `crates/server/src/config.rs`
- Modify: `crates/server/src/main.rs`
- Modify: `crates/server/src/lib.rs`
- Create: `crates/server/tests/relay_config.rs`
- Create: `crates/server/tests/onion_lifecycle.rs`

- [ ] **Step 1: Write failing production configuration tests**

Require `deaddrop relay --data-dir <path>`. Prove the relay config contains no bind, host, port, assets directory, SOCKS, proxy, or fallback field/flag; fixed virtual port 80 and nickname `deaddrop-relay` select the persistent identity. Reject missing, parent-traversing, symlinked, non-directory, and group/world-accessible state paths before Tor starts. Acquire and retain an exclusive owner-only process lock before opening SQLite or Arti so a second relay cannot share the identity/database concurrently.

- [ ] **Step 2: Launch hardened raw `OnionService` streams**

Store Arti state at `<data-dir>/tor`; use `hypertor = 0.3.0` with only `server`, `rustls`, and `static-sqlite`. Enable full vanguards, a small per-circuit stream cap, and an introduction token bucket. Do not enable client, SOCKS, WebSocket-client, proof-of-work, or a TCP reverse proxy in the production dependency. Inspect every existing path component with `symlink_metadata`, reject lexical `..` before mutation, and do not reuse the probe's final-directory-only permission helper unchanged. Model identity state explicitly: `fresh` means no manifest, Tor state, or relay database; `resume` requires a valid manifest; any nonempty/previously initialized directory with an absent or malformed manifest is `lost/incomplete` and fails closed before launch. After a fresh `OnionService::launch()` and address derivation, but before accepting streams or announcing readiness, write an owner-only manifest to a same-directory temporary file, `fsync` it, atomically rename it, and `fsync` the parent directory. On resume, launch and compare the derived address to the manifest before accepting traffic; on mismatch immediately drop the service and fail. Do not claim that hypertor confirms descriptor upload or that a mismatched descriptor was never briefly published: the pinned API exposes neither guarantee.

- [ ] **Step 3: Supervise the onion HTTP host**

Feed each already-accepted `OnionStream` into Task 4's bounded HTTP/upgrade supervisor with `try_submit`; hypertor exposes streams only after its own bounded internal accept queue, so excess application streams are immediately dropped rather than pretending admission can precede Arti acceptance. Hold supervisor permits across HTTP upgrades and stop accepting by dropping `OnionService` on shutdown. A closed accept stream or failed HTTP supervisor triggers orderly global shutdown and nonzero status. If onion launch fails after SQLite opens, fully shut down the shared runtime.

- [ ] **Step 4: Publish a stable machine-readable startup record**

After launch, manifest validation/durability, and host readiness, print exactly one stdout JSON record containing public `onion_url` and `relay_url`; do not call it descriptor-upload confirmation because hypertor exposes no such signal. Keep structured redacted diagnostics on stderr and never log private keys, challenges, event content/IDs, full `h`, or state internals. `run_until_ctrl_c` must unpublish first, then drain the shared runtime.

- [ ] **Step 5: Verify and commit**

Run config/lifecycle tests, `cargo test -p deaddrop-server`, a release build, and `cargo tree -p deaddrop-server -e normal,build` to confirm the production graph contains neither SOCKS nor hypertor's client WebSocket feature. Dev-only live-client features may appear in test graphs and must not be mistaken for the release graph.

Commit: `feat: host deaddrop as an embedded arti onion service`

---

### Task 6: Prove Tor-only persistence and update CI/documentation

**Files:**

- Modify: `crates/server/Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/server/tests/live_onion.rs`
- Modify: `scripts/check-listeners.sh`
- Modify: `scripts/run-feasibility.mjs`
- Modify: `.github/workflows/feasibility.yml`
- Modify: `README.md`

- [ ] **Step 1: Add deterministic no-listener/source guards**

Keep the debug audit at exactly one explicit loopback listener. Assert that `TcpListener` appears only in the debug transport and that `relay` accepts no networking flag other than its data directory. Do not infer success merely because a process failed before publication.

- [ ] **Step 2: Build the gated live Tor acceptance test**

Add a dev-only hypertor dependency with `client`/`ws` features; it must not enter the release graph. With `DEADDROP_LIVE_TOR=1`, start the real `deaddrop relay`, require the process to stay alive, and wait for its startup record with a fixed deadline. Inspect that exact PID before and during traffic: run `lsof -nP -a -p PID -iTCP -sTCP:LISTEN` and require no rows, then `lsof -nP -a -p PID -iUDP` and require no rows because UDP has no `LISTEN` state. Outbound Arti TCP connections are allowed. Through the dev-only embedded `hypertor::TorClient`, fetch `/`, `/app.js`, and `/health`; through dev-only `TorWebSocket`, perform AUTH, publish, and a positive authorized query. No SOCKS proxy is permitted.

- [ ] **Step 3: Prove identity and data persistence across restart**

Restart against the same private data directory and assert the onion/relay URLs are identical and the previously stored event remains available only to its authorized reader. Bound SIGINT shutdown and redact live evidence.

- [ ] **Step 4: Integrate deterministic and live CI**

Run all offline shell, Rust, listener, source-policy, and WASM regression checks in the deterministic job. Add the live onion HTTP/WebSocket proof only to the opt-in live-Tor job and record separate sanitized evidence for HTTP reachability and authenticated WebSocket success.

- [ ] **Step 5: Document operation and phase boundary**

Document `deaddrop relay --data-dir`, exclusive-directory operation, persistent identity/manifest backup implications, fail-closed identity loss, startup JSON, virtual routes, zero-listener design, and safe shutdown. State clearly that changing identity currently requires a deliberate new data directory and invalidates old links; the hosted shell is inert until the next client/WASM/vault plan, and there is no browser clearnet fallback.

- [ ] **Step 6: Run full verification and request review**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
CC_wasm32_unknown_unknown=<wasm-capable-clang> cargo build --locked -p deaddrop-protocol-core --target wasm32-unknown-unknown
CC_wasm32_unknown_unknown=<wasm-capable-clang> cargo build --locked -p deaddrop-relay-core --target wasm32-unknown-unknown
npm ci
npm test
npm run check:pins
bash -n scripts/check-listeners.sh
scripts/check-listeners.sh
git diff --check
```

Run the live test only when explicitly enabled and network access is available. Request an independent security/code review and resolve every Critical or Important finding.

Commit: `test: prove onion-only relay and static hosting`

## Completion condition

This phase is complete only when the production process opens no TCP listener, restores the same v3 onion identity and relay database across restart, serves only the embedded security-constrained shell and `/health`, upgrades only canonical `/relay`, and passes a real embedded-Arti authenticated WebSocket round trip. Then write and execute the reduced client-WASM/vault/npx plan.
