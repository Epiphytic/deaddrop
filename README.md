# Deaddrop

Deaddrop is a Tor-only Marmot client and authenticated Nostr relay for anonymous one-to-one dead drops. The current workspace proves the pinned Marmot/MLS engine in native Rust and browser WASM, feasibility primitives for embedded onion hosting, Node direct-Arti access, and browser Arti access through a KPS/WebRTC gateway. The application relay itself currently exposes only the explicit clearnet debug endpoint described below.

Run deterministic checks with:

```bash
npm ci
npm run feasibility:offline
```

Run the complete live Tor gate with:

```bash
npm run feasibility
```

The live command is the only one that writes the final machine-readable decision at `artifacts/feasibility/results.json`. The latest human-readable result is in `docs/feasibility/2026-08-31-results.md`.

## Debug relay

The native relay currently exposes an explicit WebSocket debugging mode:

```bash
cargo run --locked -p deaddrop-server --bin deaddrop -- \
  debug \
  --bind 127.0.0.1:8765 \
  --data-dir ./local/deaddrop-state
```

The state directory is created with owner-only permissions. The process reports the actual bound address as structured JSON on stderr and drains accepted relay work and SQLite before exiting on Ctrl-C.

This endpoint is clearnet and is **not the production Tor service**. Debug mode accepts loopback addresses by default. `--unsafe-debug-bind` is required for any wildcard, LAN, or public address and should only be used in an isolated development environment. The listener still requires NIP-42 authentication, but authentication does not provide Tor anonymity or protect network metadata.

The intended onion-only application, browser hosting, client roles, and trust boundaries are described in the [Deaddrop design](docs/superpowers/specs/2026-08-31-deaddrop-design.md). The implemented relay-core phase and the next embedded-Arti/onion hosting milestone are tracked in the [native relay plan](docs/superpowers/plans/2026-09-01-deaddrop-native-relay.md); there is not yet a separate onion-hosting implementation plan.

To audit the current phase's listener boundary locally, install `lsof` and run:

```bash
scripts/check-listeners.sh
```

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
