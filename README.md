# Deaddrop

Deaddrop is a Tor-only Marmot client and authenticated Nostr relay for anonymous one-to-one dead drops. The native relay now hosts its embedded web shell, health endpoint, and authenticated WebSocket relay as one persistent v3 onion service. The browser/client side is not implemented yet: the hosted page is an inert shell until the client-WASM, vault, and packaging phase, and it has no clearnet fallback.

Run deterministic checks with:

```bash
npm ci
npm run feasibility:offline
```

The complete live gate is opt-in, requires direct Tor network access and `lsof`, and may take several minutes on a cold Tor cache:

```bash
DEADDROP_LIVE_TOR=1 npm run feasibility
```

Only the live command writes the final machine-readable decision to `artifacts/feasibility/results.json`. Its stored command logs redact onion hostnames, event IDs, private state paths, and other capabilities. The latest human-readable result is in `docs/feasibility/2026-08-31-results.md`.

## Production onion relay

Give each production relay its own private state directory:

```bash
cargo run --locked -p deaddrop-server --bin deaddrop -- \
  relay \
  --data-dir ./local/deaddrop-state
```

The process exclusively locks that directory for its lifetime. A second process cannot safely share the onion identity or SQLite database and will fail instead of opening them concurrently. Existing path components must not be symlinks, and an existing directory must be owner-only (`0700` on Unix). Newly created private state and manifest files receive owner-only permissions.

Once the onion service and application host are ready, stdout contains exactly one JSON line and nothing else:

```json
{"onion_url":"http://<v3-address>.onion","relay_url":"ws://<v3-address>.onion/relay"}
```

Diagnostics are structured JSON on stderr and omit the onion address, event IDs, private keys, challenges, event content, and state internals. The startup line confirms local service construction and durable identity validation; Hypertor does not expose a separate descriptor-publication acknowledgment, so first reachability can lag while Tor publishes the descriptor.

The onion service exposes only these virtual routes:

- `GET /`, `/app.js`, and `/styles.css`: the finite build-time embedded shell assets. `HEAD` is also supported for these assets.
- `GET /health`: the fixed `ok` health response.
- `GET /relay`: only a canonical WebSocket upgrade is accepted; a normal HTTP request receives `426 Upgrade Required`.
- Every other target, host, method, request body, or noncanonical upgrade is rejected.

Production creates no local TCP listener and no UDP socket. It accepts raw streams from the embedded Arti onion service and may make outbound TCP connections to the Tor network. There is no SOCKS listener, local reverse proxy, bind flag, host/port override, operator asset directory, or network fallback. Audit the source boundary and the single loopback-only debug listener with:

```bash
scripts/check-listeners.sh
```

Stop the relay with Ctrl-C or `SIGINT` and wait for a successful process exit before copying its data. Shutdown first drops the onion service so it stops accepting new streams, then drains accepted work and closes SQLite.

### Identity, recovery, and backup

The data directory is one recovery unit: back up its Tor state, `identity.json` manifest, and relay database together while the relay is stopped. Possession of that backup includes control of the onion identity and access to relay data, so protect it as private key material. The process fails closed when initialization evidence exists but the identity manifest is missing, malformed, insecure, or inconsistent with the identity restored by Arti; it does not silently publish a replacement address over an existing database.

There is currently no in-place identity rotation command. To change identity, deliberately start the relay with a new empty data directory. That creates a different onion and relay URL, and every previously distributed link becomes invalid. Keep using the original directory when continuity is required.

## Debug relay

For local transport development only, run the explicit WebSocket debugging mode:

```bash
cargo run --locked -p deaddrop-server --bin deaddrop -- \
  debug \
  --bind 127.0.0.1:8765 \
  --data-dir ./local/deaddrop-debug-state
```

Debug mode is the only code path that constructs a `TcpListener`. It accepts loopback addresses by default; `--unsafe-debug-bind` is required for any wildcard, LAN, or public address and should be used only in an isolated development environment. NIP-42 authentication still applies, but it does not make this clearnet endpoint anonymous or protect network metadata.

The intended browser client roles and trust boundaries are described in the [Deaddrop design](docs/superpowers/specs/2026-08-31-deaddrop-design.md). The onion-hosting work is tracked in the [onion static-hosting plan](docs/superpowers/plans/2026-09-02-deaddrop-onion-static-hosting.md).

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
