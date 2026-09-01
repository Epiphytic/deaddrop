# Deaddrop

Deaddrop is a Tor-only Marmot client and authenticated Nostr relay for anonymous one-to-one dead drops. The current workspace proves the pinned Marmot/MLS engine in native Rust and browser WASM, embedded onion hosting, Node direct-Arti access, and browser Arti access through a KPS/WebRTC gateway.

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

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
