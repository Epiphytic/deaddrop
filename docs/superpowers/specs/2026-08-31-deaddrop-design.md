# Deaddrop Design

**Status:** Approved in conversation; awaiting written-spec review

**Date:** 2026-08-31

**Repository:** `Epiphytic/deaddrop`

**License:** Apache-2.0

## 1. Purpose

Deaddrop is a small, Tor-native Marmot messaging system for contacting a recipient without requiring the sender to have a persistent identity. A recipient publishes a Nostr identity and a Marmot KeyPackage. A sender may create a fresh Nostr identity for every conversation, fetch that KeyPackage over Tor, establish a one-to-one MLS group, and send an end-to-end encrypted message.

The proof of concept has two standalone products:

1. A browser and CLI client distributed as an npm package and runnable with `npx deaddrop`.
2. A Rust relay that exposes a Nostr WebSocket relay and the browser application through an Arti-hosted onion service.

Both products carry their Tor support internally. Neither requires the operator or user to configure a system Tor proxy. Loopback-only clearnet networking is permitted in an explicit debugging mode.

The first release proves interoperable one-to-one direct messages. Multi-user groups are essential but are a fast follow rather than part of the initial proof of concept.

## 2. Product Principles

- **Tor by default and by construction.** Production modes do not silently fall back to direct networking.
- **Anonymous initiation.** A sender can begin a conversation using a new, memory-only Nostr identity.
- **Recipient continuity.** A recipient can keep one or more persistent identities and encrypted local conversation state.
- **Protocol compatibility.** Deaddrop follows the adopted Marmot protocol and Nostr transport shapes rather than defining a parallel MLS dialect.
- **Minimal relay knowledge.** The relay stores public discovery records and opaque encrypted transport events, not plaintext or group membership.
- **One client core.** Browser, interactive CLI, scripting CLI, and agent integration share the same protocol and vault semantics.
- **Honest privacy boundaries.** The product distinguishes message confidentiality, sender pseudonymity, transport anonymity, and resistance to traffic analysis.

## 3. Scope

### 3.1 Proof-of-concept scope

- One-to-one Marmot conversations.
- Persistent recipient identities and optional reusable sender identities.
- A fresh sender identity per conversation by default.
- A reusable last-resort recipient KeyPackage.
- NIP-42-authenticated relay connections.
- Public recipient profile and KeyPackage discovery.
- Recipient-addressed inbox delivery and capability-addressed group delivery.
- Browser, CLI, and MCP-compatible agent access.
- Optional passphrase-encrypted vaults.
- Native Rust relay with an internally hosted onion service.
- Browser Tor through Arti WASM and a KPS gateway; Snowflake compatibility is an optional transport capability when supported by the pinned Arti integration.
- Node CLI Tor through an Arti-based direct network adapter, without KPS.
- Static browser application hosted by the relay over its onion service.
- A loopback debugging mode for development and tests.

### 3.2 Fast follows

- Multi-user Marmot groups.
- One-time KeyPackage pools with safe consumption and replenishment.
- A Cloudflare Workers deployment adapter.
- Additional gateway operators and gateway discovery.
- Attachments and encrypted media.

### 3.3 Non-goals for the proof of concept

- A general-purpose public Nostr relay.
- Clearnet production access to the native relay.
- A complete Tor SOCKS proxy in the browser.
- Contact discovery, social graphs, reactions, media, push notifications, or moderation systems.
- Delete-on-read semantics.
- Protection from a global passive observer, a compromised endpoint, or traffic correlation across colluding infrastructure.

## 4. Feasibility Gate

Implementation begins with a narrow feasibility milestone. The product architecture depends on these results, so failure does not trigger an unreviewed protocol substitution.

The gate must demonstrate:

1. A reduced Rust Marmot/MDK engine and its OpenMLS dependencies compile to `wasm32-unknown-unknown` with only the one-to-one operations Deaddrop needs.
2. The WASM engine can create and validate current Marmot account identity proofs, KeyPackages, Welcome messages, kind-445 group messages, and kind-9 application messages.
3. Browser persistence can round-trip encrypted MLS state through IndexedDB without losing epoch state.
4. Arti WASM can establish an onion connection in a supported browser through a KPS gateway. The artifact separately records whether the pinned transport supports public Snowflake infrastructure; Snowflake is not assumed to replace the required KPS gateway.
5. The Node adapter can establish an onion connection without KPS.
6. The Rust server can publish and serve its own onion service through embedded Arti.
7. A browser or Node client can exchange a minimal conversation with a native client using the same pinned Marmot wire profile.

The feasibility artifact will pin an upstream Marmot protocol revision and MDK revision. Deaddrop will track the canonical Marmot event assignments, including kind `30443` KeyPackages, kind `1059` gift-wrapped welcomes, kind `445` group transport, and kind `9` chat payloads. If the Rust-to-WASM route fails, switching to `marmot-ts` or another engine requires a short design revision and a new compatibility test; it is not an automatic fallback.

## 5. Architecture

```text
Browser app                              Node / npx CLI
  UI + IndexedDB                           CLI / JSON / MCP
          |                                      |
          +---------- Deaddrop client core ------+
                     Marmot + vault API
                              |
                   reduced Rust/WASM engine
                              |
                 Nostr transport abstraction
                    /                     \
          Arti WASM + KPS           Arti Node adapter
                    \                     /
                     onion WebSocket relay
                              |
              Rust native shell + relay core
                 Arti onion service + SQLite

Cloudflare fast follow:
  browser/CLI -> Cloudflare edge adapter -> WASM relay core -> Durable Objects
```

The codebase is a monorepo with sharply separated platform boundaries:

- `crates/protocol-core`: platform-neutral event validation, authorization decisions, retention policy, and storage traits. It must compile natively and to WASM.
- `crates/client-wasm`: the reduced Marmot/OpenMLS engine, vault crypto, and stable WASM API.
- `crates/relay-core`: Nostr relay behavior independent of socket and database implementations; it must compile natively and to WASM.
- `crates/server`: native Rust executable providing `relay`, `gateway`, and `debug` roles.
- `packages/client`: TypeScript facade shared by browser and Node.
- `packages/cli`: `deaddrop` npm executable, JSON mode, and MCP server.
- `apps/web`: a self-contained browser UI with no third-party runtime assets.
- `deploy/cloudflare`: fast-follow Worker and Durable Object bindings around `relay-core`.

The native release may ship one Rust binary with subcommands, but relay and KPS gateway are separate runtime roles. Operators should deploy them on different hosts or at least different network identities to reduce correlation.

## 6. Tor and Network Model

### 6.1 Native relay

`deaddrop relay` starts embedded Arti, creates or restores an onion-service identity, and exposes the Nostr WebSocket endpoint and static web application only through that onion service. It does not bind a public clearnet interface.

The onion identity is persistent by default so recipient links remain stable. Its keys live in a permission-restricted server data directory. An operator may deliberately rotate the service identity, but rotation invalidates old bootstrap links unless another relay hint remains valid.

`deaddrop debug` binds only to an explicit loopback address and prints a prominent warning. Binding debug mode to a non-loopback address requires a separate unsafe flag; it is never inferred.

### 6.2 Browser

The browser loads a self-contained application and runs the client cryptography and Arti components in WASM. Because browser sandboxes cannot open arbitrary TCP or UDP sockets, the Arti transport uses the KPS browser gateway design. If the pinned Arti integration also exposes Snowflake, Deaddrop may offer it as an optional censorship-resistant transport, but Snowflake is not assumed to provide or replace the KPS gateway.

The web application ships with a default public KPS gateway list and allows users to add or replace gateways. Gateway failure is visible and does not cause clearnet fallback. Deaddrop documents that a gateway can observe client connection metadata and that operating it beside a relay weakens unlinkability.

### 6.3 Node CLI

The Node runtime uses the same Rust/WASM protocol core but a Node network adapter capable of direct socket access. It embeds Arti functionality and connects to onion endpoints without a local SOCKS proxy or KPS gateway.

### 6.4 Cloudflare adapter

The Cloudflare deployment is a fast follow. It reuses the WASM-compatible relay core, Workers WebSockets, and Durable Objects or an equivalent consistent storage binding. Cloudflare's onion-routing facilities do not provide the same trust or metadata boundary as a self-hosted onion service; the UI and documentation must identify the active deployment type rather than treating them as equivalent.

## 7. Identity, Discovery, and Bootstrap Links

### 7.1 Roles

A **recipient** has a persistent Nostr account identity and one or more local MLS devices. The recipient publishes a Marmot KeyPackage and may publish public Nostr metadata.

A **sender** is a full Marmot participant but chooses its identity lifetime:

- `ephemeral` (default): a new Nostr identity per conversation, held only in memory unless saved;
- `persistent`: a vault-backed identity reused for replies or multiple conversations;
- `explicit`: an imported identity selected by the user.

Even an ephemeral sender completes NIP-42 authentication with its ephemeral key. Anonymous initiation therefore means unlinkability from a pre-existing identity, not unauthenticated relay access.

### 7.2 Bootstrap URL

The canonical clickable form is:

```text
https://<client-host>/#<nprofile>
```

The `nprofile` is standard NIP-19 data containing the recipient's Nostr public key and one or more relay hints. The fragment is not sent to the HTTP host. The page parses it locally, creates an ephemeral sender identity, connects to a hinted relay through Tor, fetches and verifies the recipient's current KeyPackage, and opens a conversation composer.

The landing screen also renders a QR code and equivalent CLI instructions, for example:

```text
npx deaddrop chat '<full-bootstrap-url>'
```

Relay hints may identify onion or clearnet endpoints, but production Deaddrop clients always reach them through Arti. A self-hosted onion URL may host the application itself; a clearnet bootstrap page can also be used because the recipient and relay information remains in the fragment. The application contains no third-party fonts, analytics, scripts, images, or CDN dependencies.

### 7.3 KeyPackage policy

The proof of concept publishes a current Marmot kind-30443 last-resort KeyPackage. Reuse is accepted for initial asynchronous reachability, and the MLS leaf/signature state is rotated as required after joining. The client warns recipients that a reusable package has weaker pre-key hygiene than a one-time pool.

KeyPackages are replaceable and have explicit validity. Clients reject expired, malformed, identity-mismatched, or unsupported-capability packages. One-time package pools and atomic consumption are deferred until the initial interoperability path works.

## 8. Relay Protocol and Authorization

The relay speaks the ordinary Nostr WebSocket protocol over its onion endpoint. Every connection must complete NIP-42 before reads or writes are accepted. Authentication identifies the current connection; it is not treated as proof of a durable human identity.

### 8.1 Stored event classes

The proof of concept stores only:

- allowlisted public discovery events, initially kind `0` metadata;
- Marmot kind `30443` KeyPackage events;
- Marmot/Nostr inbox delivery events, including kind `1059` gift wraps;
- Marmot kind `445` encrypted group transport events.

Unknown kinds and unsupported filter shapes are rejected. The allowlist can expand only through an explicit protocol change.

### 8.2 Read rules

After NIP-42 authentication, a client may:

- read allowlisted public discovery events and KeyPackages;
- read inbox events whose recipient `p` tag exactly matches the authenticated public key;
- read kind-445 events only with an exact random `h` capability in the subscription filter.

The relay rejects broad inbox scans, broad kind-445 scans, filters that omit the required tag, and filters with ambiguous recipient sets. It never exposes an index of `h` values. Knowledge of the random `h` value is the group-read capability; the relay does not maintain or infer MLS group membership.

### 8.3 Write rules

Every published event must have a valid signature, and author binding is enforced by event class:

- public profile and KeyPackage events must be authored by the NIP-42-authenticated account;
- kind-445 group events must satisfy the current Marmot ephemeral-author and envelope rules; MLS authenticates the inner sender, so the outer event key is not required to equal the connection key;
- NIP-59 gift wraps must use their protocol-required ephemeral outer author, so their outer event key is not required to equal the connection key;
- all inbox events must have exactly one permitted recipient shape.

The connection key remains the authenticated admission and rate-limit principal even where an envelope protocol requires a different event author. An anonymous sender can use a disposable connection key, so this does not expose a pre-existing identity. The relay does not claim that NIP-42 proves authorship of encrypted Marmot payloads.

Schema checks, timestamp windows, event-size limits, per-connection limits, and quotas run before persistence. The relay cannot validate MLS plaintext and does not attempt content moderation inside ciphertext.

### 8.4 Retention

Encrypted transport events default to seven-day retention and may request a shorter lifetime with NIP-40. The server caps requested retention at 30 days. Public discovery events and current replaceable KeyPackages follow replaceable-event semantics rather than message TTL semantics.

Delivery does not delete an event. Delete-on-read is excluded because it creates race, recovery, and multi-device failure modes. Expiration is enforced both on reads and by background compaction.

## 9. Conversation Data Flow

### 9.1 Recipient setup

1. The recipient creates or imports a Nostr identity.
2. The client creates a vault, optionally protected by a passphrase.
3. The Marmot engine creates the device credential, identity proof, and last-resort KeyPackage.
4. The client NIP-42-authenticates to the relay through Tor and publishes kind `0` metadata if desired and the kind `30443` KeyPackage.
5. The client produces the `nprofile` bootstrap URL, QR code, and `npx` command.

### 9.2 Anonymous first message

1. The sender opens the URL or invokes the CLI.
2. The client creates a fresh in-memory Nostr identity unless the sender selects a saved identity.
3. The client reaches a relay hint through Arti, completes NIP-42, and fetches the recipient's KeyPackage.
4. It validates the KeyPackage, creates a two-member Marmot group with a cryptographically random Nostr `h` routing value, and produces the Welcome and initial encrypted application message.
5. It publishes the gift-wrapped Welcome to the recipient's inbox and the kind-445 encrypted message to the group capability.
6. The sender may discard all state, keep the tab/process alive for a reply, or save the conversation into a vault.

### 9.3 Recipient receive and reply

1. The recipient subscribes to its authenticated inbox.
2. It decrypts and validates the Welcome, joins the MLS group, and learns the random `h` capability from authenticated group state.
3. It subscribes using that exact `h`, decrypts the initial message, and persists the new MLS epoch state atomically.
4. A reply is encrypted into the same MLS group and published as kind `445`.

The relay sees event envelopes, authenticated connection keys, routing tags, sizes, and timing. It never receives MLS plaintext or vault keys.

## 10. Client Surfaces

### 10.1 Browser

The browser is a unified recipient and sender application. Opening an ordinary page presents vault creation/import, inbox, and identity management. Opening a bootstrap fragment enters the anonymous-compose flow immediately while still allowing the sender to save the resulting conversation later.

The initial UI contains only:

- connection/Tor status;
- bootstrap-link confirmation;
- message composer and conversation history;
- save/discard identity controls;
- recipient setup and share controls;
- vault lock/unlock;
- actionable errors and retry.

### 10.2 CLI

The npm package exposes a stable `deaddrop` executable and can be run without installation through `npx deaddrop`. Its initial commands are:

- `deaddrop init` — create a recipient vault and identity;
- `deaddrop publish` — publish/refresh profile and KeyPackage;
- `deaddrop share` — print bootstrap URL, QR, and command;
- `deaddrop chat <url-or-nprofile>` — create or resume a conversation;
- `deaddrop inbox` — receive and optionally follow messages;
- `deaddrop send` — noninteractive send with JSON output;
- `deaddrop mcp` — expose a local MCP server for agents.

Human output goes to stderr when stdout is reserved for JSON. Noninteractive commands have deterministic exit codes and never prompt unless explicitly requested.

### 10.3 Agent permissions

The MCP surface has three permission profiles:

- `observe` (default): list identities and conversations and read locally decrypted messages without exporting private key material;
- `correspond`: observe plus send and reply in already approved conversations;
- `recipient`: correspond plus create identities, publish KeyPackages, and generate bootstrap links.

Write-capable profiles require explicit startup configuration. The server exposes narrow operations rather than arbitrary filesystem, key-export, or raw signing access. Every mutating result states which identity and conversation were used.

## 11. Vault and Persistence

Browser state lives in IndexedDB. CLI state lives in a permission-restricted application data directory. Both use the same versioned logical vault format even if their storage adapters differ.

The vault contains Nostr secret keys, MLS credentials and epoch state, unpublished KeyPackage secrets, conversation routing capabilities, relay hints, and minimal message history. Relay data never substitutes for the vault because the relay cannot reconstruct MLS state.

A passphrase is optional but strongly encouraged for persistent identities. Passphrase protection uses:

- a unique random salt;
- Argon2id with versioned parameters calibrated per platform;
- an AEAD-encrypted, versioned vault envelope;
- fresh nonces and authenticated metadata;
- atomic replace-on-success updates;
- best-effort zeroization, with explicit documentation of browser limitations.

There is no password recovery path. A wrong passphrase and a corrupted vault produce distinct local diagnostics without leaking secrets. An ephemeral sender can remain entirely memory-only and leave no Deaddrop vault after the tab or process closes.

## 12. Failure Handling

Errors are classified at the boundary where recovery is possible:

- **Tor bootstrap or gateway unavailable:** remain offline, show the active path and retry/backoff controls; never fall back to direct networking.
- **Onion service unavailable:** try the next explicit relay hint, preserving the trust distinction between hints.
- **NIP-42 failure:** discard subscriptions and writes for that socket and require a new challenge flow.
- **Invalid or expired KeyPackage:** do not create a group; explain that the recipient must republish.
- **MLS validation or epoch failure:** quarantine the event, preserve the last valid state, and expose a recoverable diagnostic without advancing the group.
- **Publish uncertainty:** deduplicate by Nostr event id and retry idempotently.
- **Vault write failure:** do not acknowledge a state-changing receive/send as durable until the new MLS state is atomically stored.
- **Retention expiry:** report that the relay no longer has the event; do not manufacture an empty successful conversation.
- **Unsupported browser/runtime:** fail before identity creation and explain the missing capability.

Logs are structured and redact secret keys, passphrases, decrypted content, KeyPackage private material, and full capability tags. Debug mode may increase protocol diagnostics but not secret logging.

## 13. Security and Privacy Model

Marmot/MLS provides message confidentiality and group-state security when endpoints and cryptographic implementations are sound. Tor is intended to hide the client's network address from the relay. Fresh sender Nostr keys prevent direct linkage to an existing Nostr identity.

These properties do not eliminate metadata:

- the relay sees NIP-42 keys, event timing, size, public discovery records, inbox recipient tags, and opaque group capabilities;
- a KPS gateway can observe connection metadata and may weaken anonymity if it colludes with the relay;
- browser storage, extensions, copied URLs, endpoint malware, and screenshots can reveal identities or content;
- reused sender identities, relay sets, timing, writing style, and repeated browser sessions can be correlated;
- Tor and Snowflake do not protect against every global traffic-analysis adversary.

The server therefore minimizes logs, defaults to short encrypted-event retention, accepts exact-capability queries rather than enumeration, and recommends separating gateway and relay operation. The UI must not claim that a fresh key alone guarantees anonymity.

## 14. Testing Strategy

### 14.1 Protocol and crypto

- Import upstream Marmot conformance vectors at a pinned revision.
- Cross-test native Rust, browser WASM, and Node WASM serialization and state transitions.
- Test account identity proof, KeyPackage, Welcome, application-message, commit, and replay rejection paths.
- Property-test event/filter authorization and retention boundaries.

### 14.2 Relay

- Unit-test every allowed and denied filter/write shape.
- Verify NIP-42 challenge lifecycle, author binding, quotas, expiry, replaceable events, and idempotency.
- Run integration tests against a temporary SQLite database and loopback debug endpoint.
- Assert production relay startup does not bind a clearnet listener.

### 14.3 Tor transports

- Use deterministic mock transports for routine tests.
- Run gated end-to-end tests through a local Tor test network.
- Run scheduled browser tests through KPS and a disposable onion service; test Snowflake separately only when the pinned integration exposes it.
- Detect and fail any direct DNS or socket attempt outside the configured Tor transport.

### 14.4 Client and vault

- Run the same behavioral suite against memory, IndexedDB, and filesystem stores.
- Test crash consistency around every MLS state transition.
- Test passphrase encryption, wrong-password behavior, migration, corruption, and ephemeral cleanup.
- Browser-test bootstrap fragments, QR equivalence, offline assets, and accessibility.
- Snapshot CLI JSON schemas and MCP operation contracts.

### 14.5 End-to-end acceptance

The proof of concept is complete when:

1. A recipient creates a passphrase-protected vault and publishes a KeyPackage through an onion-only relay.
2. A sender opens the shared link in a supported ordinary browser, reaches the relay using embedded Arti through KPS, creates a fresh identity, and sends a message.
3. The recipient receives and replies after restarting its client.
4. Browser and `npx` clients can initiate opposite ends of the same flow.
5. An MCP client in `correspond` mode can read and reply without gaining key-export or identity-creation authority.
6. Authenticated clients cannot enumerate inboxes or group capabilities and cannot read another recipient's inbox.
7. Packet-level verification shows no production client or relay path bypassing Tor.

## 15. Repository and Delivery

The public GitHub repository will be created at `https://github.com/Epiphytic/deaddrop` with `main` as the default branch. The entire repository, including Rust crates, npm packages, browser application, documentation, and deployment adapters, is licensed under Apache License 2.0.

Initial delivery proceeds in this order:

1. Feasibility gate and pinned upstream compatibility profile.
2. Monorepo skeleton, CI, license, and protocol boundaries.
3. Native relay core, authorization, persistence, and debug mode.
4. Native Arti onion service.
5. Reduced client WASM engine and vault adapters.
6. Node CLI and complete one-to-one loopback flow.
7. Browser Arti/KPS transport and browser UI.
8. MCP surface and permission profiles.
9. End-to-end Tor verification and public proof-of-concept release.

Multi-user groups begin only after the one-to-one acceptance suite passes, but the MLS state and relay capability design intentionally avoid assumptions that would prevent that extension.

## 16. Design Decisions

- Apache-2.0 is used repository-wide to encourage protocol interoperability and reuse while retaining explicit patent terms.
- The standalone onion service ships before a Cloudflare adapter.
- The browser uses an embedded Arti/KPS path; it does not ask users to install or configure a Tor proxy.
- The CLI uses an embedded Node-capable Arti adapter and does not depend on KPS.
- All relay connections require NIP-42, including connections made with disposable identities.
- Exact random `h` values are bearer read capabilities for encrypted group events; the relay does not model MLS membership.
- The proof of concept uses reusable last-resort KeyPackages, with one-time pools deferred.
- Seven-day retention is the default, 30 days is the hard maximum, and delivery is not destructive.
- Vault passphrases are optional; ephemeral sender state can remain memory-only.
- The relay and gateway may be roles of one release binary but should not be colocated operationally.
- Multi-user groups are the first major follow-up, not part of the initial acceptance gate.

## References

- [Marmot protocol specification](https://github.com/marmot-protocol/marmot)
- [Marmot Development Kit](https://github.com/marmot-protocol/mdk)
- [Marmot TypeScript implementation](https://github.com/marmot-protocol/marmot-ts)
- [NIP-01: Basic protocol flow](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [NIP-19: bech32-encoded entities](https://github.com/nostr-protocol/nips/blob/master/19.md)
- [NIP-40: Expiration timestamp](https://github.com/nostr-protocol/nips/blob/master/40.md)
- [NIP-42: Authentication of clients to relays](https://github.com/nostr-protocol/nips/blob/master/42.md)
- [Embedding Arti in the browser](https://reads.ethereum.foundation/blog/embedding-arti-in-the-browser/)
