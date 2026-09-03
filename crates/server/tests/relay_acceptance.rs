use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use deaddrop_relay_sqlite::SqliteStore;
use deaddrop_server::{config::DebugConfig, debug::DebugServer};
use futures::{SinkExt, StreamExt};
use nostr::{
    Alphabet, Event, EventBuilder, Filter, Keys, Kind, RelayUrl, SingleLetterTag, Tag, Timestamp,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::timeout;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

const GROUP_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GROUP_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Peer {
    socket: Socket,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn keys(byte: u8) -> Keys {
    Keys::parse(&format!("{byte:02x}").repeat(32)).unwrap()
}

fn tag(values: &[&str]) -> Tag {
    Tag::parse(values.iter().copied()).unwrap()
}

fn config(temp: &TempDir) -> DebugConfig {
    DebugConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        data_dir: temp.path().join("state"),
        unsafe_debug_bind: false,
    }
}

fn inbox_filter(account: &Keys) -> Filter {
    Filter::new().kind(Kind::GiftWrap).custom_tag(
        SingleLetterTag::lowercase(Alphabet::P),
        account.public_key().to_hex(),
    )
}

fn group_filter(route: &str) -> Filter {
    Filter::new()
        .kind(Kind::MlsGroupMessage)
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), route)
}

fn gift_wrap(disposable: &Keys, recipient: &Keys, marker: u8, expires: Option<u64>) -> Event {
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    payload[1] = marker;
    let mut tags = vec![tag(&["p", &recipient.public_key().to_hex()])];
    if let Some(expiration) = expires {
        tags.push(tag(&["expiration", &expiration.to_string()]));
    }
    EventBuilder::new(Kind::GiftWrap, BASE64_STANDARD.encode(payload))
        .tags(tags)
        .custom_created_at(Timestamp::from(now()))
        .sign_with_keys(disposable)
        .unwrap()
}

fn group_message(disposable: &Keys, route: &str, marker: u8) -> Event {
    let mut payload = [0_u8; 28];
    payload[0] = marker;
    EventBuilder::new(Kind::MlsGroupMessage, BASE64_STANDARD.encode(payload))
        .tag(tag(&["h", route]))
        .custom_created_at(Timestamp::from(now()))
        .sign_with_keys(disposable)
        .unwrap()
}

fn key_package(author: &Keys, created_at: u64, d: &str, marker: u8) -> Event {
    EventBuilder::new(Kind::Custom(30_443), BASE64_STANDARD.encode([marker]))
        .tags([
            tag(&["d", d]),
            tag(&["mls_protocol_version", "1.0"]),
            tag(&["i", &format!("{marker:02x}").repeat(32)]),
            tag(&["mls_ciphersuite", "0x0001"]),
            tag(&["mls_extensions", "0x0001"]),
            tag(&["mls_proposals", "0x0002"]),
            tag(&["app_components", "0xf001"]),
        ])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(author)
        .unwrap()
}

impl Peer {
    async fn authenticated(server: &DebugServer, account: &Keys) -> Self {
        let relay = RelayUrl::parse(&format!("ws://{}", server.bound_addr())).unwrap();
        let (socket, _) = timeout(Duration::from_secs(2), connect_async(relay.as_str()))
            .await
            .expect("connect timed out")
            .unwrap();
        let mut peer = Self { socket };
        let challenge = peer.recv().await;
        assert_eq!(challenge[0], "AUTH");
        let auth = EventBuilder::auth(challenge[1].as_str().unwrap(), relay)
            .custom_created_at(Timestamp::from(now()))
            .sign_with_keys(account)
            .unwrap();
        peer.send(json!(["AUTH", auth])).await;
        let accepted = peer.recv().await;
        assert_eq!(accepted[0], "OK");
        assert_eq!(accepted[2], true);
        peer
    }

    async fn send(&mut self, value: Value) {
        timeout(
            Duration::from_secs(2),
            self.socket.send(Message::Text(value.to_string().into())),
        )
        .await
        .expect("send timed out")
        .unwrap();
    }

    async fn recv(&mut self) -> Value {
        let message = timeout(Duration::from_secs(2), self.socket.next())
            .await
            .expect("receive timed out")
            .expect("relay closed early")
            .expect("websocket error");
        serde_json::from_str(message.to_text().expect("relay frame must be text")).unwrap()
    }

    async fn publish(&mut self, event: &Event, expected: bool) -> Value {
        self.send(json!(["EVENT", event])).await;
        let response = self.recv().await;
        assert_eq!(response[0], "OK");
        assert_eq!(response[1], event.id.to_hex());
        assert_eq!(response[2], expected);
        response
    }

    async fn subscribe_empty(&mut self, id: &str, filter: Filter) {
        self.send(json!(["REQ", id, filter])).await;
        assert_eq!(self.recv().await, json!(["EOSE", id]));
    }

    async fn expect_event(&mut self, id: &str, expected: &Event) {
        let response = self.recv().await;
        assert_eq!(response[0], "EVENT");
        assert_eq!(response[1], id);
        assert_eq!(response[2]["id"], expected.id.to_hex());
    }

    async fn snapshot(&mut self, id: &str, filter: Filter) -> Vec<Event> {
        self.send(json!(["REQ", id, filter])).await;
        let mut events = Vec::new();
        loop {
            let response = self.recv().await;
            match response[0].as_str() {
                Some("EVENT") => {
                    assert_eq!(response[1], id);
                    events.push(serde_json::from_value(response[2].clone()).unwrap());
                }
                Some("EOSE") => {
                    assert_eq!(response[1], id);
                    return events;
                }
                other => panic!("unexpected snapshot response {other:?}: {response}"),
            }
        }
    }

    async fn expect_closed(&mut self, id: &str, filter: Value) {
        self.send(json!(["REQ", id, filter])).await;
        let response = self.recv().await;
        assert_eq!(response[0], "CLOSED");
        assert_eq!(response[1], id);
    }
}

fn physical_count(path: &std::path::Path, event: &Event) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE id = ?1",
            [event.id.to_hex()],
            |row| row.get(0),
        )
        .unwrap()
}

fn metadata(author: &Keys, created_at: u64, content: &str) -> Event {
    EventBuilder::new(Kind::Metadata, content)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(author)
        .unwrap()
}

#[tokio::test]
async fn disposable_sender_routes_inbox_only_to_the_authenticated_recipient() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("state/relay.sqlite3");
    let server = DebugServer::start(config(&temp)).await.unwrap();
    let alice = keys(0x11);
    let bob = keys(0x22);
    let disposable = keys(0x33);

    let mut alice_live = Peer::authenticated(&server, &alice).await;
    let mut bob_live = Peer::authenticated(&server, &bob).await;
    let mut publisher = Peer::authenticated(&server, &bob).await;
    alice_live
        .subscribe_empty("alice-live", inbox_filter(&alice))
        .await;
    bob_live
        .subscribe_empty("bob-live", inbox_filter(&bob))
        .await;

    let to_alice = gift_wrap(&disposable, &alice, 1, None);
    publisher.publish(&to_alice, true).await;
    assert_eq!(physical_count(&database, &to_alice), 1);
    alice_live.expect_event("alice-live", &to_alice).await;

    let to_bob = gift_wrap(&disposable, &bob, 2, None);
    publisher.publish(&to_bob, true).await;
    assert_eq!(physical_count(&database, &to_bob), 1);
    bob_live.expect_event("bob-live", &to_bob).await;

    let mut alice_history = Peer::authenticated(&server, &alice).await;
    let alice_events = alice_history
        .snapshot("alice-history", inbox_filter(&alice))
        .await;
    assert_eq!(
        alice_events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>(),
        vec![to_alice.id]
    );

    let mut bob_history = Peer::authenticated(&server, &bob).await;
    bob_history
        .expect_closed("alice-is-private", json!(inbox_filter(&alice)))
        .await;
    let bob_events = bob_history
        .snapshot("bob-history", inbox_filter(&bob))
        .await;
    assert_eq!(
        bob_events.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![to_bob.id]
    );

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn group_capabilities_are_exact_and_encrypted_outer_authors_may_be_ephemeral() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("state/relay.sqlite3");
    let server = DebugServer::start(config(&temp)).await.unwrap();
    let alice = keys(0x11);
    let bob = keys(0x22);
    let disposable = keys(0x33);

    let mut exact_live = Peer::authenticated(&server, &alice).await;
    let mut other_live = Peer::authenticated(&server, &bob).await;
    let mut publisher = Peer::authenticated(&server, &bob).await;
    exact_live
        .subscribe_empty("group-a-live", group_filter(GROUP_A))
        .await;
    other_live
        .subscribe_empty("group-b-live", group_filter(GROUP_B))
        .await;

    let target = group_message(&disposable, GROUP_A, 1);
    publisher.publish(&target, true).await;
    assert_eq!(physical_count(&database, &target), 1);
    exact_live.expect_event("group-a-live", &target).await;

    let control = group_message(&disposable, GROUP_B, 2);
    publisher.publish(&control, true).await;
    assert_eq!(physical_count(&database, &control), 1);
    other_live.expect_event("group-b-live", &control).await;

    let mut exact_history = Peer::authenticated(&server, &alice).await;
    let exact = exact_history
        .snapshot("group-a-history", group_filter(GROUP_A))
        .await;
    assert_eq!(
        exact.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![target.id]
    );

    let mut wrong_history = Peer::authenticated(&server, &alice).await;
    let wrong = wrong_history
        .snapshot("wrong-valid-capability", group_filter(GROUP_B))
        .await;
    assert_eq!(
        wrong.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![control.id]
    );
    assert!(!wrong.iter().any(|event| event.id == target.id));

    let invalid_filters = [
        json!({"kinds": [445]}),
        json!({"kinds": [445], "#h": [GROUP_A, GROUP_B]}),
        json!({"kinds": [445], "#h": [&GROUP_A[..32]]}),
        json!({"kinds": [445], "#h": [GROUP_A.to_uppercase()]}),
        json!({"kinds": [445], "#h": ["zz"]}),
    ];
    for (index, filter) in invalid_filters.into_iter().enumerate() {
        wrong_history
            .expect_closed(&format!("invalid-h-{index}"), filter)
            .await;
    }

    let mismatch_metadata = EventBuilder::new(Kind::Metadata, "mismatch")
        .custom_created_at(Timestamp::from(now()))
        .sign_with_keys(&disposable)
        .unwrap();
    publisher.publish(&mismatch_metadata, false).await;
    assert_eq!(physical_count(&database, &mismatch_metadata), 0);
    let mismatch_key_package = key_package(&disposable, now(), "mismatch", 7);
    publisher.publish(&mismatch_key_package, false).await;
    assert_eq!(physical_count(&database, &mismatch_key_package), 0);

    let mismatch_gift = gift_wrap(&disposable, &alice, 9, None);
    publisher.publish(&mismatch_gift, true).await;
    assert_eq!(physical_count(&database, &mismatch_gift), 1);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_preserves_replacement_and_dedup_then_compacts_expiration() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("state/relay.sqlite3");
    let alice = keys(0x11);
    let disposable = keys(0x33);
    let base = now();
    let old_metadata = metadata(&alice, base - 2, "old-profile");
    let new_metadata = metadata(&alice, base - 1, "new-profile");
    let old_package = key_package(&alice, base - 2, "drop", 1);
    let new_package = key_package(&alice, base - 1, "drop", 2);
    let sentinel_package = key_package(&alice, base, "sentinel", 3);

    let server = DebugServer::start(config(&temp)).await.unwrap();
    let mut publisher = Peer::authenticated(&server, &alice).await;
    let mut package_live = Peer::authenticated(&server, &alice).await;
    package_live
        .subscribe_empty("package-live", Filter::new().kind(Kind::Custom(30_443)))
        .await;
    publisher.publish(&old_metadata, true).await;
    assert_eq!(physical_count(&database, &old_metadata), 1);
    publisher.publish(&new_metadata, true).await;
    let duplicate = publisher.publish(&new_metadata, true).await;
    assert!(duplicate[3].as_str().unwrap().starts_with("duplicate:"));
    publisher.publish(&old_package, true).await;
    assert_eq!(physical_count(&database, &old_package), 1);
    package_live
        .expect_event("package-live", &old_package)
        .await;
    publisher.publish(&new_package, true).await;
    package_live
        .expect_event("package-live", &new_package)
        .await;
    let duplicate = publisher.publish(&new_package, true).await;
    assert!(duplicate[3].as_str().unwrap().starts_with("duplicate:"));
    publisher.publish(&sentinel_package, true).await;
    package_live
        .expect_event("package-live", &sentinel_package)
        .await;
    let expiration = now() + 60;
    let expiring = gift_wrap(&disposable, &alice, 8, Some(expiration));
    publisher.publish(&expiring, true).await;

    assert_eq!(physical_count(&database, &old_metadata), 0);
    assert_eq!(physical_count(&database, &new_metadata), 1);
    assert_eq!(physical_count(&database, &old_package), 0);
    assert_eq!(physical_count(&database, &new_package), 1);
    assert_eq!(physical_count(&database, &sentinel_package), 1);
    assert_eq!(physical_count(&database, &expiring), 1);
    server.shutdown().await.unwrap();

    let store = SqliteStore::open(&database, 4).await.unwrap();
    assert_eq!(store.compact(expiration).await.unwrap(), 1);
    assert_eq!(physical_count(&database, &expiring), 0);
    store.shutdown().await.unwrap();

    let restarted = DebugServer::start(config(&temp)).await.unwrap();

    let mut history = Peer::authenticated(&restarted, &alice).await;
    let profiles = history
        .snapshot(
            "profiles-after-restart",
            Filter::new()
                .kind(Kind::Metadata)
                .author(alice.public_key()),
        )
        .await;
    assert_eq!(profiles, vec![new_metadata.clone()]);
    let packages = history
        .snapshot(
            "packages-after-restart",
            Filter::new()
                .kind(Kind::Custom(30_443))
                .author(alice.public_key()),
        )
        .await;
    assert_eq!(
        packages
            .iter()
            .map(|event| event.id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([new_package.id, sentinel_package.id])
    );
    let inbox = history
        .snapshot("expired-inbox", inbox_filter(&alice))
        .await;
    assert!(inbox.is_empty());

    let duplicate = history.publish(&new_metadata, true).await;
    assert!(duplicate[3].as_str().unwrap().starts_with("duplicate:"));
    assert_eq!(physical_count(&database, &new_metadata), 1);
    restarted.shutdown().await.unwrap();
}
