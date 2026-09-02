use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::RecvTimeoutError,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use deaddrop_protocol_core::validate_write;
use deaddrop_relay_core::{Clock, Store};
use deaddrop_relay_sqlite::SqliteStore;
use deaddrop_server::{
    config::DebugConfig, debug::DebugServer, maintenance::run_maintenance,
    shutdown::shutdown_channel,
};
use futures::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, Filter, Keys, Kind, RelayUrl, Tag, Timestamp};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{io::AsyncReadExt, task::JoinHandle, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, protocol::frame::coding::CloseCode},
};

type Client = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn unix_now() -> u64 {
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

async fn connect(server: &DebugServer) -> (Client, RelayUrl) {
    let relay = RelayUrl::parse(&format!("ws://{}", server.bound_addr())).unwrap();
    let (client, _) = connect_async(relay.as_str()).await.unwrap();
    (client, relay)
}

async fn recv_json(client: &mut Client) -> Value {
    let message = timeout(Duration::from_secs(2), client.next())
        .await
        .expect("relay response timed out")
        .expect("relay closed before response")
        .expect("websocket error");
    serde_json::from_str(message.to_text().expect("expected text frame")).unwrap()
}

async fn authenticate(client: &mut Client, relay: &RelayUrl, account: &Keys) {
    let challenge_message = recv_json(client).await;
    assert_eq!(challenge_message[0], "AUTH");
    let challenge = challenge_message[1]
        .as_str()
        .expect("AUTH challenge must be a string");
    let event = EventBuilder::auth(challenge, relay.clone())
        .custom_created_at(Timestamp::from(unix_now()))
        .sign_with_keys(account)
        .unwrap();
    client
        .send(Message::Text(json!(["AUTH", event]).to_string().into()))
        .await
        .unwrap();
    let response = recv_json(client).await;
    assert_eq!(response[0], "OK");
    assert_eq!(response[2], true);
}

async fn subscribe_to_profiles(client: &mut Client) {
    client
        .send(Message::Text(
            json!(["REQ", "profiles", Filter::new().kind(Kind::Metadata)])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let response = recv_json(client).await;
    assert_eq!(response, json!(["EOSE", "profiles"]));
}

#[tokio::test]
async fn challenges_first_and_finishes_accepted_publish_after_sender_disconnect() {
    let temp = TempDir::new().unwrap();
    let server = DebugServer::start(config(&temp)).await.unwrap();

    let (mut recipient, recipient_relay) = connect(&server).await;
    authenticate(&mut recipient, &recipient_relay, &keys(0x22)).await;
    subscribe_to_profiles(&mut recipient).await;

    let (mut sender, sender_relay) = connect(&server).await;
    let sender_keys = keys(0x11);
    authenticate(&mut sender, &sender_relay, &sender_keys).await;
    let content = "private-message-content-must-not-enter-logs";
    let event = EventBuilder::new(Kind::Metadata, content)
        .custom_created_at(Timestamp::from(unix_now()))
        .sign_with_keys(&sender_keys)
        .unwrap();
    sender
        .send(Message::Text(json!(["EVENT", event]).to_string().into()))
        .await
        .unwrap();
    sender.close(None).await.unwrap();

    let delivered = recv_json(&mut recipient).await;
    assert_eq!(delivered[0], "EVENT");
    assert_eq!(delivered[1], "profiles");
    assert_eq!(delivered[2]["content"], content);

    server.shutdown().await.unwrap();
    let terminal = timeout(Duration::from_secs(2), recipient.next()).await;
    assert!(
        terminal.is_ok(),
        "global shutdown must promptly close clients"
    );
}

async fn expect_policy_close(mut client: Client) {
    let response = timeout(Duration::from_secs(2), client.next())
        .await
        .expect("policy close timed out")
        .expect("server must send a close frame")
        .expect("websocket close should not be an I/O error");
    let Message::Close(Some(frame)) = response else {
        panic!("expected close frame, got {response:?}")
    };
    assert_eq!(frame.code, CloseCode::Policy);
}

#[tokio::test]
async fn rejects_binary_and_oversized_frames_with_policy_close() {
    let temp = TempDir::new().unwrap();
    let server = DebugServer::start(config(&temp)).await.unwrap();

    let (mut binary, _) = connect(&server).await;
    let _challenge = recv_json(&mut binary).await;
    binary
        .send(Message::Binary(vec![0_u8; 8].into()))
        .await
        .unwrap();
    expect_policy_close(binary).await;

    let (mut oversized, _) = connect(&server).await;
    let _challenge = recv_json(&mut oversized).await;
    oversized
        .send(Message::Text("x".repeat(70 * 1024).into()))
        .await
        .unwrap();
    expect_policy_close(oversized).await;

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn challenge_precedes_a_pipelined_client_request() {
    let temp = TempDir::new().unwrap();
    let server = DebugServer::start(config(&temp)).await.unwrap();
    let (mut client, _) = connect(&server).await;
    client
        .send(Message::Text(
            json!(["REQ", "early", Filter::new().kind(Kind::Metadata)])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

    assert_eq!(recv_json(&mut client).await[0], "AUTH");
    let rejected = recv_json(&mut client).await;
    assert_eq!(rejected[0], "CLOSED");
    assert_eq!(rejected[1], "early");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsafe_wildcard_auth_uses_the_accepted_concrete_local_address() {
    let temp = TempDir::new().unwrap();
    let mut wildcard = config(&temp);
    wildcard.bind = "0.0.0.0:0".parse().unwrap();
    wildcard.unsafe_debug_bind = true;
    let server = DebugServer::start(wildcard).await.unwrap();
    let relay = RelayUrl::parse(&format!("ws://127.0.0.1:{}", server.bound_addr().port())).unwrap();
    let (mut client, _) = connect_async(relay.as_str()).await.unwrap();
    authenticate(&mut client, &relay, &keys(0x18)).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn incomplete_handshakes_have_bounded_connection_admission() {
    const CONNECTION_LIMIT: usize = 32;
    let temp = TempDir::new().unwrap();
    let server = DebugServer::start(config(&temp)).await.unwrap();
    let mut clients = Vec::new();
    for _ in 0..=CONNECTION_LIMIT {
        clients.push(
            tokio::net::TcpStream::connect(server.bound_addr())
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut byte = [0_u8; 1];
    assert_eq!(
        timeout(
            Duration::from_millis(500),
            clients.last_mut().unwrap().read(&mut byte)
        )
        .await
        .expect("excess connection was not rejected")
        .unwrap(),
        0,
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_interrupts_an_incomplete_websocket_handshake() {
    let temp = TempDir::new().unwrap();
    let server = DebugServer::start(config(&temp)).await.unwrap();
    let _half_open = tokio::net::TcpStream::connect(server.bound_addr())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    timeout(Duration::from_millis(500), server.shutdown())
        .await
        .expect("shutdown must not wait forever for a WebSocket handshake")
        .unwrap();
}

#[tokio::test]
async fn cli_reports_actual_bind_and_structured_logs_redact_wire_data() {
    let temp = TempDir::new().unwrap();
    let secret_content = "secret-event-content-7f51";
    let secret_h = "a9".repeat(32);
    let mut child = Command::new(env!("CARGO_BIN_EXE_deaddrop"))
        .args([
            "debug",
            "--bind",
            "127.0.0.1:0",
            "--data-dir",
            temp.path().join("state").to_str().unwrap(),
            "--unsafe-debug-bind",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "trace")
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (line_sender, line_receiver) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if line_sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let mut startup = String::new();
    let bound_addr = loop {
        let line = match line_receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("server did not report readiness within five seconds");
            }
            Err(RecvTimeoutError::Disconnected) => {
                let _ = child.wait();
                panic!("server exited before binding");
            }
        };
        startup.push_str(&line);
        startup.push('\n');
        let value: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("logs must be JSON objects: {error}: {line:?}"));
        if value["fields"]["event"] == "debug_listener_started" {
            break value["fields"]["bind"]
                .as_str()
                .unwrap()
                .parse::<SocketAddr>()
                .unwrap();
        }
    };
    assert_ne!(
        bound_addr.port(),
        0,
        "log must report the actual bound port"
    );
    assert!(startup.contains("unsafe_debug_bind"));

    let url = format!("ws://{bound_addr}");
    let (mut client, _) = connect_async(&url).await.unwrap();
    let challenge_message = recv_json(&mut client).await;
    let challenge = challenge_message[1].as_str().unwrap().to_owned();
    client
        .send(Message::Text(
            json!(["PRIVATE-WIRE-NAME", {"content": secret_content, "h": secret_h}])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    expect_policy_close(client).await;

    child.kill().unwrap();
    child.wait().unwrap();
    reader.join().unwrap();
    let remainder = line_receiver.try_iter().collect::<Vec<_>>().join("\n");
    let logs = startup + &remainder;
    assert!(!logs.contains(secret_content));
    assert!(!logs.contains(&secret_h));
    assert!(!logs.contains(&challenge));
    for line in logs.lines().filter(|line| !line.is_empty()) {
        serde_json::from_str::<Value>(line).expect("every diagnostic line must be structured JSON");
    }
}

#[derive(Clone)]
struct FakeClock(Arc<AtomicU64>);

impl Clock for FakeClock {
    fn now_seconds(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

fn expiring_inbox(now: u64, recipient: &Keys, disposable: &Keys) -> Event {
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    EventBuilder::new(Kind::GiftWrap, BASE64_STANDARD.encode(payload))
        .tags([
            tag(&["p", &recipient.public_key().to_hex()]),
            tag(&["expiration", &(now + 2).to_string()]),
        ])
        .custom_created_at(Timestamp::from(now))
        .sign_with_keys(disposable)
        .unwrap()
}

#[tokio::test]
async fn maintenance_uses_injected_clock_and_physically_deletes_expired_rows() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("state").join("relay.sqlite3");
    let now = 1_700_000_000;
    let store = SqliteStore::open(&path, 8).await.unwrap();
    let recipient = keys(0x33);
    let event = expiring_inbox(now, &recipient, &keys(0x44));
    let validated = validate_write(
        &BTreeSet::from([recipient.public_key()]),
        now,
        event.clone(),
    )
    .unwrap();
    store.put(validated).await.unwrap();
    assert_eq!(physical_event_count(&path), 1);

    let clock = FakeClock(Arc::new(AtomicU64::new(now)));
    let (shutdown, signal) = shutdown_channel();
    let task: JoinHandle<Result<(), deaddrop_relay_sqlite::Error>> = tokio::spawn(run_maintenance(
        store.clone(),
        clock.clone(),
        Duration::from_millis(10),
        signal,
    ));
    clock.0.store(now + 3, Ordering::Release);

    timeout(Duration::from_secs(2), async {
        loop {
            if physical_event_count(&path) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("maintenance never physically compacted the row");

    shutdown.trigger();
    task.await.unwrap().unwrap();
    store.shutdown().await.unwrap();
}

fn physical_event_count(path: &std::path::Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap()
}
