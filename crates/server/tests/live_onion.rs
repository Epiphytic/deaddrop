#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hypertor::{TorClient, TorWebSocket, WsMessage};
use nostr::{
    Alphabet, Event, EventBuilder, Filter, Keys, Kind, RelayUrl, SingleLetterTag, Tag, Timestamp,
};
use serde_json::{Value, json};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupRecord {
    onion_url: String,
    relay_url: String,
}

const STARTUP_TIMEOUT: Duration = Duration::from_secs(300);
const CLIENT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);
const DESCRIPTOR_TIMEOUT: Duration = Duration::from_secs(300);
const TRAFFIC_TIMEOUT: Duration = Duration::from_secs(90);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_onion_serves_http_and_restores_private_authenticated_history() -> Result<()> {
    if std::env::var("DEADDROP_LIVE_TOR").as_deref() != Ok("1") {
        eprintln!("skipped: set DEADDROP_LIVE_TOR=1 to run the live onion test");
        return Ok(());
    }

    let relay_root = tempfile::Builder::new()
        .prefix("deaddrop-relay-live-")
        .tempdir()
        .context("create private relay test directory")?;
    let client_root = tempfile::Builder::new()
        .prefix("deaddrop-client-live-")
        .tempdir()
        .context("create separate Tor client directory")?;
    let client = tokio::time::timeout(
        CLIENT_BOOTSTRAP_TIMEOUT,
        TorClient::builder()
            .state_dir(client_root.path().join("state"))
            .cache_dir(client_root.path().join("cache"))
            .build(),
    )
    .await
    .context("Tor client bootstrap exceeded its deadline")??;

    let recipient = keys(0x11);
    let other_reader = keys(0x22);
    let disposable = keys(0x33);
    let event = gift_wrap(&disposable, &recipient);

    let first_startup = {
        let mut relay = ManagedChild::spawn(relay_root.path());
        let startup = relay.read_startup()?;
        assert_canonical_urls(&startup)?;
        assert_no_listening_sockets(&mut relay)?;

        wait_for_http(&client, &startup.onion_url).await?;
        eprintln!("live onion HTTP reachability: PASS");

        let mut publisher =
            authenticated_socket(&client, &startup.relay_url, &other_reader).await?;
        publisher
            .send_text(json!(["EVENT", event.clone()]).to_string())
            .await
            .context("publish private event over Tor")?;
        let stored = recv_json(&mut publisher).await?;
        ensure!(
            stored[0] == "OK" && stored[1] == event.id.to_hex() && stored[2] == true,
            "relay did not acknowledge the private event"
        );

        assert_no_listening_sockets(&mut relay)?;
        close_socket(publisher).await?;
        relay.stop_cleanly()?;
        startup
    };

    let second_startup = {
        let mut relay = ManagedChild::spawn(relay_root.path());
        let startup = relay.read_startup()?;
        ensure!(
            startup.onion_url == first_startup.onion_url,
            "onion identity changed across restart"
        );
        ensure!(
            startup.relay_url == first_startup.relay_url,
            "relay URL changed across restart"
        );
        assert_no_listening_sockets(&mut relay)?;

        let filter = inbox_filter(&recipient);
        let mut unauthorized =
            authenticated_socket(&client, &startup.relay_url, &other_reader).await?;
        unauthorized
            .send_text(json!(["REQ", "unauthorized", filter.clone()]).to_string())
            .await
            .context("send unauthorized private query")?;
        let denied = recv_json(&mut unauthorized).await?;
        ensure!(
            denied[0] == "CLOSED"
                && denied[1] == "unauthorized"
                && denied[2]
                    .as_str()
                    .is_some_and(|reason| reason.starts_with("restricted:")),
            "private history query was not denied to the wrong reader"
        );
        close_socket(unauthorized).await?;

        let mut authorized = authenticated_socket(&client, &startup.relay_url, &recipient).await?;
        authorized
            .send_text(json!(["REQ", "history", filter]).to_string())
            .await
            .context("send authorized private query")?;
        let delivered = recv_json(&mut authorized).await?;
        ensure!(
            delivered[0] == "EVENT"
                && delivered[1] == "history"
                && delivered[2]["id"] == event.id.to_hex(),
            "authorized reader did not receive the persisted event"
        );
        ensure!(
            recv_json(&mut authorized).await? == json!(["EOSE", "history"]),
            "authorized history query did not terminate cleanly"
        );
        assert_no_listening_sockets(&mut relay)?;
        close_socket(authorized).await?;
        eprintln!("live onion authenticated WebSocket persistence: PASS");

        relay.stop_cleanly()?;
        startup
    };

    ensure!(
        second_startup.onion_url == first_startup.onion_url
            && second_startup.relay_url == first_startup.relay_url,
        "persistent identity proof was not retained"
    );
    Ok(())
}

fn keys(byte: u8) -> Keys {
    Keys::parse(&format!("{byte:02x}").repeat(32)).expect("fixed test key should be valid")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should follow the Unix epoch")
        .as_secs()
}

fn gift_wrap(disposable: &Keys, recipient: &Keys) -> Event {
    let mut payload = vec![0_u8; 99];
    payload[0] = 0x02;
    payload[1] = 0x42;
    EventBuilder::new(Kind::GiftWrap, BASE64_STANDARD.encode(payload))
        .tag(
            Tag::parse(["p", &recipient.public_key().to_hex()])
                .expect("recipient tag should be valid"),
        )
        .custom_created_at(Timestamp::from(now()))
        .sign_with_keys(disposable)
        .expect("fixed test event should sign")
}

fn inbox_filter(recipient: &Keys) -> Filter {
    Filter::new().kind(Kind::GiftWrap).custom_tag(
        SingleLetterTag::lowercase(Alphabet::P),
        recipient.public_key().to_hex(),
    )
}

fn assert_canonical_urls(startup: &StartupRecord) -> Result<()> {
    let host = startup
        .onion_url
        .strip_prefix("http://")
        .context("startup onion URL did not use http")?;
    let address = host
        .strip_suffix(".onion")
        .context("startup onion URL did not end in .onion")?;
    ensure!(
        address.len() == 56
            && address
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)),
        "startup onion URL was not a canonical v3 address"
    );
    let expected_relay = format!("ws://{host}/relay");
    ensure!(
        startup.relay_url == expected_relay,
        "startup relay URL was not canonical"
    );
    Ok(())
}

async fn wait_for_http(client: &TorClient, onion_url: &str) -> Result<()> {
    tokio::time::timeout(DESCRIPTOR_TIMEOUT, async {
        loop {
            if fetch_text(client, onion_url, "/")
                .await
                .is_ok_and(|body| body.contains("Deaddrop relay"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .context("onion descriptor did not become reachable before the deadline")?;

    let app = fetch_text(client, onion_url, "/app.js").await?;
    ensure!(
        app.contains("renderShell"),
        "embedded app.js body was unexpected"
    );
    let health = fetch_text(client, onion_url, "/health").await?;
    ensure!(health == "ok\n", "health response body was unexpected");
    Ok(())
}

async fn fetch_text(client: &TorClient, onion_url: &str, path: &str) -> Result<String> {
    let url = format!("{onion_url}{path}");
    tokio::time::timeout(TRAFFIC_TIMEOUT, async {
        client.get(&url)?.send().await?.error_for_status()?.text()
    })
    .await
    .context("onion HTTP request exceeded its deadline")?
    .map_err(Into::into)
}

async fn authenticated_socket(
    client: &TorClient,
    relay_url: &str,
    account: &Keys,
) -> Result<TorWebSocket> {
    let mut socket =
        tokio::time::timeout(TRAFFIC_TIMEOUT, TorWebSocket::connect(client, relay_url))
            .await
            .context("onion WebSocket connect exceeded its deadline")??;
    let challenge = recv_json(&mut socket).await?;
    ensure!(
        challenge[0] == "AUTH",
        "relay did not issue a NIP-42 challenge"
    );
    let challenge = challenge[1]
        .as_str()
        .context("NIP-42 challenge was not a string")?;
    let relay = RelayUrl::parse(relay_url).context("startup relay URL should parse")?;
    let auth = EventBuilder::auth(challenge, relay)
        .custom_created_at(Timestamp::from(now()))
        .sign_with_keys(account)
        .context("sign NIP-42 authentication event")?;
    socket
        .send_text(json!(["AUTH", auth]).to_string())
        .await
        .context("send NIP-42 authentication event")?;
    let accepted = recv_json(&mut socket).await?;
    ensure!(
        accepted[0] == "OK" && accepted[2] == true,
        "relay rejected NIP-42 authentication"
    );
    Ok(socket)
}

async fn recv_json(socket: &mut TorWebSocket) -> Result<Value> {
    let message = tokio::time::timeout(RESPONSE_TIMEOUT, socket.recv())
        .await
        .context("relay response exceeded its deadline")??
        .context("relay closed before sending the expected response")?;
    let WsMessage::Text(text) = message else {
        bail!("relay response was not a text frame")
    };
    serde_json::from_str(&text).context("relay response was not valid JSON")
}

async fn close_socket(socket: TorWebSocket) -> Result<()> {
    tokio::time::timeout(RESPONSE_TIMEOUT, socket.close())
        .await
        .context("WebSocket close exceeded its deadline")??;
    Ok(())
}

fn assert_no_listening_sockets(relay: &mut ManagedChild) -> Result<()> {
    relay.assert_running()?;
    let pid = relay.child.id().to_string();
    let tcp = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN"])
        .output()
        .context("lsof is required for the live onion test")?;
    require_no_lsof_rows(tcp, "TCP listener")?;

    relay.assert_running()?;
    let udp = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid, "-iUDP"])
        .output()
        .context("lsof is required for the live onion test")?;
    require_no_lsof_rows(udp, "UDP socket")?;
    relay.assert_running()
}

fn require_no_lsof_rows(output: Output, socket_kind: &str) -> Result<()> {
    ensure!(
        output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty(),
        "production relay exposed a {socket_kind} or lsof inspection failed"
    );
    Ok(())
}

struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    fn spawn(data_dir: &std::path::Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_deaddrop"))
            .args(["relay", "--data-dir"])
            .arg(data_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("production relay should start");
        Self { child }
    }

    fn read_startup(&mut self) -> Result<StartupRecord> {
        let stdout = self
            .child
            .stdout
            .take()
            .context("relay stdout was not piped")?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });

        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let line = loop {
            match receiver.try_recv() {
                Ok(result) => break result.context("read relay startup record")?,
                Err(TryRecvError::Empty) => {
                    self.assert_running()?;
                    ensure!(
                        Instant::now() < deadline,
                        "relay did not publish startup before the deadline"
                    );
                    thread::sleep(Duration::from_millis(100));
                }
                Err(TryRecvError::Disconnected) => bail!("relay startup reader disconnected"),
            }
        };
        self.assert_running()?;
        serde_json::from_str(line.trim()).context("first stdout line was not a startup record")
    }

    fn assert_running(&mut self) -> Result<()> {
        ensure!(
            self.child
                .try_wait()
                .context("read relay process status")?
                .is_none(),
            "relay exited before the live proof completed"
        );
        Ok(())
    }

    fn stop_cleanly(&mut self) -> Result<()> {
        self.assert_running()?;
        let status = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status()
            .context("send SIGINT to relay")?;
        ensure!(status.success(), "could not signal relay shutdown");

        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            match self
                .child
                .try_wait()
                .context("read relay shutdown status")?
            {
                Some(status) => {
                    ensure!(status.success(), "relay did not shut down successfully");
                    return Ok(());
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
                None => bail!("relay exceeded the SIGINT shutdown deadline"),
            }
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
