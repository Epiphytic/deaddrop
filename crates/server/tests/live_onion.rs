#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
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
const UNAUTHORIZED_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_onion_serves_http_and_restores_private_authenticated_history() -> Result<()> {
    if std::env::var("DEADDROP_LIVE_TOR").as_deref() != Ok("1") {
        eprintln!("skipped: set DEADDROP_LIVE_TOR=1 to run the live onion test");
        return Ok(());
    }

    let relay_root = private_live_tempdir("deaddrop-relay-live-")
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
        send_text_bounded(
            &mut publisher,
            json!(["EVENT", event.clone()]).to_string(),
            "private event publish",
        )
        .await?;
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
            after_onion_readiness(wait_for_http(&client, &startup.onion_url), || {
                authenticated_socket(&client, &startup.relay_url, &other_reader)
            })
            .await?;
        send_text_bounded(
            &mut unauthorized,
            json!(["REQ", "unauthorized", filter.clone()]).to_string(),
            "unauthorized private query",
        )
        .await?;
        let denied = recv_json(&mut unauthorized).await?;
        ensure!(
            denied[0] == "CLOSED"
                && denied[1] == "unauthorized"
                && denied[2]
                    .as_str()
                    .is_some_and(|reason| reason.starts_with("restricted:")),
            "private history query was not denied to the wrong reader"
        );
        let unauthorized_still_open = observe_no_subscription_event(
            &mut unauthorized,
            "unauthorized",
            UNAUTHORIZED_OBSERVATION_TIMEOUT,
        )
        .await?;
        if unauthorized_still_open {
            close_socket(unauthorized).await?;
        }

        let mut authorized = authenticated_socket(&client, &startup.relay_url, &recipient).await?;
        send_text_bounded(
            &mut authorized,
            json!(["REQ", "history", filter]).to_string(),
            "authorized private query",
        )
        .await?;
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

fn private_live_tempdir(prefix: &str) -> Result<tempfile::TempDir> {
    private_live_tempdir_in(&std::env::temp_dir(), prefix)
}

fn private_live_tempdir_in(temp_root: &std::path::Path, prefix: &str) -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;

    let canonical_root = temp_root
        .canonicalize()
        .context("resolve private temporary directory")?;
    tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(canonical_root)
        .context("create temporary directory beneath its canonical root")
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

async fn after_onion_readiness<T, R, C, F>(readiness: R, connect: C) -> Result<T>
where
    R: std::future::Future<Output = Result<()>>,
    C: FnOnce() -> F,
    F: std::future::Future<Output = Result<T>>,
{
    readiness.await?;
    connect().await
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
    send_text_bounded(
        &mut socket,
        json!(["AUTH", auth]).to_string(),
        "NIP-42 authentication send",
    )
    .await?;
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

trait MessageReceiver {
    async fn next_message(&mut self) -> Result<Option<WsMessage>>;
}

impl MessageReceiver for TorWebSocket {
    async fn next_message(&mut self) -> Result<Option<WsMessage>> {
        self.recv().await.map_err(Into::into)
    }
}

async fn send_text_bounded(socket: &mut TorWebSocket, text: String, operation: &str) -> Result<()> {
    tokio::time::timeout(RESPONSE_TIMEOUT, socket.send_text(text))
        .await
        .with_context(|| format!("{operation} exceeded its deadline"))?
        .map_err(Into::into)
}

async fn observe_no_subscription_event(
    receiver: &mut impl MessageReceiver,
    subscription_id: &str,
    interval: Duration,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + interval;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(true);
        }
        let message = match tokio::time::timeout_at(deadline, receiver.next_message()).await {
            Err(_) => return Ok(true),
            Ok(result) => result?,
        };
        let Some(message) = message else {
            return Ok(false);
        };
        match message {
            WsMessage::Close(_) => return Ok(false),
            WsMessage::Binary(_) => {
                bail!("relay sent a binary frame during negative observation")
            }
            WsMessage::Text(text) => {
                let message: Value = serde_json::from_str(&text)
                    .context("relay sent invalid JSON during negative observation")?;
                let fields = message
                    .as_array()
                    .context("relay sent a non-array message during negative observation")?;
                let message_type = fields
                    .first()
                    .and_then(Value::as_str)
                    .context("relay message type was missing during negative observation")?;
                if message_type == "EVENT" {
                    let delivered_subscription = fields
                        .get(1)
                        .and_then(Value::as_str)
                        .context("relay EVENT omitted its subscription ID")?;
                    ensure!(
                        delivered_subscription != subscription_id,
                        "relay leaked an unauthorized EVENT after closing the subscription"
                    );
                }
            }
            _ => bail!("relay sent an unsupported frame during negative observation"),
        }
    }
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
    let mut tcp = Command::new("lsof");
    tcp.args(["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN"]);
    let tcp = run_bounded_command(tcp, SUBPROCESS_TIMEOUT)
        .context("TCP lsof inspection could not run")?;
    ensure!(!tcp.timed_out, "TCP lsof inspection exceeded its deadline");
    require_no_lsof_rows(tcp.output, "TCP listener")?;

    relay.assert_running()?;
    let mut udp = Command::new("lsof");
    udp.args(["-nP", "-a", "-p", &pid, "-iUDP"]);
    let udp = run_bounded_command(udp, SUBPROCESS_TIMEOUT)
        .context("UDP lsof inspection could not run")?;
    ensure!(!udp.timed_out, "UDP lsof inspection exceeded its deadline");
    require_no_lsof_rows(udp.output, "UDP socket")?;
    relay.assert_running()
}

struct BoundedCommandOutput {
    output: Output,
    timed_out: bool,
}

fn run_bounded_command(mut command: Command, timeout: Duration) -> Result<BoundedCommandOutput> {
    let mut stdout_file = tempfile::tempfile().context("create subprocess stdout capture")?;
    let mut stderr_file = tempfile::tempfile().context("create subprocess stderr capture")?;
    command.stdout(Stdio::from(
        stdout_file
            .try_clone()
            .context("clone subprocess stdout capture")?,
    ));
    command.stderr(Stdio::from(
        stderr_file
            .try_clone()
            .context("clone subprocess stderr capture")?,
    ));
    let mut child = command.spawn().context("spawn bounded subprocess")?;
    let deadline = Instant::now() + timeout;

    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(SUBPROCESS_POLL_INTERVAL.min(timeout));
            }
            Ok(None) => {
                let kill_result = child.kill();
                let wait_result = child.wait();
                kill_result.context("kill subprocess after its deadline")?;
                let status = wait_result.context("reap subprocess after its deadline")?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("poll bounded subprocess");
            }
        }
    };

    stdout_file
        .seek(SeekFrom::Start(0))
        .context("rewind subprocess stdout")?;
    stderr_file
        .seek(SeekFrom::Start(0))
        .context("rewind subprocess stderr")?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    stdout_file
        .read_to_end(&mut stdout)
        .context("read subprocess stdout")?;
    stderr_file
        .read_to_end(&mut stderr)
        .context("read subprocess stderr")?;

    Ok(BoundedCommandOutput {
        output: Output {
            status,
            stdout,
            stderr,
        },
        timed_out,
    })
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
        let mut signal = Command::new("kill");
        signal.args(["-INT", &self.child.id().to_string()]);
        let signal =
            run_bounded_command(signal, SUBPROCESS_TIMEOUT).context("run relay SIGINT command")?;
        ensure!(
            !signal.timed_out,
            "relay SIGINT command exceeded its deadline"
        );
        ensure!(
            signal.output.status.success(),
            "could not signal relay shutdown"
        );

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

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::{collections::VecDeque, fs};

    use super::*;

    enum SyntheticReceive {
        Message(WsMessage),
        Error,
        Stall,
    }

    struct SyntheticReceiver {
        receives: VecDeque<SyntheticReceive>,
    }

    impl SyntheticReceiver {
        fn new(receives: impl IntoIterator<Item = SyntheticReceive>) -> Self {
            Self {
                receives: receives.into_iter().collect(),
            }
        }
    }

    impl MessageReceiver for SyntheticReceiver {
        async fn next_message(&mut self) -> Result<Option<WsMessage>> {
            match self.receives.pop_front().unwrap_or(SyntheticReceive::Stall) {
                SyntheticReceive::Message(message) => Ok(Some(message)),
                SyntheticReceive::Error => bail!("synthetic receive failure"),
                SyntheticReceive::Stall => pending().await,
            }
        }
    }

    #[test]
    fn live_fixture_resolves_a_macos_style_symlinked_temp_root() {
        use std::os::unix::fs::symlink;

        let safe_root = std::env::current_dir().unwrap().canonicalize().unwrap();
        let sandbox = tempfile::Builder::new()
            .prefix("deaddrop-live-path-test-")
            .tempdir_in(safe_root)
            .unwrap();
        let private_var = sandbox.path().join("private/var");
        let canonical_temp_root = private_var.join("folders");
        fs::create_dir_all(&canonical_temp_root).unwrap();
        symlink("private/var", sandbox.path().join("var")).unwrap();
        let macos_temp_root = sandbox.path().join("var/folders");

        let fixture = private_live_tempdir_in(&macos_temp_root, "deaddrop-relay-live-").unwrap();

        assert!(fixture.path().starts_with(&canonical_temp_root));
        let mut component_path = std::path::PathBuf::new();
        for component in fixture.path().components() {
            component_path.push(component.as_os_str());
            assert!(
                !fs::symlink_metadata(&component_path)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "fixture retained symlinked component {}",
                component_path.display()
            );
        }
        deaddrop_server::state::StateDirectory::acquire(fixture.path())
            .expect("production state validation must accept the live fixture path");
    }

    #[tokio::test]
    async fn restarted_websocket_connection_waits_for_http_readiness() {
        let (release_readiness, readiness) = tokio::sync::oneshot::channel();
        let connection_started = std::cell::Cell::new(false);
        let started = &connection_started;
        let mut connection = Box::pin(after_onion_readiness(
            async move {
                readiness.await.unwrap();
                Ok(())
            },
            move || async move {
                started.set(true);
                Ok::<_, anyhow::Error>("connected")
            },
        ));

        assert!(futures::poll!(&mut connection).is_pending());
        assert!(!connection_started.get());

        release_readiness.send(()).unwrap();
        assert_eq!(connection.await.unwrap(), "connected");
        assert!(connection_started.get());
    }

    #[tokio::test]
    async fn negative_observation_rejects_an_event_after_closed() {
        let mut receiver = SyntheticReceiver::new([
            SyntheticReceive::Message(WsMessage::Text(
                json!(["NOTICE", "control traffic"]).to_string(),
            )),
            SyntheticReceive::Message(WsMessage::Text(
                json!(["EVENT", "private-history", {}]).to_string(),
            )),
        ]);

        let error =
            observe_no_subscription_event(&mut receiver, "private-history", Duration::from_secs(1))
                .await
                .unwrap_err();

        assert!(error.to_string().contains("unauthorized EVENT"));
    }

    #[tokio::test]
    async fn negative_observation_handles_control_close_and_receive_errors() {
        let mut closed = SyntheticReceiver::new([
            SyntheticReceive::Message(WsMessage::Text(
                json!(["NOTICE", "control traffic"]).to_string(),
            )),
            SyntheticReceive::Message(WsMessage::Close(None)),
        ]);
        assert!(
            !observe_no_subscription_event(&mut closed, "private-history", Duration::from_secs(1))
                .await
                .unwrap()
        );

        let mut failed = SyntheticReceiver::new([SyntheticReceive::Error]);
        let error =
            observe_no_subscription_event(&mut failed, "private-history", Duration::from_secs(1))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("synthetic receive failure"));

        let mut binary =
            SyntheticReceiver::new([SyntheticReceive::Message(WsMessage::Binary(vec![0x01]))]);
        let error =
            observe_no_subscription_event(&mut binary, "private-history", Duration::from_secs(1))
                .await
                .unwrap_err();
        assert!(error.to_string().contains("binary"));
    }

    #[tokio::test]
    async fn negative_observation_waits_for_its_fixed_interval() {
        let mut receiver = SyntheticReceiver::new([]);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                observe_no_subscription_event(
                    &mut receiver,
                    "private-history",
                    Duration::from_millis(100),
                ),
            )
            .await
            .is_err()
        );

        let mut receiver = SyntheticReceiver::new([]);
        tokio::time::timeout(
            Duration::from_millis(200),
            observe_no_subscription_event(
                &mut receiver,
                "private-history",
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("negative observation ignored its deadline")
        .unwrap();
    }

    #[test]
    fn bounded_subprocess_preserves_status_stdout_and_stderr() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf 'bounded stdout'; printf 'bounded stderr' >&2; exit 7",
        ]);

        let result = run_bounded_command(command, Duration::from_secs(1)).unwrap();

        assert!(!result.timed_out);
        assert_eq!(result.output.status.code(), Some(7));
        assert_eq!(result.output.stdout, b"bounded stdout");
        assert_eq!(result.output.stderr, b"bounded stderr");
    }

    #[test]
    fn bounded_subprocess_kills_and_reaps_a_stalled_child() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf 'started'; printf 'stalled' >&2; exec sleep 30",
        ]);
        let started = Instant::now();

        let result = run_bounded_command(command, Duration::from_millis(50)).unwrap();

        assert!(result.timed_out);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(result.output.stdout, b"started");
        assert_eq!(result.output.stderr, b"stalled");
    }
}
