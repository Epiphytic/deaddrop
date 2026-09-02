use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use deaddrop_relay_core::{
    ChallengeSource, Clock, RelayHub, Session, SessionLimits, SessionOutput, WireLimits,
    parse_client_message,
};
use deaddrop_relay_sqlite::SqliteStore;
use futures::{SinkExt, StreamExt};
use nostr::{JsonUtil, RelayUrl};
use tokio::{
    net::TcpStream,
    time::{Instant, MissedTickBehavior, interval, sleep_until, timeout},
};
use tokio_tungstenite::{
    accept_async_with_config,
    tungstenite::{
        Error as WebSocketError, Message,
        protocol::{CloseFrame, Role, WebSocketConfig, frame::coding::CloseCode},
    },
};

use crate::{runtime::TaskSubmitter, shutdown::ShutdownSignal};

pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

struct OsChallengeSource;

impl ChallengeSource for OsChallengeSource {
    fn fill(&mut self, output: &mut [u8]) {
        getrandom::fill(output).expect("operating system randomness unavailable");
    }
}

pub(crate) async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    shutdown: ShutdownSignal,
) {
    if let Err(error) = run_connection(stream, relay_url, hub, tasks, shutdown).await {
        tracing::debug!(
            event = "debug_connection_ended",
            peer = %peer,
            reason = error.category(),
        );
    } else {
        tracing::debug!(event = "debug_connection_ended", peer = %peer, reason = "closed");
    }
}

#[derive(Debug)]
pub(crate) enum ConnectionError {
    WebSocket,
    HandshakeTimeout,
    WriteTimeout,
    Invariant,
}

impl ConnectionError {
    fn category(&self) -> &'static str {
        match self {
            Self::WebSocket => "websocket",
            Self::HandshakeTimeout => "handshake-timeout",
            Self::WriteTimeout => "write-timeout",
            Self::Invariant => "relay-invariant",
        }
    }
}

impl From<WebSocketError> for ConnectionError {
    fn from(_error: WebSocketError) -> Self {
        Self::WebSocket
    }
}

async fn run_connection(
    stream: TcpStream,
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    mut shutdown: ShutdownSignal,
) -> Result<(), ConnectionError> {
    let websocket = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Ok(()),
        accepted = timeout(
            HANDSHAKE_TIMEOUT,
            accept_async_with_config(stream, Some(websocket_config())),
        ) => accepted.map_err(|_| ConnectionError::HandshakeTimeout)??,
    };
    drive_websocket(websocket, relay_url, hub, tasks, shutdown, WRITE_TIMEOUT).await
}

pub(crate) async fn serve_websocket<S>(
    stream: S,
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    shutdown: ShutdownSignal,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    serve_websocket_with_write_timeout(stream, relay_url, hub, tasks, shutdown, WRITE_TIMEOUT).await
}

async fn serve_websocket_with_write_timeout<S>(
    stream: S,
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    shutdown: ShutdownSignal,
    write_timeout: Duration,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let websocket = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        Role::Server,
        Some(websocket_config()),
    )
    .await;
    drive_websocket(websocket, relay_url, hub, tasks, shutdown, write_timeout).await
}

async fn drive_websocket<S>(
    mut websocket: tokio_tungstenite::WebSocketStream<S>,
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    mut shutdown: ShutdownSignal,
    write_timeout: Duration,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut session = Session::new(
        hub,
        relay_url,
        SystemClock,
        OsChallengeSource,
        SessionLimits::default(),
    );
    let result = async {
        if drain_outputs(
            &mut websocket,
            &mut session,
            &mut shutdown,
            write_timeout,
        )
        .await?
            == DrainStatus::Closed
        {
            return Ok(());
        }

        let mut outputs = interval(Duration::from_millis(5));
        outputs.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let idle = sleep_until(Instant::now() + IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    close(&mut websocket, CloseCode::Away, "server shutdown").await?;
                    break;
                }
                _ = &mut idle => {
                    close(&mut websocket, CloseCode::Policy, "idle timeout").await?;
                    break;
                }
                incoming = websocket.next() => {
                    match incoming {
                        Some(Ok(Message::Text(text))) => {
                            idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                            let bytes = text.as_bytes();
                            tracing::trace!(event = "debug_frame_received", frame_type = "text", frame_bytes = bytes.len());
                            match parse_client_message(bytes, &wire_limits()) {
                                Ok(message) => {
                                    let task = session.handle(message);
                                    tasks.submit(task).await;
                                    if drain_outputs(
                                        &mut websocket,
                                        &mut session,
                                        &mut shutdown,
                                        write_timeout,
                                    ).await? == DrainStatus::Closed {
                                        break;
                                    }
                                }
                                Err(_) => {
                                    close(&mut websocket, CloseCode::Policy, "invalid client message").await?;
                                    break;
                                }
                            }
                        }
                        Some(Ok(Message::Binary(bytes))) => {
                            idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                            tracing::trace!(event = "debug_frame_received", frame_type = "binary", frame_bytes = bytes.len());
                            close(&mut websocket, CloseCode::Policy, "text frames required").await?;
                            break;
                        }
                        Some(Ok(Message::Ping(_))) => {
                            idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                            if flush_with_shutdown(
                                &mut websocket,
                                &mut shutdown,
                                write_timeout,
                            ).await? == DrainStatus::Closed {
                                break;
                            }
                        }
                        Some(Ok(Message::Pong(_))) => {
                            idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Ok(Message::Frame(_))) => {
                            close(&mut websocket, CloseCode::Policy, "unsupported frame").await?;
                            break;
                        }
                        Some(Err(WebSocketError::Capacity(_))) => {
                            close(&mut websocket, CloseCode::Policy, "frame limit exceeded").await?;
                            break;
                        }
                        Some(Err(_)) => return Err(ConnectionError::WebSocket),
                    }
                }
                _ = outputs.tick() => {
                    if drain_outputs(
                        &mut websocket,
                        &mut session,
                        &mut shutdown,
                        write_timeout,
                    ).await? == DrainStatus::Closed {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    session.disconnect();
    result
}

fn wire_limits() -> WireLimits {
    WireLimits {
        max_frame_bytes: MAX_FRAME_BYTES,
        max_subscription_id_bytes: 64,
        max_filters_per_req: 8,
    }
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(4 * 1024)
        .write_buffer_size(4 * 1024)
        .max_write_buffer_size(2 * MAX_FRAME_BYTES)
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainStatus {
    Open,
    Closed,
}

async fn drain_outputs<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    session: &mut Session<SqliteStore, SystemClock, OsChallengeSource>,
    shutdown: &mut ShutdownSignal,
    write_timeout: Duration,
) -> Result<DrainStatus, ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(output) = session.next_output() {
        match output {
            SessionOutput::Send(message) => {
                let json = message.as_json();
                if send_with_shutdown(
                    websocket,
                    Message::Text(json.into()),
                    shutdown,
                    write_timeout,
                )
                .await?
                    == DrainStatus::Closed
                {
                    return Ok(DrainStatus::Closed);
                }
            }
            SessionOutput::Close(_) => {
                close(websocket, CloseCode::Policy, "relay closed connection").await?;
                return Ok(DrainStatus::Closed);
            }
            SessionOutput::Subscribe(_)
            | SessionOutput::Unsubscribe(_)
            | SessionOutput::Publish(_) => return Err(ConnectionError::Invariant),
        }
    }
    Ok(DrainStatus::Open)
}

async fn send_with_shutdown<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    message: Message,
    shutdown: &mut ShutdownSignal,
    write_timeout: Duration,
) -> Result<DrainStatus, ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(DrainStatus::Closed),
        result = timeout(write_timeout, websocket.send(message)) => {
            match result {
                Ok(result) => {
                    result?;
                    Ok(DrainStatus::Open)
                }
                Err(_) => Err(ConnectionError::WriteTimeout),
            }
        }
    }
}

async fn flush_with_shutdown<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    shutdown: &mut ShutdownSignal,
    write_timeout: Duration,
) -> Result<DrainStatus, ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(DrainStatus::Closed),
        result = timeout(write_timeout, websocket.flush()) => {
            match result {
                Ok(result) => {
                    result?;
                    Ok(DrainStatus::Open)
                }
                Err(_) => Err(ConnectionError::WriteTimeout),
            }
        }
    }
}

async fn close<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    code: CloseCode,
    reason: &'static str,
) -> Result<(), ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let result = timeout(
        Duration::from_millis(250),
        websocket.close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
    )
    .await;
    if let Ok(result) = result {
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use deaddrop_relay_core::{SessionLimits, StrictClientMessage};
    use futures::{SinkExt, StreamExt};
    use nostr::{EventBuilder, Filter, Keys, Kind, SubscriptionId, Timestamp};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio::{io::duplex, sync::mpsc};
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

    use super::*;
    use crate::shutdown::shutdown_channel;

    async fn recv_json<S>(websocket: &mut WebSocketStream<S>) -> Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let message = tokio::time::timeout(Duration::from_secs(2), websocket.next())
            .await
            .expect("relay response timed out")
            .expect("relay closed before response")
            .expect("websocket error");
        serde_json::from_str(message.to_text().expect("expected text frame")).unwrap()
    }

    #[tokio::test]
    async fn already_upgraded_stream_completes_authenticated_publish_and_query() {
        let temp = TempDir::new().unwrap();
        let store = SqliteStore::open(temp.path().join("state/relay.sqlite3"), 8)
            .await
            .unwrap();
        let hub = RelayHub::new(store.clone());
        let relay_url = RelayUrl::parse("ws://examplehiddenservice.onion/relay").unwrap();
        let (task_sender, mut task_receiver) = mpsc::channel(8);
        let task_worker = tokio::spawn(async move {
            while let Some(task) = task_receiver.recv().await {
                task.await;
            }
        });
        let (server_stream, client_stream) = duplex(8 * 1024);
        let mut client_socket =
            WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (_shutdown, signal) = shutdown_channel();
        let server = tokio::spawn(serve_websocket(
            server_stream,
            relay_url.clone(),
            hub,
            TaskSubmitter::new(task_sender),
            signal,
        ));

        let challenge_message = recv_json(&mut client_socket).await;
        assert_eq!(challenge_message[0], "AUTH");
        let challenge = challenge_message[1].as_str().unwrap();
        let account = Keys::parse(&"11".repeat(32)).unwrap();
        let auth = EventBuilder::auth(challenge, relay_url)
            .custom_created_at(Timestamp::from(SystemClock.now_seconds()))
            .sign_with_keys(&account)
            .unwrap();
        client_socket
            .send(Message::Text(json!(["AUTH", auth]).to_string().into()))
            .await
            .unwrap();
        let authenticated = recv_json(&mut client_socket).await;
        assert_eq!(authenticated[0], "OK");
        assert_eq!(authenticated[2], true);

        let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"alice"}"#)
            .custom_created_at(Timestamp::from(SystemClock.now_seconds()))
            .sign_with_keys(&account)
            .unwrap();
        client_socket
            .send(Message::Text(
                json!(["EVENT", profile.clone()]).to_string().into(),
            ))
            .await
            .unwrap();
        let stored = recv_json(&mut client_socket).await;
        assert_eq!(stored[0], "OK");
        assert_eq!(stored[1], profile.id.to_hex());
        assert_eq!(stored[2], true);

        client_socket
            .send(Message::Text(
                json!(["REQ", "profiles", Filter::new().kind(Kind::Metadata)])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let delivered = recv_json(&mut client_socket).await;
        assert_eq!(delivered[0], "EVENT");
        assert_eq!(delivered[1], "profiles");
        assert_eq!(delivered[2]["id"], profile.id.to_hex());
        assert_eq!(
            recv_json(&mut client_socket).await,
            json!(["EOSE", "profiles"])
        );

        client_socket.close(None).await.unwrap();
        server.await.unwrap().unwrap();
        task_worker.await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stalled_generic_driver_times_out_without_impeding_another_driver() {
        let temp = TempDir::new().unwrap();
        let store = SqliteStore::open(temp.path().join("state/relay.sqlite3"), 8)
            .await
            .unwrap();
        let hub = RelayHub::new(store.clone());
        let relay_url = RelayUrl::parse("ws://examplehiddenservice.onion/relay").unwrap();
        let (task_sender, mut task_receiver) = mpsc::channel(8);
        let task_worker = tokio::spawn(async move {
            while let Some(task) = task_receiver.recv().await {
                task.await;
            }
        });
        let tasks = TaskSubmitter::new(task_sender);

        let (stalled_stream, stalled_peer) = duplex(1);
        let (_stalled_shutdown, stalled_signal) = shutdown_channel();
        let stalled = tokio::spawn(serve_websocket_with_write_timeout(
            stalled_stream,
            relay_url.clone(),
            hub.clone(),
            tasks.clone(),
            stalled_signal,
            Duration::from_millis(25),
        ));

        let (healthy_stream, healthy_peer) = duplex(8 * 1024);
        let mut healthy_client =
            WebSocketStream::from_raw_socket(healthy_peer, Role::Client, None).await;
        let (healthy_shutdown, healthy_signal) = shutdown_channel();
        let healthy = tokio::spawn(serve_websocket_with_write_timeout(
            healthy_stream,
            relay_url,
            hub,
            tasks.clone(),
            healthy_signal,
            Duration::from_secs(1),
        ));

        assert_eq!(recv_json(&mut healthy_client).await[0], "AUTH");
        let stalled_result = tokio::time::timeout(Duration::from_millis(500), stalled)
            .await
            .expect("stalled driver ignored its write deadline")
            .unwrap();
        assert!(matches!(stalled_result, Err(ConnectionError::WriteTimeout)));
        drop(stalled_peer);

        healthy_shutdown.trigger();
        tokio::time::timeout(Duration::from_millis(500), healthy)
            .await
            .expect("healthy driver ignored global shutdown")
            .unwrap()
            .unwrap();
        drop(tasks);
        task_worker.await.unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn generic_raw_stream_enforces_websocket_message_limit() {
        let temp = TempDir::new().unwrap();
        let store = SqliteStore::open(temp.path().join("state/relay.sqlite3"), 4)
            .await
            .unwrap();
        let hub = RelayHub::new(store.clone());
        let relay_url = RelayUrl::parse("ws://examplehiddenservice.onion/relay").unwrap();
        let (task_sender, _task_receiver) = mpsc::channel(1);
        let (server_stream, client_stream) = duplex(2 * MAX_FRAME_BYTES);
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (_shutdown, signal) = shutdown_channel();
        let server = tokio::spawn(serve_websocket(
            server_stream,
            relay_url,
            hub,
            TaskSubmitter::new(task_sender),
            signal,
        ));

        assert_eq!(recv_json(&mut client).await[0], "AUTH");
        let account = Keys::parse(&"22".repeat(32)).unwrap();
        let oversized = EventBuilder::new(Kind::Metadata, "x".repeat(MAX_FRAME_BYTES))
            .custom_created_at(Timestamp::from(SystemClock.now_seconds()))
            .sign_with_keys(&account)
            .unwrap();
        client
            .send(Message::Text(
                json!(["EVENT", oversized]).to_string().into(),
            ))
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .expect("oversized message was not closed")
            .expect("driver ended without a close frame")
            .expect("websocket error before close frame");
        let Message::Close(Some(frame)) = response else {
            panic!("expected close frame, got {response:?}");
        };
        assert_eq!(frame.code, CloseCode::Policy);
        assert_eq!(frame.reason, "frame limit exceeded");

        server.await.unwrap().unwrap();
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stalled_outbound_write_is_interrupted_by_shutdown() {
        let (stream, _stalled_peer) = duplex(32);
        let mut websocket =
            WebSocketStream::from_raw_socket(stream, Role::Server, Some(websocket_config())).await;
        let (shutdown, mut signal) = shutdown_channel();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            shutdown.trigger();
        });

        let status = tokio::time::timeout(
            Duration::from_millis(500),
            send_with_shutdown(
                &mut websocket,
                Message::Text("x".repeat(MAX_FRAME_BYTES).into()),
                &mut signal,
                Duration::from_secs(1),
            ),
        )
        .await
        .expect("shutdown must interrupt a stalled output write")
        .unwrap();
        assert_eq!(status, DrainStatus::Closed);
    }

    #[tokio::test]
    async fn relay_close_output_terminates_the_socket_drain() {
        let temp = TempDir::new().unwrap();
        let store = SqliteStore::open(temp.path().join("state/relay.sqlite3"), 4)
            .await
            .unwrap();
        let hub = RelayHub::new(store.clone());
        let relay_url = RelayUrl::parse("ws://127.0.0.1:8765").unwrap();
        let mut session = Session::new(
            hub,
            relay_url,
            SystemClock,
            OsChallengeSource,
            SessionLimits {
                max_subscriptions: 1,
                max_history_events: 1,
                max_pending_outputs: 2,
                max_in_flight_tasks: 1,
            },
        );
        for id in ["first", "overflow"] {
            session
                .handle(StrictClientMessage::Req {
                    subscription_id: SubscriptionId::new(id),
                    filters: vec![Filter::new().kind(Kind::Metadata)],
                })
                .await;
        }
        assert!(session.is_closed());

        let (server_stream, client_stream) = duplex(1024);
        let (mut server_socket, mut client_socket) = tokio::join!(
            WebSocketStream::from_raw_socket(server_stream, Role::Server, None),
            WebSocketStream::from_raw_socket(client_stream, Role::Client, None),
        );
        let (_shutdown, mut signal) = shutdown_channel();
        assert_eq!(
            drain_outputs(
                &mut server_socket,
                &mut session,
                &mut signal,
                Duration::from_secs(1),
            )
            .await
            .unwrap(),
            DrainStatus::Closed
        );
        assert!(matches!(
            client_socket.next().await,
            Some(Ok(Message::Close(_)))
        ));
        store.shutdown().await.unwrap();
    }
}
