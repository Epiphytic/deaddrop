use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use deaddrop_relay_core::{
    ChallengeSource, Clock, RelayHub, Session, SessionLimits, SessionOutput, SessionTask,
    WireLimits, parse_client_message,
};
use deaddrop_relay_sqlite::SqliteStore;
use futures::{SinkExt, StreamExt};
use nostr::{JsonUtil, RelayUrl};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{Instant, MissedTickBehavior, interval, sleep_until, timeout},
};
use tokio_tungstenite::{
    accept_async_with_config,
    tungstenite::{
        Error as WebSocketError, Message,
        protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode},
    },
};

use crate::shutdown::ShutdownSignal;

pub(crate) const MAX_FRAME_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

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

#[derive(Clone)]
pub(crate) struct TaskSubmitter(mpsc::Sender<SessionTask>);

impl TaskSubmitter {
    pub(crate) fn new(sender: mpsc::Sender<SessionTask>) -> Self {
        Self(sender)
    }

    /// Once a session returns work, either transfer it to the server owner or
    /// drive it inline if that owner is already closing. Never cancel it.
    async fn submit(&self, task: SessionTask) {
        if let Err(error) = self.0.send(task).await {
            error.0.await;
        }
    }
}

pub(crate) async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    mut shutdown: ShutdownSignal,
) {
    if let Err(error) = run_connection(stream, relay_url, hub, tasks, &mut shutdown).await {
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
enum ConnectionError {
    WebSocket,
    HandshakeTimeout,
    Invariant,
}

impl ConnectionError {
    fn category(&self) -> &'static str {
        match self {
            Self::WebSocket => "websocket",
            Self::HandshakeTimeout => "handshake-timeout",
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
    shutdown: &mut ShutdownSignal,
) -> Result<(), ConnectionError> {
    let mut websocket = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Ok(()),
        accepted = timeout(
            HANDSHAKE_TIMEOUT,
            accept_async_with_config(stream, Some(websocket_config())),
        ) => accepted.map_err(|_| ConnectionError::HandshakeTimeout)??,
    };
    let mut session = Session::new(
        hub,
        relay_url,
        SystemClock,
        OsChallengeSource,
        SessionLimits::default(),
    );
    if drain_outputs(&mut websocket, &mut session, shutdown).await? == DrainStatus::Closed {
        session.disconnect();
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
                                if drain_outputs(&mut websocket, &mut session, shutdown).await? == DrainStatus::Closed {
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
                        if flush_with_shutdown(&mut websocket, shutdown).await? == DrainStatus::Closed {
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
                if drain_outputs(&mut websocket, &mut session, shutdown).await? == DrainStatus::Closed {
                    break;
                }
            }
        }
    }
    session.disconnect();
    Ok(())
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
) -> Result<DrainStatus, ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(output) = session.next_output() {
        match output {
            SessionOutput::Send(message) => {
                let json = message.as_json();
                if send_with_shutdown(websocket, Message::Text(json.into()), shutdown).await?
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
) -> Result<DrainStatus, ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(DrainStatus::Closed),
        result = websocket.send(message) => {
            result?;
            Ok(DrainStatus::Open)
        }
    }
}

async fn flush_with_shutdown<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    shutdown: &mut ShutdownSignal,
) -> Result<DrainStatus, ConnectionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        biased;
        _ = shutdown.cancelled() => Ok(DrainStatus::Closed),
        result = websocket.flush() => {
            result?;
            Ok(DrainStatus::Open)
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
    use futures::StreamExt;
    use nostr::{Filter, Kind, SubscriptionId};
    use tempfile::TempDir;
    use tokio::io::duplex;
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

    use super::*;
    use crate::shutdown::shutdown_channel;

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
            drain_outputs(&mut server_socket, &mut session, &mut signal)
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
