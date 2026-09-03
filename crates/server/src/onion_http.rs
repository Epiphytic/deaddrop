use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use deaddrop_relay_core::RelayHub;
use deaddrop_relay_sqlite::SqliteStore;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode, Version,
    body::Incoming,
    header::{
        CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, EXPECT,
        HOST, HeaderName, HeaderValue, ORIGIN, REFERRER_POLICY, SEC_WEBSOCKET_EXTENSIONS,
        SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, TRANSFER_ENCODING,
        UPGRADE, X_CONTENT_TYPE_OPTIONS,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use nostr::RelayUrl;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::handshake::server::create_response_with_body;

use crate::{
    connection::serve_websocket,
    runtime::{ConnectionAdmissionError, RuntimeHandle, TaskSubmitter},
    shutdown::ShutdownSignal,
    static_app,
};

const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HEADERS: usize = 32;
const MAX_HTTP_BUFFER_BYTES: usize = 8 * 1024;
const HTTP_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_BODY: &[u8] = b"ok\n";
const ERROR_BAD_REQUEST: &[u8] = b"bad request\n";
const ERROR_NOT_FOUND: &[u8] = b"not found\n";
const ERROR_METHOD: &[u8] = b"method not allowed\n";
const ERROR_UPGRADE: &[u8] = b"websocket upgrade required\n";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), autoplay=(), bluetooth=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), microphone=(), payment=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=()";

#[derive(Clone)]
pub(crate) struct OnionHttpHost {
    canonical_host: Arc<str>,
    runtime: RuntimeHandle,
}

impl OnionHttpHost {
    pub(crate) fn new(canonical_host: impl Into<Arc<str>>, runtime: RuntimeHandle) -> Self {
        Self {
            canonical_host: canonical_host.into(),
            runtime,
        }
    }

    pub(crate) fn try_serve<S>(&self, stream: S) -> Result<(), ConnectionAdmissionError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let canonical_host = Arc::clone(&self.canonical_host);
        let relay = RelayContext::new(canonical_host.as_ref(), &self.runtime);
        self.runtime.try_register_connection(async move {
            serve_http_stream(stream, canonical_host, relay, HEADER_TIMEOUT).await;
        })
    }
}

#[derive(Clone)]
struct RelayContext {
    relay_url: RelayUrl,
    hub: RelayHub<SqliteStore>,
    tasks: TaskSubmitter,
    shutdown: ShutdownSignal,
}

impl RelayContext {
    fn new(canonical_host: &str, runtime: &RuntimeHandle) -> Self {
        Self {
            relay_url: RelayUrl::parse(&format!("ws://{canonical_host}/relay"))
                .expect("Arti supplied an invalid onion hostname"),
            hub: runtime.hub(),
            tasks: runtime.task_submitter(),
            shutdown: runtime.shutdown_signal(),
        }
    }
}

type UpgradeSender = Arc<Mutex<Option<oneshot::Sender<hyper::upgrade::OnUpgrade>>>>;

async fn serve_http_stream<S>(
    stream: S,
    canonical_host: Arc<str>,
    relay: RelayContext,
    header_timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let raw_head = Arc::new(Mutex::new(RawHead::default()));
    let observed_stream = ObservedIo::new(stream, Arc::clone(&raw_head));
    let (upgrade_sender, upgrade_receiver) = oneshot::channel();
    let upgrade_sender = Arc::new(Mutex::new(Some(upgrade_sender)));
    let service = service_fn(move |request: Request<Incoming>| {
        let canonical_host = Arc::clone(&canonical_host);
        let upgrade_sender = Arc::clone(&upgrade_sender);
        let raw_head = Arc::clone(&raw_head);
        async move {
            Ok::<_, Infallible>(route(
                request,
                canonical_host.as_ref(),
                &upgrade_sender,
                &raw_head,
            ))
        }
    });
    // Hyper owns failures that occur before it can construct `Request<Incoming>`,
    // so those protocol responses cannot pass through `route`/`secure`. Keep
    // them bounded and bodyless, and disable Hyper's automatic Date header.
    // The security envelope applies to every application-generated response
    // once a request reaches the service.
    let mut builder = http1::Builder::new();
    builder.timer(TokioTimer::new());
    builder.header_read_timeout(header_timeout);
    builder.half_close(true);
    builder.auto_date_header(false);
    builder.max_headers(MAX_HEADERS);
    builder.max_buf_size(MAX_HTTP_BUFFER_BYTES);
    let connection = builder
        .serve_connection(TokioIo::new(observed_stream), service)
        .with_upgrades();
    let http_shutdown = relay.shutdown.clone();
    let http = async move {
        tokio::pin!(connection);
        let mut shutdown = http_shutdown;
        let connection_timeout = tokio::time::sleep(HTTP_CONNECTION_TIMEOUT);
        tokio::pin!(connection_timeout);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(HTTP_SHUTDOWN_TIMEOUT, &mut connection).await;
            }
            result = &mut connection => {
                if result.is_err() {
                    tracing::debug!(event = "onion_http_connection_ended", reason = "http");
                }
            }
            _ = &mut connection_timeout => {
                tracing::debug!(event = "onion_http_connection_ended", reason = "http-timeout");
            }
        }
    };
    let websocket = async move {
        let Ok(on_upgrade) = upgrade_receiver.await else {
            return;
        };
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(_) => {
                tracing::debug!(event = "onion_http_connection_ended", reason = "upgrade");
                return;
            }
        };
        if serve_websocket(
            TokioIo::new(upgraded),
            relay.relay_url,
            relay.hub,
            relay.tasks,
            relay.shutdown,
        )
        .await
        .is_err()
        {
            tracing::debug!(event = "onion_http_connection_ended", reason = "websocket");
        }
    };
    tokio::join!(http, websocket);
}

fn route(
    mut request: Request<Incoming>,
    canonical_host: &str,
    upgrade_sender: &UpgradeSender,
    raw_head: &Arc<Mutex<RawHead>>,
) -> Response<Full<Bytes>> {
    let head = request.method() == Method::HEAD;
    let response = if invalid_request(&request, canonical_host, raw_head) {
        response(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            ERROR_BAD_REQUEST,
            head,
        )
    } else {
        match (request.method(), request.uri().path()) {
            (&Method::GET | &Method::HEAD, path) => match static_app::get(path) {
                Some(asset) => response(StatusCode::OK, asset.content_type, asset.bytes, head),
                None if path == "/health" => health_or_method(&request),
                None if path == "/relay" && request.method() == Method::GET => {
                    relay_response(&mut request, canonical_host, upgrade_sender)
                }
                None if path == "/relay" => response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "text/plain; charset=utf-8",
                    ERROR_METHOD,
                    head,
                ),
                None => response(
                    StatusCode::NOT_FOUND,
                    "text/plain; charset=utf-8",
                    ERROR_NOT_FOUND,
                    head,
                ),
            },
            (_, "/" | "/app.js" | "/styles.css" | "/health" | "/relay") => response(
                StatusCode::METHOD_NOT_ALLOWED,
                "text/plain; charset=utf-8",
                ERROR_METHOD,
                head,
            ),
            _ => response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                ERROR_NOT_FOUND,
                head,
            ),
        }
    };
    secure(response)
}

fn health_or_method(request: &Request<Incoming>) -> Response<Full<Bytes>> {
    let head = request.method() == Method::HEAD;
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/health") => response(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            HEALTH_BODY,
            false,
        ),
        _ => response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            ERROR_METHOD,
            head,
        ),
    }
}

fn relay_response(
    request: &mut Request<Incoming>,
    canonical_host: &str,
    upgrade_sender: &UpgradeSender,
) -> Response<Full<Bytes>> {
    if !is_upgrade_attempt(request) {
        let mut response = response(
            StatusCode::UPGRADE_REQUIRED,
            "text/plain; charset=utf-8",
            ERROR_UPGRADE,
            false,
        );
        response
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        return response;
    }
    if !valid_websocket_upgrade(request, canonical_host) {
        return response(
            StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            ERROR_BAD_REQUEST,
            false,
        );
    }
    let Some(sender) = upgrade_sender.lock().expect("upgrade lock poisoned").take() else {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            b"unavailable\n",
            false,
        );
    };
    let normalized = normalized_upgrade_request(request);
    let switching_response =
        match create_response_with_body(&normalized, || Full::new(Bytes::new())) {
            Ok(response) => response,
            Err(_) => {
                return response(
                    StatusCode::BAD_REQUEST,
                    "text/plain; charset=utf-8",
                    ERROR_BAD_REQUEST,
                    false,
                );
            }
        };
    let on_upgrade = hyper::upgrade::on(request);
    if sender.send(on_upgrade).is_err() {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            b"unavailable\n",
            false,
        );
    }
    switching_response
}

fn is_upgrade_attempt(request: &Request<Incoming>) -> bool {
    request.headers().contains_key(SEC_WEBSOCKET_VERSION)
        || request.headers().contains_key(SEC_WEBSOCKET_KEY)
        || header_tokens(request, CONNECTION).is_some_and(|tokens| {
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
        })
        || header_tokens(request, UPGRADE).is_some_and(|tokens| {
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("websocket"))
        })
}

fn valid_websocket_upgrade(request: &Request<Incoming>, canonical_host: &str) -> bool {
    request.method() == Method::GET
        && header_tokens(request, CONNECTION).is_some_and(|tokens| {
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
        })
        && header_tokens(request, UPGRADE).is_some_and(|tokens| {
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("websocket"))
        })
        && single_header(request, SEC_WEBSOCKET_VERSION).is_some_and(|value| value == b"13")
        && single_header(request, SEC_WEBSOCKET_KEY).is_some_and(|value| {
            BASE64
                .decode(value)
                .is_ok_and(|decoded| decoded.len() == 16)
        })
        && optional_origin_is_valid(request, canonical_host)
        && !request.headers().contains_key(SEC_WEBSOCKET_EXTENSIONS)
        && !request.headers().contains_key(SEC_WEBSOCKET_PROTOCOL)
}

fn header_tokens(request: &Request<Incoming>, name: HeaderName) -> Option<Vec<&str>> {
    let mut tokens = Vec::new();
    for value in request.headers().get_all(name).iter() {
        let value = value.to_str().ok()?;
        for token in value.split(',').map(str::trim) {
            if token.is_empty() || !token.bytes().all(is_http_token_byte) {
                return None;
            }
            tokens.push(token);
        }
    }
    (!tokens.is_empty()).then_some(tokens)
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn single_header(request: &Request<Incoming>, name: HeaderName) -> Option<&[u8]> {
    let mut values = request.headers().get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value.as_bytes())
}

fn optional_origin_is_valid(request: &Request<Incoming>, canonical_host: &str) -> bool {
    let mut origins = request.headers().get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    origins.next().is_none()
        && origin
            .to_str()
            .is_ok_and(|origin| origin == format!("http://{canonical_host}"))
}

fn normalized_upgrade_request(request: &Request<Incoming>) -> Request<()> {
    let mut normalized = Request::builder()
        .method(Method::GET)
        .uri("/relay")
        .version(Version::HTTP_11)
        .body(())
        .expect("normalized WebSocket request is valid");
    let headers = normalized.headers_mut();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
    headers.insert(
        SEC_WEBSOCKET_KEY,
        request
            .headers()
            .get(SEC_WEBSOCKET_KEY)
            .expect("validated WebSocket key")
            .clone(),
    );
    normalized
}

fn invalid_request(
    request: &Request<Incoming>,
    canonical_host: &str,
    raw_head: &Arc<Mutex<RawHead>>,
) -> bool {
    if request.version() != Version::HTTP_11
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || !request.uri().path().starts_with('/')
        || !raw_head
            .lock()
            .expect("raw request-head lock poisoned")
            .content_length_is_absent_or_lexical_zero()
    {
        return true;
    }
    let mut hosts = request.headers().get_all(HOST).iter();
    let Some(host) = hosts.next() else {
        return true;
    };
    if hosts.next().is_some() || host.as_bytes() != canonical_host.as_bytes() {
        return true;
    }
    if request.headers().contains_key(TRANSFER_ENCODING) || request.headers().contains_key(EXPECT) {
        return true;
    }
    let mut lengths = request.headers().get_all(CONTENT_LENGTH).iter();
    match lengths.next() {
        None => false,
        Some(length) => lengths.next().is_some() || length.as_bytes() != b"0",
    }
}

#[derive(Default)]
struct RawHead {
    bytes: Vec<u8>,
    complete: bool,
    overflowed: bool,
}

impl RawHead {
    fn observe(&mut self, bytes: &[u8]) {
        if self.complete || self.overflowed {
            return;
        }
        for byte in bytes {
            if self.bytes.len() >= MAX_HTTP_BUFFER_BYTES {
                self.overflowed = true;
                break;
            }
            self.bytes.push(*byte);
            if self.bytes.ends_with(b"\r\n\r\n") {
                self.complete = true;
                break;
            }
        }
    }

    fn content_length_is_absent_or_lexical_zero(&self) -> bool {
        if !self.complete || self.overflowed {
            return false;
        }
        let Some(end) = self
            .bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        else {
            return false;
        };
        let mut values = self.bytes[..end]
            .split(|byte| *byte == b'\n')
            .skip(1)
            .filter_map(|line| {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let colon = line.iter().position(|byte| *byte == b':')?;
                line[..colon]
                    .eq_ignore_ascii_case(b"content-length")
                    .then(|| trim_ows(&line[colon + 1..]))
            });
        match values.next() {
            None => true,
            Some(value) => value == b"0" && values.next().is_none(),
        }
    }
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

struct ObservedIo<S> {
    inner: S,
    raw_head: Arc<Mutex<RawHead>>,
    observing: bool,
}

impl<S> ObservedIo<S> {
    fn new(inner: S, raw_head: Arc<Mutex<RawHead>>) -> Self {
        Self {
            inner,
            raw_head,
            observing: true,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if self.observing && matches!(result, Poll::Ready(Ok(()))) {
            let finished = {
                let mut raw_head = self
                    .raw_head
                    .lock()
                    .expect("raw request-head lock poisoned");
                raw_head.observe(&buffer.filled()[before..]);
                raw_head.complete || raw_head.overflowed
            };
            self.observing = !finished;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    bytes: &'static [u8],
    head: bool,
) -> Response<Full<Bytes>> {
    let body = if head { &[][..] } else { bytes };
    Response::builder()
        .status(status)
        .header(CONNECTION, "close")
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, bytes.len())
        .body(Full::new(Bytes::from_static(body)))
        .expect("static response is valid")
}

fn secure<B>(mut response: Response<B>) -> Response<B> {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    for (name, value) in [
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-embedder-policy", "require-corp"),
        ("cross-origin-resource-policy", "same-origin"),
        ("permissions-policy", PERMISSIONS_POLICY),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use nostr::{EventBuilder, Filter, Keys, Kind, RelayUrl, Tag, Timestamp};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        sync::Notify,
    };
    use tokio_tungstenite::{
        WebSocketStream, client_async,
        tungstenite::{Message, client::IntoClientRequest, protocol::Role},
    };

    use super::*;
    use crate::runtime::RelayRuntime;

    const HOST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

    struct RawResponse {
        status: u16,
        headers: String,
        body: Vec<u8>,
    }

    async fn raw_request(request: &str) -> RawResponse {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let (server, mut client) = duplex(128 * 1024);
        host.try_serve(server).unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut bytes))
            .await
            .expect("HTTP response timed out")
            .unwrap();
        runtime.shutdown().await.unwrap();

        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP response missing header terminator");
        let headers = String::from_utf8(bytes[..split].to_vec()).unwrap();
        let status = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        RawResponse {
            status,
            headers,
            body: bytes[split + 4..].to_vec(),
        }
    }

    fn request(method: &str, target: &str, extra_headers: &str) -> String {
        format!("{method} {target} HTTP/1.1\r\nHost: {HOST}\r\n{extra_headers}\r\n")
    }

    fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).expect("test frame fits extended length");
        let mask = [0x11, 0x22, 0x33, 0x44];
        let mut frame = vec![0x81, 0xfe];
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        frame
    }

    async fn recv_json<S>(socket: &mut WebSocketStream<S>) -> Value
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("relay response timed out")
            .expect("relay closed before response")
            .expect("websocket error");
        serde_json::from_str(message.to_text().expect("expected text response")).unwrap()
    }

    async fn open_websocket(host: &OnionHttpHost) -> WebSocketStream<tokio::io::DuplexStream> {
        let (server, client) = duplex(128 * 1024);
        host.try_serve(server).unwrap();
        client_async(format!("ws://{HOST}/relay"), client)
            .await
            .expect("canonical HTTP upgrade failed")
            .0
    }

    async fn authenticate_socket(
        socket: &mut WebSocketStream<tokio::io::DuplexStream>,
        keys: &Keys,
    ) {
        let challenge = recv_json(socket).await;
        assert_eq!(challenge[0], "AUTH");
        let relay_url = RelayUrl::parse(&format!("ws://{HOST}/relay")).unwrap();
        let auth = EventBuilder::auth(challenge[1].as_str().unwrap(), relay_url)
            .custom_created_at(Timestamp::now())
            .sign_with_keys(keys)
            .unwrap();
        socket
            .send(Message::Text(json!(["AUTH", auth]).to_string().into()))
            .await
            .unwrap();
        assert_eq!(recv_json(socket).await[2], true);
    }

    #[tokio::test]
    async fn serves_only_the_finite_static_and_health_routes() {
        for (path, content_type, body_fragment) in [
            ("/", "text/html; charset=utf-8", "Deaddrop relay"),
            ("/app.js", "text/javascript; charset=utf-8", "renderShell"),
            ("/styles.css", "text/css; charset=utf-8", "--paper"),
        ] {
            let response = raw_request(&request("GET", path, "")).await;
            assert_eq!(response.status, 200, "GET {path}");
            assert!(
                response
                    .headers
                    .contains(&format!("content-type: {content_type}"))
            );
            assert!(
                String::from_utf8(response.body)
                    .unwrap()
                    .contains(body_fragment)
            );

            let response = raw_request(&request("HEAD", path, "")).await;
            assert_eq!(response.status, 200, "HEAD {path}");
            assert!(response.body.is_empty());
        }

        let health = raw_request(&request("GET", "/health", "")).await;
        assert_eq!(health.status, 200);
        assert_eq!(health.body, b"ok\n");
        assert_eq!(
            raw_request(&request("HEAD", "/health", "")).await.status,
            405
        );
        assert_eq!(
            raw_request(&request("GET", "/missing", "")).await.status,
            404
        );
        assert_eq!(
            raw_request(&request("POST", "/", "Content-Length: 0\r\n"))
                .await
                .status,
            405
        );
        assert_eq!(raw_request(&request("GET", "/relay", "")).await.status, 426);
    }

    #[tokio::test]
    async fn head_relay_never_upgrades_even_with_complete_websocket_headers() {
        let response = raw_request(&request(
            "HEAD",
            "/relay",
            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        ))
        .await;
        assert_eq!(response.status, 405);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn relay_upgrade_required_response_advertises_websocket() {
        let response = raw_request(&request("GET", "/relay", "")).await;
        assert_eq!(response.status, 426);
        assert!(
            response
                .headers
                .to_ascii_lowercase()
                .contains("\r\nupgrade: websocket")
        );
    }

    #[tokio::test]
    async fn origin_alone_is_an_incomplete_handshake_not_a_malformed_one() {
        for headers in [
            format!("Origin: http://{HOST}\r\n"),
            format!("Origin: http://{HOST}\r\nConnection: keep-alive\r\n"),
        ] {
            let response = raw_request(&request("GET", "/relay", &headers)).await;
            assert_eq!(response.status, 426);
            assert!(
                response
                    .headers
                    .to_ascii_lowercase()
                    .contains("upgrade: websocket")
            );
        }
    }

    #[tokio::test]
    async fn rejects_noncanonical_targets_hosts_and_request_bodies_before_dispatch() {
        let cases = [
            "GET /?x=1 HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\n\r\n",
            "GET /? HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\n\r\n",
            "GET http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/ HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: foreign.onion\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:80\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\nContent-Length: 1\r\n\r\nx",
            "GET / HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
        ];
        for raw in cases {
            assert_eq!(
                raw_request(raw).await.status,
                400,
                "request was not rejected: {raw:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejected_request_body_framing_never_dispatches_a_pipelined_second_request() {
        for raw in [
            format!(
                "GET / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 1\r\n\r\nxGET /health HTTP/1.1\r\nHost: {HOST}\r\n\r\n"
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /health HTTP/1.1\r\nHost: {HOST}\r\n\r\n"
            ),
        ] {
            let response = raw_request(&raw).await;
            assert_eq!(response.status, 400);
            assert_eq!(response.body, ERROR_BAD_REQUEST);
            assert!(!String::from_utf8_lossy(&response.body).contains("HTTP/1.1"));
        }
    }

    #[tokio::test]
    async fn every_application_response_has_the_static_security_envelope() {
        for request in [
            request("GET", "/", ""),
            request("GET", "/missing", ""),
            request("POST", "/", "Content-Length: 0\r\n"),
            request("GET", "/relay", ""),
            "GET / HTTP/1.1\r\nHost: wrong.onion\r\n\r\n".to_owned(),
        ] {
            let response = raw_request(&request).await;
            let headers = response.headers.to_ascii_lowercase();
            for required in [
                "cache-control: no-store",
                "content-security-policy:",
                "connect-src 'none'",
                "frame-ancestors 'none'",
                "referrer-policy: no-referrer",
                "x-content-type-options: nosniff",
                "cross-origin-opener-policy: same-origin",
                "cross-origin-embedder-policy: require-corp",
                "cross-origin-resource-policy: same-origin",
                "permissions-policy:",
            ] {
                assert!(
                    headers.contains(required),
                    "missing {required:?} in {headers}"
                );
            }
            for forbidden in [
                "\r\ndate:",
                "\r\nserver:",
                "strict-transport-security",
                "access-control-allow-origin",
            ] {
                assert!(
                    !headers.contains(forbidden),
                    "unexpected {forbidden:?} in {headers}"
                );
            }
        }
    }

    #[tokio::test]
    async fn http_upgrade_completes_authentication_publish_and_history_round_trip() {
        let temp = TempDir::new().unwrap();
        let database_path = temp.path().join("state/relay.sqlite3");
        let runtime = RelayRuntime::start(&database_path).await.unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let (server, client) = duplex(128 * 1024);
        host.try_serve(server).unwrap();
        let relay_url = RelayUrl::parse(&format!("ws://{HOST}/relay")).unwrap();
        let (mut socket, response) = client_async(relay_url.as_str(), client)
            .await
            .expect("canonical HTTP upgrade failed");
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert!(!response.headers().contains_key("date"));

        let challenge_message = recv_json(&mut socket).await;
        assert_eq!(challenge_message[0], "AUTH");
        let keys = Keys::parse(&"11".repeat(32)).unwrap();
        let auth = EventBuilder::auth(challenge_message[1].as_str().unwrap(), relay_url.clone())
            .custom_created_at(Timestamp::now())
            .sign_with_keys(&keys)
            .unwrap();
        socket
            .send(Message::Text(json!(["AUTH", auth]).to_string().into()))
            .await
            .unwrap();
        assert_eq!(recv_json(&mut socket).await[2], true);

        let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"alice"}"#)
            .custom_created_at(Timestamp::now())
            .sign_with_keys(&keys)
            .unwrap();
        socket
            .send(Message::Text(
                json!(["EVENT", profile.clone()]).to_string().into(),
            ))
            .await
            .unwrap();
        let stored = recv_json(&mut socket).await;
        assert_eq!(stored[0], "OK");
        assert_eq!(stored[1], profile.id.to_hex());
        assert_eq!(stored[2], true);
        socket
            .send(Message::Text(
                json!(["REQ", "history", Filter::new().kind(Kind::Metadata)])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        assert_eq!(recv_json(&mut socket).await[2]["id"], profile.id.to_hex());
        assert_eq!(recv_json(&mut socket).await, json!(["EOSE", "history"]));

        socket.close(None).await.unwrap();
        runtime.shutdown().await.unwrap();
        assert_eq!(
            rusqlite::Connection::open(database_path)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn accepted_publish_survives_sender_disconnect_and_reaches_live_subscriber() {
        let temp = TempDir::new().unwrap();
        let database_path = temp.path().join("state/relay.sqlite3");
        let runtime = RelayRuntime::start_with_test_capacities(&database_path, 3, 1, 1)
            .await
            .unwrap();
        let handle = runtime.handle();
        let host = OnionHttpHost::new(HOST, handle.clone());
        let subscriber_keys = Keys::parse(&"33".repeat(32)).unwrap();
        let publisher_keys = Keys::parse(&"44".repeat(32)).unwrap();

        let mut subscriber = open_websocket(&host).await;
        authenticate_socket(&mut subscriber, &subscriber_keys).await;
        subscriber
            .send(Message::Text(
                json!(["REQ", "live", Filter::new().kind(Kind::Metadata)])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        assert_eq!(recv_json(&mut subscriber).await, json!(["EOSE", "live"]));

        let mut publisher = open_websocket(&host).await;
        authenticate_socket(&mut publisher, &publisher_keys).await;

        let entered = Arc::new(Notify::new());
        let entered_task = Arc::clone(&entered);
        let release = Arc::new(Notify::new());
        let release_task = Arc::clone(&release);
        handle
            .task_submitter()
            .submit(Box::pin(async move {
                entered_task.notify_one();
                release_task.notified().await;
            }))
            .await;
        entered.notified().await;

        let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"detached"}"#)
            .custom_created_at(Timestamp::now())
            .sign_with_keys(&publisher_keys)
            .unwrap();
        publisher
            .send(Message::Text(
                json!(["EVENT", profile.clone()]).to_string().into(),
            ))
            .await
            .unwrap();
        publisher.flush().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while handle.task_submitter().remaining_capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("publish never crossed the accepted task boundary");
        publisher.close(None).await.unwrap();

        release.notify_one();
        let delivered = recv_json(&mut subscriber).await;
        assert_eq!(delivered[0], "EVENT");
        assert_eq!(delivered[1], "live");
        assert_eq!(delivered[2]["id"], profile.id.to_hex());
        subscriber.close(None).await.unwrap();
        runtime.shutdown().await.unwrap();
        assert_eq!(
            rusqlite::Connection::open(database_path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE id = ?1",
                    [profile.id.to_hex()],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn accepts_exact_origin_and_multiline_mixed_case_upgrade_tokens() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let (server, client) = duplex(128 * 1024);
        host.try_serve(server).unwrap();
        let mut request = format!("ws://{HOST}/relay").into_client_request().unwrap();
        request.headers_mut().insert(
            ORIGIN,
            HeaderValue::from_str(&format!("http://{HOST}")).unwrap(),
        );
        request.headers_mut().remove(CONNECTION);
        request
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("keep-alive, uPgRaDe"));
        request.headers_mut().remove(UPGRADE);
        request
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("h2c, WebSocket"));
        let (mut socket, response) = client_async(request, client).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let headers = response.headers();
        let rendered = headers
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}: {}",
                    name.as_str(),
                    value.to_str().expect("security header is ASCII")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            .to_ascii_lowercase();
        for required in [
            "cache-control: no-store",
            "content-security-policy:",
            "connect-src 'none'",
            "frame-ancestors 'none'",
            "referrer-policy: no-referrer",
            "x-content-type-options: nosniff",
            "cross-origin-opener-policy: same-origin",
            "cross-origin-embedder-policy: require-corp",
            "cross-origin-resource-policy: same-origin",
            "permissions-policy:",
        ] {
            assert!(
                rendered.contains(required),
                "missing {required:?} in {rendered}"
            );
        }
        for forbidden in [
            "date:",
            "server:",
            "strict-transport-security",
            "access-control-allow-origin",
            "x-powered-by",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "unexpected {forbidden:?} in {rendered}"
            );
        }
        assert_eq!(recv_json(&mut socket).await[0], "AUTH");
        socket.close(None).await.unwrap();
        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn malformed_websocket_upgrades_are_rejected_before_a_session_exists() {
        let valid = "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n".to_owned();
        let cases = [
            valid.replace(
                "Connection: keep-alive, Upgrade\r\n",
                "Connection: keep-alive\r\n",
            ),
            valid.replace("Upgrade: websocket", "Upgrade: h2c"),
            valid.replace("Connection: keep-alive, Upgrade", "Connection: , Upgrade"),
            valid.replace("Connection: keep-alive, Upgrade", "Connection: Upgrade,"),
            valid.replace("Upgrade: websocket", "Upgrade: websocket,"),
            valid.replace("Upgrade: websocket", "Upgrade: web socket"),
            valid.replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 12"),
            format!("{valid}Sec-WebSocket-Version: 13\r\n"),
            valid.replace("dGhlIHNhbXBsZSBub25jZQ==", "c2hvcnQ="),
            format!("{valid}Origin: null\r\n"),
            format!("{valid}Origin: http://foreign.onion\r\n"),
            format!("{valid}Sec-WebSocket-Extensions: permessage-deflate\r\n"),
            format!("{valid}Sec-WebSocket-Protocol: nostr\r\n"),
            format!("{valid}Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"),
            format!("{valid}Origin: http://{HOST}\r\nOrigin: http://{HOST}\r\n"),
        ];
        for headers in cases {
            let response = raw_request(&request("GET", "/relay", &headers)).await;
            assert_eq!(
                response.status, 400,
                "upgrade was not rejected: {headers:?}"
            );
            assert!(!response.body.starts_with(b"[\"AUTH\""));
        }

        for raw in [
            format!("GET /relay HTTP/1.1\r\nHost: wrong.onion\r\n{valid}\r\n"),
            format!("GET /other HTTP/1.1\r\nHost: {HOST}\r\n{valid}\r\n"),
            format!("GET /relay? HTTP/1.1\r\nHost: {HOST}\r\n{valid}\r\n"),
            format!("GET ws://{HOST}/relay HTTP/1.1\r\nHost: {HOST}\r\n{valid}\r\n"),
        ] {
            let response = raw_request(&raw).await;
            assert_ne!(
                response.status, 101,
                "noncanonical target started a session"
            );
            assert!(!response.body.starts_with(b"[\"AUTH\""));
        }
    }

    #[tokio::test]
    async fn runtime_permit_is_retained_across_upgrade_and_shutdown_closes_the_session() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start_with_connection_capacity(
            temp.path().join("state/relay.sqlite3"),
            1,
        )
        .await
        .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let mut first = open_websocket(&host).await;
        assert_eq!(recv_json(&mut first).await[0], "AUTH");

        let (second_server, _second_client) = duplex(1024);
        assert_eq!(
            host.try_serve(second_server),
            Err(ConnectionAdmissionError::AtCapacity)
        );
        runtime.trigger_shutdown();
        let (third_server, _third_client) = duplex(1024);
        assert_eq!(
            host.try_serve(third_server),
            Err(ConnectionAdmissionError::ShuttingDown)
        );
        let mut shutdown = Box::pin(runtime.shutdown());
        let closed = tokio::select! {
            biased;
            message = first.next() => message,
            result = &mut shutdown => panic!("runtime completed before closing upgraded session: {result:?}"),
        };
        assert!(matches!(closed, Some(Ok(Message::Close(_))) | None));
        shutdown.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_bounds_an_admitted_partial_http_upgrade() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start_with_connection_capacity(
            temp.path().join("state/relay.sqlite3"),
            1,
        )
        .await
        .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let (server, mut client) = duplex(1024);
        host.try_serve(server).unwrap();
        client
            .write_all(b"GET /relay HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        runtime.trigger_shutdown();
        tokio::time::timeout(Duration::from_secs(1), runtime.shutdown())
            .await
            .expect("partial HTTP upgrade prevented shutdown")
            .unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut bytes))
            .await
            .expect("partial HTTP client remained open")
            .unwrap();
    }

    #[tokio::test]
    async fn upgraded_route_enforces_binary_and_oversized_message_policy() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());

        let mut binary = open_websocket(&host).await;
        assert_eq!(recv_json(&mut binary).await[0], "AUTH");
        binary
            .send(Message::Binary(vec![1, 2, 3].into()))
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), binary.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(closed, Message::Close(_)));

        let mut oversized = open_websocket(&host).await;
        assert_eq!(recv_json(&mut oversized).await[0], "AUTH");
        oversized
            .send(Message::Text(
                "x".repeat(crate::connection::MAX_FRAME_BYTES + 1).into(),
            ))
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), oversized.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(closed, Message::Close(_)));
        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn exact_http_upgrade_still_rejects_wrong_nip42_relay_urls() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let wrong_tags = [
            format!("wss://{HOST}/relay"),
            "ws://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/relay".to_owned(),
            format!("ws://{HOST}:80/relay"),
            format!("ws://{HOST}/other"),
            format!("ws://{HOST}/relay?x=1"),
            format!("ws://{HOST}/relay/"),
        ];
        let keys = Keys::parse(&"22".repeat(32)).unwrap();
        for wrong_tag in wrong_tags {
            let mut socket = open_websocket(&host).await;
            let challenge = recv_json(&mut socket).await;
            assert_eq!(challenge[0], "AUTH");
            let auth = EventBuilder::new(Kind::Authentication, "")
                .tags([
                    Tag::parse(["challenge", challenge[1].as_str().unwrap()]).unwrap(),
                    Tag::parse(["relay", wrong_tag.as_str()]).unwrap(),
                ])
                .custom_created_at(Timestamp::now())
                .sign_with_keys(&keys)
                .unwrap();
            socket
                .send(Message::Text(json!(["AUTH", auth]).to_string().into()))
                .await
                .unwrap();
            let rejection = recv_json(&mut socket).await;
            assert_eq!(rejection[0], "OK");
            assert_eq!(
                rejection[2], false,
                "wrong relay URL was accepted: {}",
                wrong_tag
            );
        }
        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn raw_header_observation_stops_at_terminator_and_preserves_upgrade_read_ahead() {
        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start(temp.path().join("state/relay.sqlite3"))
            .await
            .unwrap();
        let host = OnionHttpHost::new(HOST, runtime.handle());
        let (server, mut client) = duplex(32 * 1024);
        host.try_serve(server).unwrap();
        let mut bytes = request(
            "GET",
            "/relay",
            "Connection: keep-alive\r\nConnection: uPgRaDe\r\nUpgrade: h2c\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        )
        .into_bytes();
        bytes.extend(masked_text_frame(
            "x".repeat(MAX_HTTP_BUFFER_BYTES + 1).as_bytes(),
        ));
        client.write_all(&bytes).await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            response.push(byte[0]);
        }
        let response = String::from_utf8(response).unwrap().to_ascii_lowercase();
        assert!(response.starts_with("http/1.1 101"), "{response}");
        assert!(response.contains("sec-websocket-accept:"));

        let mut websocket = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        assert_eq!(recv_json(&mut websocket).await[0], "AUTH");
        let close = tokio::time::timeout(Duration::from_secs(2), websocket.next())
            .await
            .expect("coalesced frame did not reach the WebSocket driver")
            .expect("socket ended without a policy close")
            .expect("WebSocket protocol error prevented an observable policy close");
        assert!(matches!(close, Message::Close(_)));
        runtime.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn request_framing_requires_http11_and_lexical_zero_content_length() {
        assert_eq!(
            raw_request(&request("GET", "/", "Content-Length: 0\r\n"))
                .await
                .status,
            200
        );
        for raw in [
            format!("GET / HTTP/1.0\r\nHost: {HOST}\r\n\r\n"),
            request("GET", "/", "Content-Length: 00\r\n"),
            request("GET", "/", "Content-Length: 0, 0\r\n"),
            request("GET", "/", "Content-Length: 0\r\nContent-Length: 0\r\n"),
        ] {
            assert_ne!(
                raw_request(&raw).await.status,
                200,
                "framing was accepted: {raw:?}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_oversized_and_slow_headers_never_reach_routes_or_add_date() {
        let malformed = raw_request(&format!("GET / HTTP/1.1\r\nHost {HOST}\r\n\r\n")).await;
        assert_ne!(malformed.status, 200);
        assert!(malformed.body.is_empty());
        assert!(!malformed.headers.to_ascii_lowercase().contains("\r\ndate:"));

        let oversized = raw_request(&format!(
            "GET / HTTP/1.1\r\nHost: {HOST}\r\nX-Padding: {}\r\n\r\n",
            "x".repeat(MAX_HTTP_BUFFER_BYTES + 1)
        ))
        .await;
        assert_ne!(oversized.status, 200);
        assert!(oversized.body.is_empty());
        assert!(!oversized.headers.to_ascii_lowercase().contains("\r\ndate:"));

        let temp = TempDir::new().unwrap();
        let runtime = RelayRuntime::start(temp.path().join("slow/relay.sqlite3"))
            .await
            .unwrap();
        let (server, mut client) = duplex(1024);
        let server = tokio::spawn(serve_http_stream(
            server,
            Arc::from(HOST),
            RelayContext::new(HOST, &runtime.handle()),
            Duration::from_millis(25),
        ));
        client.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut bytes))
            .await
            .expect("slow header was not bounded")
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes)
                .to_ascii_lowercase()
                .contains("\r\ndate:")
        );
        server.await.unwrap();
        runtime.shutdown().await.unwrap();
    }
}
