use hypertor::OnionApp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn health_route_serves_expected_json_without_a_tcp_listener() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let task =
        tokio::spawn(async move { onion_probe::health_app().serve_connection(server).await });

    client
        .write_all(b"GET /health HTTP/1.1\r\nHost: deaddrop.onion\r\nConnection: close\r\n\r\n")
        .await
        .expect("request should write");

    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("response should read");
    task.await
        .expect("server task should join")
        .expect("in-memory HTTP server should succeed");

    let response = String::from_utf8(response).expect("response should be UTF-8");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.ends_with("{\"service\":\"deaddrop-feasibility\",\"status\":\"ok\"}"));
}

#[test]
fn app_type_is_the_embedded_onion_http_app() {
    let _: OnionApp = onion_probe::health_app();
}
