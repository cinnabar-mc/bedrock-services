use super::super::test_support::{acceptor, connector, request};
use super::*;
use tokio::{io::AsyncReadExt, net::TcpListener};

/// Reads the complete original protected request, retaining no live credential or public destination.
async fn read_request(stream: &mut tokio_rustls::server::TlsStream<TcpStream>) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        bytes.push(byte);
        assert!(bytes.len() <= MAX_UPGRADE_BYTES);
        if bytes.ends_with(b"\r\n\r\n") {
            return bytes;
        }
    }
}

/// Independent fixture response to the generated challenge, with explicit changes for rejection cases.
fn response(request: &ConnectionRequest, status: u16, extra: &str) -> Vec<u8> {
    let mut hash = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    hash.update(request.headers()["sec-websocket-key"].as_bytes());
    hash.update(ACCEPT_GUID);
    let accept = STANDARD.encode(hash.finish().as_ref());
    format!("HTTP/1.1 {status} Fixture\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {}\r\n{extra}\r\n", request.subprotocol()).into_bytes()
}

/// Sends actual TLS HTTP bytes to the production bounded parser, without starting an RTA epoch on rejection.
async fn exchange(request: &ConnectionRequest, response: Vec<u8>) -> Result<Socket, SocketError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let connector = connector();
    let acceptor = acceptor();
    let (client, server) = tokio::join!(connector.wrap("localhost", tcp), acceptor.accept(server));
    let mut server = server.unwrap();
    let expected = encode_request(request.url(), request.headers());
    let (result, ()) = tokio::join!(handshake(client.unwrap(), request), async {
        assert_eq!(read_request(&mut server).await, *expected);
        // Invalid responses can cause the client to close before the full oversized reply is written.
        let _ = server.write_all(&response).await;
        let _ = server.flush().await;
    });
    result
}

/// Accept/subprotocol/HTTP version and duplicate/body/extension ambiguity are rejected over actual TLS.
#[tokio::test]
async fn validates_exact_accept_subprotocol_and_refused_status_without_starting_epoch() {
    let (_, request) = request().await;
    let valid = response(&request, 101, "");
    let mut cases = vec![
        (response(&request, 401, ""), SocketError::UpgradeStatus(401)),
        (
            response(&request, 302, "Location: https://untrusted.invalid/\r\n"),
            SocketError::UpgradeStatus(302),
        ),
        (
            response(&request, 101, "Sec-WebSocket-Accept: wrong\r\n"),
            SocketError::Protocol,
        ),
        (
            response(&request, 101, "Sec-WebSocket-Protocol: unexpected\r\n"),
            SocketError::Protocol,
        ),
        (
            response(
                &request,
                101,
                "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            ),
            SocketError::Protocol,
        ),
        (
            response(&request, 101, "Content-Length: 1\r\n"),
            SocketError::Protocol,
        ),
        (
            response(&request, 101, "Transfer-Encoding: chunked\r\n"),
            SocketError::Protocol,
        ),
    ];
    let text = String::from_utf8(valid.clone()).unwrap();
    cases.push((
        text.replacen("HTTP/1.1", "HTTP/1.0", 1).into_bytes(),
        SocketError::Protocol,
    ));
    cases.push((
        text.replace(request.subprotocol(), "unexpected")
            .into_bytes(),
        SocketError::Protocol,
    ));
    let accept = text
        .lines()
        .find(|line| line.starts_with("Sec-WebSocket-Accept:"))
        .unwrap();
    cases.push((
        text.replace(accept, "Sec-WebSocket-Accept: wrong")
            .into_bytes(),
        SocketError::Protocol,
    ));
    cases.push((
        text.replace(
            &format!("Sec-WebSocket-Protocol: {}\r\n", request.subprotocol()),
            "",
        )
        .into_bytes(),
        SocketError::Protocol,
    ));
    cases.push((
        text.replace("\r\n", "\n").into_bytes(),
        SocketError::Protocol,
    ));
    for (bytes, expected) in cases {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            exchange(&request, bytes),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(error) if error == expected));
        assert!(request.unused().is_ok());
    }
    assert!(exchange(&request, valid).await.is_ok());
    assert!(
        request.unused().is_ok(),
        "an uninstalled verified stream does not consume state ownership"
    );
}

/// Bounds incomplete header bytes and preserves an application frame coalesced with the upgrade response.
#[tokio::test]
async fn bounds_headers_and_retains_first_frame_buffered_with_upgrade() {
    let (_, request) = request().await;
    let huge = format!(
        "HTTP/1.1 101 Fixture\r\nX-Fill: {}",
        "x".repeat(MAX_UPGRADE_BYTES + 1)
    )
    .into_bytes();
    assert!(matches!(
        exchange(&request, huge).await,
        Err(SocketError::Capacity)
    ));
    let mut bytes = response(&request, 101, "");
    let payload = b"[4]";
    bytes.extend_from_slice(&[0x81, payload.len() as u8]);
    bytes.extend_from_slice(payload);
    let mut socket = exchange(&request, bytes).await.unwrap();
    let message = futures_util::StreamExt::next(&mut socket)
        .await
        .unwrap()
        .unwrap();
    assert!(message.is_text());
    assert_eq!(&**message.as_payload(), payload);
}

/// Neither an untrusted root nor a mismatching hostname can reach the protected HTTP writer.
#[tokio::test]
async fn verified_tls_rejects_untrusted_root_and_wrong_hostname() {
    for trusted in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let connector = if trusted {
            connector()
        } else {
            crate::websocket_io::connector().unwrap()
        };
        let host = if trusted {
            "other.invalid"
        } else {
            "localhost"
        };
        let acceptor = acceptor();
        let (client, server) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(connector.wrap(host, tcp), acceptor.accept(server))
        })
        .await
        .unwrap();
        assert_eq!(
            SocketError::from_wire(client.unwrap_err()),
            SocketError::Configuration
        );
        assert!(server.is_err());
    }
}
