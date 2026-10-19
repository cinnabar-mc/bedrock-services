//! Existing synthetic HTTP peers and independent signature checks shared by owning fixtures.

#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Serves a bounded sequence of synthetic HTTP exchanges on an ephemeral loopback port.
#[cfg(test)]
pub(crate) async fn fixture(
    mut handler: impl FnMut(&str, &str, &[u8]) -> (u16, Value) + Send + 'static,
    count: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    fixture_headers(
        move |target, headers, body| {
            let (status, body) = handler(target, headers, body);
            (status, Vec::new(), body)
        },
        count,
    )
    .await
}

/// Serves synthetic exchanges with explicit challenge headers using the same bounded reader.
pub(crate) async fn fixture_headers(
    mut handler: impl FnMut(&str, &str, &[u8]) -> (u16, Vec<(&'static str, &'static str)>, Value)
    + Send
    + 'static,
    count: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    fixture_bytes(
        move |target, header, body| {
            let (status, headers, body) = handler(target, header, body);
            let body = if status == 304 {
                Vec::new()
            } else {
                serde_json::to_vec(&body).unwrap()
            };
            (status, headers, body)
        },
        count,
    )
    .await
}

/// Consumes the complete Content-Length request before a fixture replies or closes its socket.
pub(crate) async fn read_request(stream: &mut TcpStream) -> (Vec<u8>, usize, usize) {
    let mut bytes = Vec::new();
    let (header_end, length) = loop {
        assert!(bytes.len() <= 1024 * 1024);
        assert_ne!(stream.read_buf(&mut bytes).await.unwrap(), 0);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let header = std::str::from_utf8(&bytes[..end]).unwrap();
            let length = header
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
            break (end + 4, length);
        }
    };
    while bytes.len() < header_end + length {
        assert_ne!(stream.read_buf(&mut bytes).await.unwrap(), 0);
    }
    (bytes, header_end, length)
}

/// Serves original bounded binary or JSON responses through the same concrete HTTP reader.
pub(crate) async fn fixture_bytes(
    mut handler: impl FnMut(&str, &str, &[u8]) -> (u16, Vec<(&'static str, &'static str)>, Vec<u8>)
    + Send
    + 'static,
    count: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (bytes, header_end, length) = read_request(&mut stream).await;
            let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let target = header
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let (status, response_headers, body) =
                handler(target, header, &bytes[header_end..header_end + length]);
            let extra = response_headers
                .into_iter()
                .map(|(name, value)| format!("{name}: {value}\r\n"))
                .collect::<String>();
            let content_length = if status == 304 {
                assert!(body.is_empty(), "304 responses have no message body");
                String::new()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let header = format!(
                "HTTP/1.1 {status} Fixture\r\n{content_length}Connection: close\r\n{extra}\r\n"
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    (address, task)
}

/// Produces original credentials with deliberately distant expiry and no account data.
pub(crate) fn token(value: &str, user: bool) -> Value {
    json!({"Token": value, "NotAfter": "2099-01-01T00:00:00Z",
        "DisplayClaims": if user { json!({"xui": [{"uhs": "synthetic", "xid": "123", "gtg": "Fixture"}]}) }
            else { json!({}) }})
}

/// Validates a signature independently from the production request/digest helpers.
#[cfg(test)]
pub(crate) fn verify_signature(
    target: &str,
    header: &str,
    body: &[u8],
    key: &Value,
    extra_headers: &[&str],
) {
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    use sha2::{Digest, Sha256};
    let value = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("signature"))
        .unwrap()
        .1
        .trim();
    let signature = STANDARD.decode(value).unwrap();
    assert_eq!(signature.len(), 76);
    assert_eq!(&signature[..4], &1_u32.to_be_bytes());
    let mut hash = Sha256::new();
    for field in [
        &signature[..4],
        &signature[4..12],
        b"POST",
        target.as_bytes(),
        b"",
    ] {
        hash.update(field);
        hash.update([0]);
    }
    for extra in extra_headers {
        let value = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case(extra))
            .unwrap()
            .1
            .trim();
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    hash.update(body);
    hash.update([0]);
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap()).unwrap());
    let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
    key.verify_prehash(
        &hash.finalize(),
        &Signature::from_slice(&signature[12..]).unwrap(),
    )
    .unwrap();
}
