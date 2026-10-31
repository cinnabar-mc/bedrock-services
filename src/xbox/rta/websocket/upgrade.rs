use super::{Options, SocketError};
use crate::{
    websocket_io::{MAX_UPGRADE_BYTES, UpgradeIo},
    xbox::rta::ConnectionRequest,
};
use aws_lc_rs::digest;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_websockets::{ClientBuilder, Config, Limits, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

pub(super) type Socket = WebSocketStream<BufReader<UpgradeIo<MaybeTlsStream<TcpStream>>>>;
/// RFC 6455's fixed accept challenge suffix, used only for HTTP upgrade validation.
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Generates the complete transport fields before the account adds authorization and signs.
pub(super) fn headers() -> Result<HeaderMap, SocketError> {
    let endpoint = url::Url::parse(super::super::connection::ENDPOINT)
        .map_err(|_| SocketError::Configuration)?;
    let authority = &endpoint[url::Position::BeforeHost..url::Position::AfterPort];
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        HeaderValue::from_str(authority).map_err(|_| SocketError::Configuration)?,
    );
    for (name, value) in [
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        (
            "sec-websocket-protocol",
            super::super::connection::SUBPROTOCOL,
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    let key: [u8; 16] = rand::random();
    headers.insert(
        "sec-websocket-key",
        HeaderValue::from_str(&STANDARD.encode(key)).map_err(|_| SocketError::Configuration)?,
    );
    Ok(headers)
}

/// Encodes the signed fields verbatim, without HTTP-client defaults or replacement keys.
fn encode_request(url: &url::Url, headers: &HeaderMap) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"GET ");
    bytes.extend_from_slice(url.path().as_bytes());
    if let Some(query) = url.query() {
        bytes.push(b'?');
        bytes.extend_from_slice(query.as_bytes());
    }
    bytes.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers {
        bytes.extend_from_slice(name.as_str().as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}

/// Requires exactly one challenge or negotiated field, rejecting ambiguous duplicates.
fn single<'a>(headers: &[httparse::Header<'a>], name: &str) -> Result<&'a [u8], SocketError> {
    let mut values = headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = values.next().ok_or(SocketError::Protocol)?.value;
    if values.next().is_some() {
        return Err(SocketError::Protocol);
    }
    Ok(value)
}

/// Checks the response against the exact already-signed key, without retaining server diagnostics.
fn validate_response(bytes: &[u8], request: &ConnectionRequest) -> Result<(), SocketError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    if !response
        .parse(bytes)
        .map_err(|_| SocketError::Protocol)?
        .is_complete()
    {
        return Err(SocketError::Protocol);
    }
    let code = response.code.ok_or(SocketError::Protocol)?;
    if code != 101 {
        return Err(SocketError::UpgradeStatus(code));
    }
    let key = request
        .headers()
        .get("sec-websocket-key")
        .ok_or(SocketError::Configuration)?;
    let mut hash = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    hash.update(key.as_bytes());
    hash.update(ACCEPT_GUID);
    let accept = STANDARD.encode(hash.finish().as_ref());
    let connected = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .filter_map(|header| std::str::from_utf8(header.value).ok())
        .any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    if response.version != Some(1)
        || !single(response.headers, "upgrade")?.eq_ignore_ascii_case(b"websocket")
        || !connected
        || single(response.headers, "sec-websocket-accept")? != accept.as_bytes()
        || single(response.headers, "sec-websocket-protocol")? != request.subprotocol().as_bytes()
        || response.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("sec-websocket-extensions")
                || h.name.eq_ignore_ascii_case("transfer-encoding")
                || (h.name.eq_ignore_ascii_case("content-length") && h.value != b"0")
        })
    {
        return Err(SocketError::Protocol);
    }
    Ok(())
}

/// Sends one protected request and preserves any frame bytes buffered after its bounded response.
pub(super) async fn handshake(
    stream: MaybeTlsStream<TcpStream>,
    request: &ConnectionRequest,
) -> Result<Socket, SocketError> {
    let mut stream = BufReader::new(UpgradeIo::new(stream));
    let bytes = encode_request(request.url(), request.headers());
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| SocketError::Transport)?;
    stream.flush().await.map_err(|_| SocketError::Transport)?;
    drop(bytes);
    let mut response = Vec::new();
    loop {
        let count = stream.read_until(b'\n', &mut response).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                SocketError::Capacity
            } else {
                SocketError::Transport
            }
        })?;
        if count == 0 {
            return Err(SocketError::Transport);
        }
        if response.len() > MAX_UPGRADE_BYTES {
            return Err(SocketError::Capacity);
        }
        if !response.ends_with(b"\r\n") {
            return Err(SocketError::Protocol);
        }
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    validate_response(&response, request)?;
    stream.get_mut().upgraded();
    Ok(ClientBuilder::new()
        .config(
            Config::default()
                .frame_size(super::super::MAX_MESSAGE_BYTES)
                .flush_threshold(1),
        )
        .limits(Limits::default().max_payload_len(Some(super::super::MAX_MESSAGE_BYTES)))
        .take_over(stream))
}

/// Owns DNS/TCP/verified TLS/upgrade until completion or cancellation, following no redirects.
pub(super) async fn connect(
    request: &ConnectionRequest,
    options: Options,
) -> Result<Socket, SocketError> {
    let url = request.url();
    let host = url.host_str().ok_or(SocketError::Configuration)?;
    let port = url
        .port_or_known_default()
        .ok_or(SocketError::Configuration)?;
    let connector = crate::websocket_io::connector().map_err(|_| SocketError::Configuration)?;
    tokio::time::timeout(options.connect_timeout, async {
        #[cfg(test)]
        if let Some((address, ca)) = &request.trace_transport {
            let pem = std::str::from_utf8(ca).map_err(|_| SocketError::Configuration)?;
            let der = STANDARD
                .decode(
                    pem.lines()
                        .filter(|line| !line.starts_with('-'))
                        .collect::<String>(),
                )
                .map_err(|_| SocketError::Configuration)?;
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots
                .add(tokio_rustls::rustls::pki_types::CertificateDer::from(der))
                .map_err(|_| SocketError::Configuration)?;
            let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(
                std::sync::Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()),
            )
            .with_safe_default_protocol_versions()
            .map_err(|_| SocketError::Configuration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = tokio_websockets::Connector::Rustls(std::sync::Arc::new(config).into());
            let tcp = TcpStream::connect(address)
                .await
                .map_err(|_| SocketError::Transport)?;
            let stream = connector
                .wrap(host, tcp)
                .await
                .map_err(SocketError::from_wire)?;
            return handshake(stream, request).await;
        }
        #[cfg(feature = "test-support")]
        if let Some(transport) = &request.hosted_transport {
            let stream = transport
                .socket(
                    url,
                    crate::test_support::activation::transport::SocketKind::Rta,
                )
                .await
                .map_err(|_| SocketError::Transport)?;
            return handshake(stream, request).await;
        }
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|_| SocketError::Transport)?;
        let stream = connector
            .wrap(host, tcp)
            .await
            .map_err(SocketError::from_wire)?;
        handshake(stream, request).await
    })
    .await
    .map_err(|_| SocketError::TimedOut)?
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
