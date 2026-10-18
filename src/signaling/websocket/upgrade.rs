use super::{Options, SocketError};
use crate::signaling::{ConnectionRequest, MAX_MESSAGE_BYTES, connection::websocket_url};
use std::io;
use tokio::net::TcpStream;
use tokio_websockets::{ClientBuilder, Config, Limits, MaybeTlsStream, WebSocketStream};

#[cfg(test)]
pub(super) use crate::websocket_io::MAX_UPGRADE_BYTES;
pub(super) use crate::websocket_io::UpgradeIo;

pub(super) type Socket = WebSocketStream<UpgradeIo<MaybeTlsStream<TcpStream>>>;

/// Revalidates the credential destination immediately before constructing the protected request.
pub(super) fn builder(
    url: &url::Url,
    mut authorization: reqwest::header::HeaderValue,
) -> Result<ClientBuilder<'static>, SocketError> {
    let url = websocket_url(url.as_str()).map_err(|_| SocketError::Configuration)?;
    authorization.set_sensitive(true);
    ClientBuilder::new()
        .uri(url.as_str())
        .map_err(|_| SocketError::Configuration)?
        .config(
            Config::default()
                .frame_size(MAX_MESSAGE_BYTES)
                .flush_threshold(1),
        )
        .limits(Limits::default().max_payload_len(Some(MAX_MESSAGE_BYTES)))
        .add_header(reqwest::header::AUTHORIZATION, authorization)
        .map_err(|_| SocketError::Configuration)
}

/// Requires the negotiated HTTP upgrade and rejects unrequested extensions/subprotocols.
pub(super) fn validate_upgrade(
    response: &tokio_websockets::upgrade::Response,
) -> Result<(), SocketError> {
    use reqwest::header::{CONNECTION, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL, UPGRADE};
    let headers = response.headers();
    let upgraded = headers
        .get(UPGRADE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let connected = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    if response.version() != reqwest::Version::HTTP_11
        || !upgraded
        || !connected
        || headers.contains_key(SEC_WEBSOCKET_EXTENSIONS)
        || headers.contains_key(SEC_WEBSOCKET_PROTOCOL)
    {
        return Err(SocketError::Protocol);
    }
    Ok(())
}

/// Owns TCP, verified TLS and one HTTP upgrade until it succeeds or its future is dropped.
pub(super) async fn connect(
    request: &ConnectionRequest,
    options: Options,
) -> Result<Socket, SocketError> {
    let builder = builder(
        request.url(),
        request
            .authorization()
            .map_err(|_| SocketError::Configuration)?,
    )?;
    let url = request.url();
    let host = url
        .host_str()
        .ok_or(SocketError::Configuration)?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url
        .port_or_known_default()
        .ok_or(SocketError::Configuration)?;
    let connector = crate::websocket_io::connector().map_err(|_| SocketError::Configuration)?;
    tokio::time::timeout(options.connect_timeout, async {
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|_| SocketError::Transport)?;
        let tls = connector
            .wrap(host, tcp)
            .await
            .map_err(SocketError::from_wire)?;
        let (mut socket, response) =
            builder
                .connect_on(UpgradeIo::new(tls))
                .await
                .map_err(|error| match error {
                    tokio_websockets::Error::Io(ref io)
                        if io.kind() == io::ErrorKind::InvalidData =>
                    {
                        SocketError::Capacity
                    }
                    error => SocketError::from_wire(error),
                })?;
        validate_upgrade(&response)?;
        socket.get_mut().upgraded();
        Ok(socket)
    })
    .await
    .map_err(|_| SocketError::TimedOut)?
}
