use super::{Options, SocketError};
use crate::signaling::{ConnectionRequest, MAX_MESSAGE_BYTES, connection::websocket_url};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use tokio_websockets::{ClientBuilder, Config, Connector, Limits, MaybeTlsStream, WebSocketStream};

/// Limits incomplete HTTP upgrade headers without changing WebSocket framing.
pub(super) const MAX_UPGRADE_BYTES: usize = 32 * 1024;

pub(super) type Socket = WebSocketStream<UpgradeIo<MaybeTlsStream<TcpStream>>>;

/// HTTP parsing has a byte budget; successful upgrade restores ordinary socket reads.
pub(super) struct UpgradeIo<T> {
    inner: T,
    remaining: Option<usize>,
    #[cfg(test)]
    writes_blocked: bool,
    #[cfg(test)]
    write_waker: Option<std::task::Waker>,
}

impl<T> UpgradeIo<T> {
    pub(super) fn new(inner: T) -> Self {
        Self {
            inner,
            remaining: Some(MAX_UPGRADE_BYTES),
            #[cfg(test)]
            writes_blocked: false,
            #[cfg(test)]
            write_waker: None,
        }
    }

    pub(super) fn upgraded(&mut self) {
        self.remaining = None;
    }

    /// Holds writes Pending so tests can control pressure without depending on socket buffer sizes.
    #[cfg(test)]
    pub(super) fn block_writes(&mut self) {
        self.writes_blocked = true;
    }

    /// Releases write pressure and notifies the most recent registered writer.
    #[cfg(test)]
    pub(super) fn resume_writes(&mut self) {
        self.writes_blocked = false;
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for UpgradeIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(remaining) = this.remaining else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        // A small initialized scratch buffer keeps the bound safe without unsafe ReadBuf bookkeeping.
        let mut scratch = [0; 4096];
        let count = remaining.min(buf.remaining()).min(scratch.len());
        let mut read = ReadBuf::new(&mut scratch[..count]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                this.remaining = Some(remaining - read.filled().len());
                buf.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for UpgradeIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        #[cfg(test)]
        if this.writes_blocked {
            this.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

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
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| SocketError::Configuration)?
        .with_root_certificates(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
        .with_no_client_auth();
    let connector = Connector::Rustls(tokio_rustls::TlsConnector::from(Arc::new(config)));
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
