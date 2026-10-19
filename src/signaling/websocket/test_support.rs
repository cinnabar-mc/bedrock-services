//! Fixed loopback MessagingSocket fixture; it supplies no retail identity or admission authority.
//!
//! Both sockets use the actual bounded codec and remain caller-polled. No runtime,
//! task, endpoint override or certificate change is installed by this helper.

use super::{MessagingSocket, Options, SocketError, upgrade};
use crate::signaling::MAX_MESSAGE_BYTES;
use futures_util::{SinkExt, StreamExt};
use reqwest::header::HeaderValue;
use std::time::Duration;
use tokio::{
    net::{TcpListener, TcpStream},
    time::Instant,
};
use tokio_websockets::{Config, Limits, MaybeTlsStream, Message, ServerBuilder, WebSocketStream};

/// Owns one synthetic service peer; dropping it drops only its actual loopback socket.
/// This is a test peer, not a configurable service client or verified account.
pub struct Peer {
    socket: Option<WebSocketStream<TcpStream>>,
    close_deadline: Option<Instant>,
}

/// Opens the actual bounded SDK edge and a caller-owned loopback service peer.
/// The network ID is framing metadata only. A fixed synthetic header is checked
/// by the peer; no credential, TLS validation or session approval is performed.
/// Panics on local fixture setup failure; all network I/O remains on loopback.
pub async fn pair(network_id: u64) -> (MessagingSocket, Peer) {
    let (socket, peer) = pair_with_initial(network_id, None).await;
    (
        socket,
        Peer {
            socket: Some(peer),
            close_deadline: None,
        },
    )
}

impl Peer {
    /// Sends and flushes one bounded text frame through the real service socket.
    /// A canceled wait leaves any accepted partial frame in the existing codec.
    pub async fn send_text(&mut self, text: &str) -> Result<(), SocketError> {
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(SocketError::Capacity);
        }
        if self.close_deadline.is_some() {
            return Err(SocketError::Closed);
        }
        self.socket
            .as_mut()
            .ok_or(SocketError::Closed)?
            .send(Message::text(text.to_owned()))
            .await
            .map_err(SocketError::from_wire)
    }

    /// Reads exactly one text frame without silently discarding other frame kinds.
    /// None reports observed EOF/Close; call close to flush any pending close reply.
    pub async fn recv_text(&mut self) -> Result<Option<String>, SocketError> {
        let Some(socket) = self.socket.as_mut() else {
            return Ok(None);
        };
        match socket.next().await {
            Some(Ok(message)) if message.is_text() => std::str::from_utf8(message.as_payload())
                .map(|text| Some(text.to_owned()))
                .map_err(|_| SocketError::Protocol),
            Some(Ok(message)) if message.is_close() => Ok(None),
            Some(Ok(_)) => Err(SocketError::Protocol),
            Some(Err(error)) => Err(SocketError::from_wire(error)),
            None => Ok(None),
        }
    }

    /// Flushes close under one retained finite cutoff, then retires the actual peer socket.
    /// Dropping this borrowed wait preserves both its original cutoff and codec state.
    pub async fn close(&mut self) -> Result<(), SocketError> {
        let Some(socket) = self.socket.as_mut() else {
            return Ok(());
        };
        let deadline = *self
            .close_deadline
            .get_or_insert_with(|| Instant::now() + Options::default().close_timeout);
        if Instant::now() >= deadline {
            self.socket = None;
            return Err(SocketError::TimedOut);
        }
        let result = tokio::time::timeout_at(deadline, socket.close()).await;
        self.socket = None;
        if Instant::now() >= deadline {
            return Err(SocketError::TimedOut);
        }
        result
            .map_err(|_| SocketError::TimedOut)?
            .map_err(SocketError::from_wire)
    }
}

/// Writes an optional first frame after the upgrade response before returning either owner.
pub(super) async fn pair_with_initial(
    network_id: u64,
    initial: Option<Message>,
) -> (MessagingSocket, WebSocketStream<TcpStream>) {
    tokio::time::timeout(Options::default().connect_timeout, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let url =
            url::Url::parse("wss://messaging.invalid/prefix/ws/v1.0/messaging/connect").unwrap();
        let builder =
            upgrade::builder(&url, HeaderValue::from_static("MCToken synthetic-only")).unwrap();
        let server_builder = ServerBuilder::new()
            .config(
                Config::default()
                    .frame_size(MAX_MESSAGE_BYTES)
                    .flush_threshold(1),
            )
            .limits(Limits::default().max_payload_len(Some(MAX_MESSAGE_BYTES)));
        let (client, server) = tokio::join!(
            builder.connect_on(upgrade::UpgradeIo::new(MaybeTlsStream::Plain(tcp))),
            async {
                let (request, mut socket) = server_builder.accept(server).await.unwrap();
                if let Some(message) = initial {
                    socket.send(message).await.unwrap();
                }
                (request, socket)
            },
        );
        let (mut socket, response) = client.unwrap();
        upgrade::validate_upgrade(&response).unwrap();
        socket.get_mut().upgraded();
        let (request, server) = server;
        assert_eq!(request.uri().path(), url.path());
        assert_eq!(
            request.headers()[reqwest::header::HOST],
            "messaging.invalid"
        );
        assert_eq!(
            request.headers()[reqwest::header::AUTHORIZATION],
            "MCToken synthetic-only"
        );
        (
            MessagingSocket::from_socket(
                socket,
                network_id,
                Duration::from_secs(3600),
                Options::default(),
            )
            .unwrap(),
            server,
        )
    })
    .await
    .expect("bounded loopback messaging fixture setup")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::{Event, wire};
    use serde_json::{Value, json};
    use uuid::Uuid;

    /// The public fixture exchanges real JSON-RPC with its caller's network ID and closes both owners.
    #[tokio::test]
    async fn loopback_pair_drives_actual_messaging_and_bounded_peer_close() {
        let network_id = 9;
        let (mut socket, mut peer) = pair(network_id).await;
        let request = socket
            .send_signal(
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                "fixture-offer",
                false,
                std::time::Instant::now() + Options::default().connect_timeout,
            )
            .unwrap();
        let application = async {
            assert!(
                matches!(socket.drive().await.unwrap(), Event::Completed { request: got, result: Ok(()) } if got == request)
            );
            socket.close();
            assert_eq!(socket.drive().await.err(), Some(SocketError::Closed));
        };
        let service = async {
            let text = peer.recv_text().await.unwrap().unwrap();
            let envelope: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(envelope["method"], wire::SEND);
            let inner: Value =
                serde_json::from_str(envelope["params"]["message"].as_str().unwrap()).unwrap();
            assert_eq!(inner["method"], wire::WEBRTC);
            assert_eq!(inner["params"]["netherNetId"], network_id.to_string());
            assert_eq!(inner["params"]["message"], "fixture-offer");
            peer.send_text(
                &json!({"jsonrpc":"2.0", "id":envelope["id"], "result":null}).to_string(),
            )
            .await
            .unwrap();
            peer.close().await.unwrap();
            peer.close().await.unwrap();
        };
        tokio::time::timeout(Options::default().connect_timeout, async {
            tokio::join!(application, service);
        })
        .await
        .unwrap();
    }
}
