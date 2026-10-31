//! Physical guest retirement may precede another socket's already accepted receipt.

use super::*;
use crate::signaling::{Event, ReceivedSignal, RequestId, websocket::SocketError};
use futures_util::FutureExt;
use std::{
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

/// A late receipt cannot panic the relay or prevent the other original guest from progressing.
#[tokio::test]
async fn late_receipt_after_physical_guest_close_keeps_other_sockets_live() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let host_id = Uuid::from_u128(1);
        let guest_ids = [Uuid::from_u128(2), Uuid::from_u128(3)];
        let (mut host, mut host_peer) = super::super::pair(1).await;
        let (mut first, first_peer) = super::super::pair(2).await;
        let (mut second, second_peer) = super::super::pair(3).await;
        let relay = AssertUnwindSafe(activation(
            host_peer.socket.take().unwrap(),
            host_id,
            [first_peer, second_peer],
            guest_ids,
        ))
        .catch_unwind();
        let application = async {
            let deadline = Instant::now() + Duration::from_secs(10);
            let result = async {
                let request = first
                    .send_signal(host_id, Uuid::new_v4(), "original offer", false, deadline)
                    .map_err(|_| SocketError::Protocol)?;
                let (signal, accepted) =
                    tokio::join!(receive(&mut host), completed(&mut first, request));
                let signal = signal?;
                accepted?;
                if signal.sender() != guest_ids[0] || signal.signal() != "original offer" {
                    return Err(SocketError::Protocol);
                }
                first.close();
                if first.drive().await.err() != Some(SocketError::Closed) {
                    return Err(SocketError::Protocol);
                }
                // The relay has physically retired this guest before the original receipt is admitted.
                let receipt = host
                    .acknowledge(&signal, Uuid::new_v4(), deadline)
                    .map_err(|_| SocketError::Protocol)?;
                completed(&mut host, receipt).await?;
                let request = second
                    .request_credentials(deadline)
                    .map_err(|_| SocketError::Protocol)?;
                completed(&mut second, request).await?;
                if !second
                    .credentials()
                    .is_some_and(|credentials| credentials.servers().is_empty())
                {
                    return Err(SocketError::Protocol);
                }
                Ok::<_, SocketError>(())
            }
            .await;
            let mut terminals = Vec::new();
            for socket in [&mut first, &mut second, &mut host] {
                socket.close();
                terminals.push(socket.drive().await.err());
            }
            drop((host, first, second));
            (result, terminals)
        };
        let ((result, terminals), relay) = tokio::join!(application, relay);
        result.expect("late receipt prevented another original socket from progressing");
        assert!(
            terminals
                .iter()
                .all(|terminal| *terminal == Some(SocketError::Closed))
        );
        let (host, guests) = relay.expect("relay panicked after a physically closed recipient");
        assert!(std::iter::once(host).chain(guests).all(|terminal| matches!(
            terminal,
            HostedSocketTerminal::Close | HostedSocketTerminal::Eof
        )));
    })
    .await
    .expect("finite original relay retirement control stalled");
}

/// Observes only the original request's actual service completion.
async fn completed(
    socket: &mut crate::signaling::websocket::MessagingSocket,
    expected: RequestId,
) -> Result<(), SocketError> {
    loop {
        if let Event::Completed { request, result } = socket.drive().await? {
            return if request == expected && result.is_ok() {
                Ok(())
            } else {
                Err(SocketError::Protocol)
            };
        }
    }
}

/// Retains the actual received signal while the sending guest closes its physical socket.
async fn receive(
    socket: &mut crate::signaling::websocket::MessagingSocket,
) -> Result<ReceivedSignal, SocketError> {
    loop {
        if let Event::Signal(signal) = socket.drive().await? {
            return Ok(signal);
        }
    }
}

/// Deterministically reports a write that cannot progress while preserving readable transport input.
struct BlockWrites<S> {
    inner: S,
    blocked: std::sync::Arc<tokio::sync::Notify>,
}

impl<S: AsyncRead + Unpin> AsyncRead for BlockWrites<S> {
    /// Reads the original stream independently of its blocked writer.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: Unpin> AsyncWrite for BlockWrites<S> {
    /// Makes backpressure observable without filling operating-system buffers or sleeping.
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.blocked.notify_one();
        Poll::Pending
    }
    /// Retains an unfinished flush on this physical writer.
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    /// Retains an unfinished shutdown on this physical writer.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

/// Actual codecs and an observable blocked writer for one original peer.
type BlockedPair = (
    WebSocketStream<tokio::io::DuplexStream>,
    WebSocketStream<BlockWrites<tokio::io::DuplexStream>>,
    std::sync::Arc<tokio::sync::Notify>,
);

/// Builds actual codecs around a deterministic backpressured transport.
fn blocked_pair() -> BlockedPair {
    let (client, server) = tokio::io::duplex(1024);
    let blocked = std::sync::Arc::new(tokio::sync::Notify::new());
    (
        tokio_websockets::ClientBuilder::new().take_over(client),
        tokio_websockets::ServerBuilder::new().serve(BlockWrites {
            inner: server,
            blocked: blocked.clone(),
        }),
        blocked,
    )
}

/// A stalled host recipient cannot prevent another original guest's TURN or close exchange.
#[tokio::test]
async fn blocked_activation_recipient_regression() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (host, relay_host, blocked) = blocked_pair();
        let (mut first, mut first_peer) = super::super::pair(2).await;
        let (mut second, mut second_peer) = super::super::pair(3).await;
        first_peer
            .socket
            .as_mut()
            .unwrap()
            .get_mut()
            .set_nodelay(true)
            .unwrap();
        second_peer
            .socket
            .as_mut()
            .unwrap()
            .get_mut()
            .set_nodelay(true)
            .unwrap();
        let relay = activation(
            relay_host,
            Uuid::from_u128(1),
            [first_peer, second_peer],
            [Uuid::from_u128(2), Uuid::from_u128(3)],
        );
        let first_task = async {
            for _ in 0..MAX_PENDING_REQUESTS + 4 {
                let request = first
                    .send_signal(
                        Uuid::from_u128(1),
                        Uuid::new_v4(),
                        "offer",
                        false,
                        Instant::now() + Duration::from_secs(2),
                    )
                    .unwrap();
                completed(&mut first, request).await.unwrap();
            }
            first.close();
            assert_eq!(first.drive().await.err(), Some(SocketError::Closed));
        };
        let second_task = async {
            blocked.notified().await;
            let request = second
                .request_credentials(Instant::now() + Duration::from_secs(2))
                .unwrap();
            completed(&mut second, request).await.unwrap();
            second.close();
            assert_eq!(second.drive().await.err(), Some(SocketError::Closed));
        };
        let application = async {
            tokio::join!(first_task, second_task);
            drop(host);
        };
        tokio::join!(relay, application);
    })
    .await
    .expect("a blocked recipient stalled another activation socket");
}

/// Friend routing keeps processing the original sender while its recipient's writes are blocked.
#[tokio::test]
async fn blocked_friend_recipient_regression() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (visitor, relay_visitor, blocked) = blocked_pair();
        let (mut host, host_peer) = super::super::pair(1).await;
        let relay = friend::run(relay_visitor, host_peer, [Uuid::from_u128(2),Uuid::from_u128(1)]);
        let application = async {
            host.send_signal(Uuid::from_u128(2), Uuid::new_v4(), "offer", false, Instant::now()+Duration::from_secs(2)).unwrap();
            tokio::select! {
                _ = blocked.notified() => {},
                result = host.drive() => { assert!(matches!(result, Ok(Event::Completed{..}))); blocked.notified().await; }
            }
            let turn = host.request_credentials(Instant::now()+Duration::from_secs(2)).unwrap();
            loop {
                if let Event::Completed {request, result} = host.drive().await.unwrap() {
                    assert!(result.is_ok());
                    if request == turn { break; }
                }
            }
            host.close();
            assert_eq!(host.drive().await.err(), Some(SocketError::Closed));
            drop(visitor);
        };
        tokio::join!(relay, application);
    }).await.expect("a blocked recipient stalled the original friend sender");
}

/// A permanently pending writer is retired within its own finite deadline.
#[tokio::test(start_paused = true)]
async fn blocked_writer_has_a_finite_retirement_deadline() {
    let (_client, server, blocked) = blocked_pair();
    let mut socket = RelaySocket::new(Some(server));
    send(&mut socket, json!({"jsonrpc":"2.0","id":1,"result":null})).unwrap();
    tokio::select! {
        _ = blocked.notified() => {},
        _ = read(&mut socket) => panic!("blocked writer completed without a deadline"),
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(matches!(
        read(&mut socket).await,
        Frame::Terminal(HostedSocketTerminal::Io(std::io::ErrorKind::TimedOut))
    ));
    assert!(socket.socket.is_none());
}
