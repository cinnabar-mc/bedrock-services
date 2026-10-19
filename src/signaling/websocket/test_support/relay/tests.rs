//! Physical guest retirement may precede another socket's already accepted receipt.

use super::*;
use crate::signaling::{Event, ReceivedSignal, RequestId, websocket::SocketError};
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
