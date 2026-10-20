//! Original verified RTA socket and exact canonical legacy upgrade metadata.

use super::*;
use futures_util::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::{Message, WebSocketStream};

/// Reads only one canonical nonzero local ID on the exact fixed signaling origin/path.
/// The original ConnectionRequest and MessagingSocket independently bind that ID to their caller.
pub(in super::super) fn legacy_id(url: &url::Url) -> Option<u64> {
    let mut expected = url::Url::parse(SIGNALING_ORIGIN).unwrap();
    expected.set_scheme("wss").ok()?;
    if url.scheme() != "wss"
        || url.origin() != expected.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let value = url.path().strip_prefix("/ws/v1.0/signaling/")?;
    let id = value.parse::<u64>().ok().filter(|id| *id != 0)?;
    (id.to_string() == value).then_some(id)
}

/// Acknowledges the real original subscription, then publishes at most one actual shoulder tap.
pub(in super::super) async fn rta<S>(
    mut socket: WebSocketStream<S>,
    state: Shared,
    sequence: Value,
) -> HostedSocketTerminal
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(terminal) = admit(&mut socket, state, sequence).await {
        return terminal;
    }
    super::super::sockets::terminal(&mut socket).await
}

/// Flushes the original acknowledgment and service-owned nonce tap without replacing its socket.
pub(in super::super) async fn admit<S>(
    socket: &mut WebSocketStream<S>,
    state: Shared,
    sequence: Value,
) -> Result<(), HostedSocketTerminal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut admit = state
        .lock()
        .unwrap()
        .friend
        .as_mut()
        .unwrap()
        .admit
        .take()
        .unwrap();
    socket
        .send(Message::text(
            json!([1,sequence,0,19,
        {"ConnectionId":super::super::super::script::CONNECTION}])
            .to_string(),
        ))
        .await
        .unwrap();
    let admitted = tokio::select! {
        release = &mut admit => release.is_ok(),
        terminal = super::super::sockets::terminal(socket) => return Err(terminal),
    };
    if admitted {
        let tap = {
            let mut state = state.lock().unwrap();
            let friend = state.friend.as_mut().unwrap();
            assert_eq!(friend.joins, 1);
            assert_eq!(friend.leaves, 0);
            friend.nonce_available = true;
            let reference = state.reference.as_ref().unwrap();
            json!([3,19,{"shoulderTaps":[{"resource":format!("{}~{}~{}",
                reference.service_config_id(),reference.template_name(),reference.name()),
                "branch":BRANCH,"changeNumber":2}]}])
        };
        socket.send(Message::text(tap.to_string())).await.unwrap();
    }
    Ok(())
}
