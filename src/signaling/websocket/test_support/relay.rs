//! Fixed activation relay using the owning signaling wire definitions and actual socket codecs.

use super::Peer;
use crate::{
    signaling::{MAX_BATCH_MESSAGES, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, wire},
    test_support::HostedSocketTerminal,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{collections::HashSet, future::pending};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::{Message, WebSocketStream};
use uuid::Uuid;

enum Frame {
    Text(String),
    Control,
    Close,
    Terminal(HostedSocketTerminal),
}

/// Routes only the fixed host/guest pairs; every sender comes from its original physical socket.
pub(crate) async fn activation<S>(
    host: WebSocketStream<S>,
    host_id: Uuid,
    guests: [Peer; 2],
    guest_ids: [Uuid; 2],
) -> (HostedSocketTerminal, [HostedSocketTerminal; 2])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let [mut first, mut second] = guests;
    let mut host = Some(host);
    let identities = [host_id, guest_ids[0], guest_ids[1]];
    let mut terminals = [None, None, None];
    let mut callbacks: [HashSet<Uuid>; 3] = std::array::from_fn(|_| HashSet::new());
    while terminals.iter().any(Option::is_none) {
        let (source, frame) = tokio::select! {
            frame = read(&mut host) => (0, frame),
            frame = read(&mut first.socket) => (1, frame),
            frame = read(&mut second.socket) => (2, frame),
        };
        let text = match frame {
            Frame::Text(text) => text,
            Frame::Control => {
                let result = match source {
                    0 => flush(&mut host).await,
                    1 => flush(&mut first.socket).await,
                    _ => flush(&mut second.socket).await,
                };
                if let Err(terminal) = result {
                    terminals[source] = Some(terminal);
                }
                continue;
            }
            Frame::Close => {
                let terminal = match source {
                    0 => close(&mut host).await,
                    1 => close(&mut first.socket).await,
                    _ => close(&mut second.socket).await,
                };
                terminals[source] = Some(terminal);
                continue;
            }
            Frame::Terminal(terminal) => {
                terminals[source] = Some(terminal);
                match source {
                    0 => {
                        host = None;
                    }
                    1 => {
                        first.socket = None;
                    }
                    _ => {
                        second.socket = None;
                    }
                }
                continue;
            }
        };
        let value: Value = serde_json::from_str(&text).unwrap();
        let values = match value {
            Value::Array(values) => {
                assert!(!values.is_empty() && values.len() <= MAX_BATCH_MESSAGES);
                values
            }
            value => vec![value],
        };
        for value in values {
            assert_eq!(value["jsonrpc"], "2.0");
            let Some(method) = value["method"].as_str() else {
                let id = Uuid::parse_str(value["id"].as_str().unwrap()).unwrap();
                assert!(callbacks[source].remove(&id));
                assert!(value.get("result").is_some_and(Value::is_null));
                assert!(value.get("error").is_none());
                continue;
            };
            let request = value["id"].as_u64().unwrap();
            let result = match method {
                wire::TURN => json!({"ExpirationInSeconds":300,"TurnAuthServers":[]}),
                wire::PING => Value::Null,
                wire::SEND => {
                    let params = &value["params"];
                    let recipient =
                        Uuid::parse_str(params["toPlayerId"].as_str().unwrap()).unwrap();
                    let target = identities.iter().position(|id| *id == recipient).unwrap();
                    assert!(source != target && (source == 0 || target == 0));
                    let message = Uuid::parse_str(params["messageId"].as_str().unwrap()).unwrap();
                    assert!(!message.is_nil());
                    let inner = params["message"].as_str().unwrap();
                    let parsed: Value = serde_json::from_str(inner).unwrap();
                    assert_eq!(parsed["jsonrpc"], "2.0");
                    assert!(matches!(
                        parsed["method"].as_str(),
                        Some(wire::WEBRTC | wire::RECEIPT)
                    ));
                    let active = match target {
                        0 => host.is_some(),
                        1 => first.socket.is_some(),
                        _ => second.socket.is_some(),
                    };
                    // Retirement can precede an already accepted receipt on another physical socket.
                    // An absent recipient creates neither a callback nor a peer-delivery receipt.
                    if active {
                        assert!(callbacks[target].len() < MAX_PENDING_REQUESTS);
                        let callback = Uuid::new_v4();
                        assert!(callbacks[target].insert(callback));
                        let delivery = json!({"jsonrpc":"2.0","id":callback,"method":wire::RECEIVE,
                            "params":{"From":identities[source],"Id":message,"Message":inner}});
                        let result = match target {
                            0 => send(&mut host, delivery).await,
                            1 => send(&mut first.socket, delivery).await,
                            _ => send(&mut second.socket, delivery).await,
                        };
                        if let Err(terminal) = result {
                            terminals[target] = Some(terminal);
                        }
                    }
                    // Actual peer delivery is the peer's subsequent original RECEIPT, never this reply.
                    Value::Null
                }
                _ => panic!("unexpected activation signaling method"),
            };
            let reply = json!({"jsonrpc":"2.0","id":request,"result":result});
            let result = match source {
                0 => send(&mut host, reply).await,
                1 => send(&mut first.socket, reply).await,
                _ => send(&mut second.socket, reply).await,
            };
            if let Err(terminal) = result {
                terminals[source] = Some(terminal);
                break;
            }
        }
    }
    let [host, first, second] = terminals.map(Option::unwrap);
    (host, [first, second])
}

/// Retains partial codec reads/close replies across selection cancellation and observes real terminals.
async fn read<S>(socket: &mut Option<WebSocketStream<S>>) -> Frame
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(socket) = socket else {
        return pending().await;
    };
    match socket.next().await {
        Some(Ok(message)) if message.is_text() => {
            assert!(message.as_payload().len() <= MAX_MESSAGE_BYTES);
            Frame::Text(
                std::str::from_utf8(message.as_payload())
                    .unwrap()
                    .to_owned(),
            )
        }
        Some(Ok(message)) if message.is_close() => Frame::Close,
        Some(Ok(message)) if message.is_ping() || message.is_pong() => Frame::Control,
        Some(Ok(_)) => Frame::Terminal(HostedSocketTerminal::Protocol),
        Some(Err(error)) => Frame::Terminal(failure(error)),
        None => Frame::Terminal(HostedSocketTerminal::Eof),
    }
}

/// Attempts the same bounded write; a socket failure retires only its original recipient.
async fn send<S>(
    socket: &mut Option<WebSocketStream<S>>,
    value: Value,
) -> Result<(), HostedSocketTerminal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let text = serde_json::to_string(&value).unwrap();
    assert!(text.len() <= MAX_MESSAGE_BYTES);
    let Some(active) = socket.as_mut() else {
        return Ok(());
    };
    match active.send(Message::text(text)).await {
        Ok(()) => Ok(()),
        Err(error) => {
            *socket = None;
            Err(failure(error))
        }
    }
}

/// Keeps an actual IO cause distinct from framing failure and clean physical retirement.
fn failure(error: tokio_websockets::Error) -> HostedSocketTerminal {
    match error {
        tokio_websockets::Error::Io(error) => HostedSocketTerminal::Io(error.kind()),
        _ => HostedSocketTerminal::Protocol,
    }
}

/// Flushes selected control output, retaining a physical failure on only that socket.
async fn flush<S>(socket: &mut Option<WebSocketStream<S>>) -> Result<(), HostedSocketTerminal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(active) = socket.as_mut() else {
        return Ok(());
    };
    match active.flush().await {
        Ok(()) => Ok(()),
        Err(error) => {
            *socket = None;
            Err(failure(error))
        }
    }
}

/// Retains an observed Close until its actual response flush completes, then retires that socket.
async fn close<S>(socket: &mut Option<WebSocketStream<S>>) -> HostedSocketTerminal
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let terminal = match socket.as_mut().unwrap().close().await {
        Ok(()) => HostedSocketTerminal::Close,
        Err(error) => failure(error),
    };
    *socket = None;
    terminal
}

#[cfg(test)]
mod tests;
