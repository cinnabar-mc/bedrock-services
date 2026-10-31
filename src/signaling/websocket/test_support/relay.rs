//! Fixed activation relay using the owning signaling wire definitions and actual socket codecs.

use super::Peer;
use crate::{
    signaling::{MAX_BATCH_MESSAGES, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, wire},
    test_support::HostedSocketTerminal,
};
use futures_util::{Sink, Stream};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::{Message, WebSocketStream};
use uuid::Uuid;

pub(crate) mod friend;

enum Frame {
    Text(String),
    Control,
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
    let mut first = RelaySocket::new(first.socket.take());
    let mut second = RelaySocket::new(second.socket.take());
    let mut host = RelaySocket::new(Some(host));
    let identities = [host_id, guest_ids[0], guest_ids[1]];
    let mut terminals = [None, None, None];
    let mut callbacks: [HashSet<Uuid>; 3] = std::array::from_fn(|_| HashSet::new());
    while terminals.iter().any(Option::is_none) {
        let (source, frame) = tokio::select! {
            frame = read(&mut host) => (0, frame),
            frame = read(&mut first) => (1, frame),
            frame = read(&mut second) => (2, frame),
        };
        let text = match frame {
            Frame::Text(text) => text,
            Frame::Control => continue,
            Frame::Terminal(terminal) => {
                terminals[source] = Some(terminal);
                match source {
                    0 => {
                        host.socket = None;
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
                    let callback = match target {
                        0 => callback(&mut host, &mut callbacks[target]),
                        1 => callback(&mut first, &mut callbacks[target]),
                        _ => callback(&mut second, &mut callbacks[target]),
                    };
                    let callback = match callback {
                        Ok(callback) => callback,
                        Err(terminal) => {
                            terminals[target] = Some(terminal);
                            None
                        }
                    };
                    // Retirement can precede an already accepted receipt on another physical socket.
                    if let Some(callback) = callback {
                        let delivery = json!({"jsonrpc":"2.0","id":callback,"method":wire::RECEIVE,
                            "params":{"From":identities[source],"Id":message,"Message":inner}});
                        let result = match target {
                            0 => send(&mut host, delivery),
                            1 => send(&mut first, delivery),
                            _ => send(&mut second, delivery),
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
                0 => send(&mut host, reply),
                1 => send(&mut first, reply),
                _ => send(&mut second, reply),
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

/// Owns bounded output and write progress separately for each original physical socket.
struct RelaySocket<S> {
    socket: Option<WebSocketStream<S>>,
    output: VecDeque<Message>,
    bytes: usize,
    flushing: bool,
    closing: bool,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RelaySocket<S> {
    /// Installs one original socket without starting a task or writing any frame.
    fn new(socket: Option<WebSocketStream<S>>) -> Self {
        Self {
            socket,
            output: VecDeque::new(),
            bytes: 0,
            flushing: false,
            closing: false,
            deadline: None,
        }
    }

    /// Bounds time from the first unfinished write without delaying normal sends.
    fn writing(&mut self) {
        if self.deadline.is_none() {
            self.deadline = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
        }
    }

    /// Retires only this physical peer and discards its undeliverable output.
    fn retire(&mut self, terminal: HostedSocketTerminal) -> Frame {
        self.socket = None;
        self.output.clear();
        self.bytes = 0;
        self.deadline = None;
        Frame::Terminal(terminal)
    }

    /// Polls writes and reads together so backpressure cannot prevent sibling sockets from running.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Frame> {
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(
                self.retire(HostedSocketTerminal::Io(std::io::ErrorKind::TimedOut)),
            );
        }
        let Some(socket) = self.socket.as_mut() else {
            return Poll::Pending;
        };
        let mut socket = Pin::new(socket);
        if self.closing {
            match socket.as_mut().poll_close(cx) {
                Poll::Ready(result) => {
                    return Poll::Ready(
                        self.retire(result.map_or_else(failure, |_| HostedSocketTerminal::Close)),
                    );
                }
                Poll::Pending => {}
            }
        } else {
            for _ in 0..32 {
                if self.output.is_empty() {
                    break;
                }
                match socket.as_mut().poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        let message = self.output.pop_front().unwrap();
                        self.bytes -= message.as_payload().len();
                        if let Err(error) = socket.as_mut().start_send(message) {
                            return Poll::Ready(self.retire(failure(error)));
                        }
                        self.flushing = true;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(self.retire(failure(error))),
                    Poll::Pending => break,
                }
            }
            if self.flushing {
                match socket.as_mut().poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.flushing = false;
                        if self.output.is_empty() {
                            self.deadline = None;
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(self.retire(failure(error))),
                    Poll::Pending => {}
                }
            }
            match socket.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(message))) if message.is_text() => {
                    assert!(message.as_payload().len() <= MAX_MESSAGE_BYTES);
                    return Poll::Ready(Frame::Text(
                        std::str::from_utf8(message.as_payload())
                            .unwrap()
                            .to_owned(),
                    ));
                }
                Poll::Ready(Some(Ok(message))) if message.is_close() => {
                    self.closing = true;
                    self.writing();
                    return Poll::Ready(Frame::Control);
                }
                Poll::Ready(Some(Ok(message))) if message.is_ping() || message.is_pong() => {
                    self.flushing = true;
                    self.writing();
                    return Poll::Ready(Frame::Control);
                }
                Poll::Ready(Some(Ok(_))) => {
                    return Poll::Ready(self.retire(HostedSocketTerminal::Protocol));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(self.retire(failure(error))),
                Poll::Ready(None) => return Poll::Ready(self.retire(HostedSocketTerminal::Eof)),
                Poll::Pending => {}
            }
        }
        if !self.output.is_empty() && !self.flushing {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

/// Selects this socket's independent read/write progress without losing partial codec state.
async fn read<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut RelaySocket<S>) -> Frame {
    poll_fn(|cx| socket.poll(cx)).await
}

/// Queues one bounded frame immediately; a stalled recipient cannot block routing other peers.
fn send<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut RelaySocket<S>,
    value: Value,
) -> Result<(), HostedSocketTerminal> {
    if socket.socket.is_none() || socket.closing {
        return Ok(());
    }
    let text = serde_json::to_string(&value).unwrap();
    assert!(text.len() <= MAX_MESSAGE_BYTES);
    if socket.output.len() >= 32 || socket.bytes + text.len() > 2 * MAX_MESSAGE_BYTES {
        let terminal = HostedSocketTerminal::Io(std::io::ErrorKind::TimedOut);
        let Frame::Terminal(terminal) = socket.retire(terminal) else {
            unreachable!()
        };
        return Err(terminal);
    }
    socket.bytes += text.len();
    socket.output.push_back(Message::text(text));
    socket.writing();
    Ok(())
}

/// Bounds unacknowledged callbacks and retires a stalled recipient instead of blocking its siblings.
fn callback<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut RelaySocket<S>,
    callbacks: &mut HashSet<Uuid>,
) -> Result<Option<Uuid>, HostedSocketTerminal> {
    if socket.socket.is_none() || socket.closing {
        return Ok(None);
    }
    if callbacks.len() >= MAX_PENDING_REQUESTS {
        let Frame::Terminal(terminal) =
            socket.retire(HostedSocketTerminal::Io(std::io::ErrorKind::TimedOut))
        else {
            unreachable!()
        };
        return Err(terminal);
    }
    let id = Uuid::new_v4();
    assert!(callbacks.insert(id));
    Ok(Some(id))
}

/// Keeps an actual IO cause distinct from framing failure and clean physical retirement.
fn failure(error: tokio_websockets::Error) -> HostedSocketTerminal {
    match error {
        tokio_websockets::Error::Io(error) => HostedSocketTerminal::Io(error.kind()),
        _ => HostedSocketTerminal::Protocol,
    }
}

#[cfg(test)]
mod tests;
