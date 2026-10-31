//! Fixed two-socket friend routing using the original bounded readers, writers and terminal owners.

use super::*;
use tokio::net::TcpStream;

/// Relays only the actual account socket and its fixed controlled host; it grants no game admission.
pub(crate) async fn run<S>(
    visitor: WebSocketStream<S>,
    mut host_peer: Peer,
    identities: [Uuid; 2],
) -> (HostedSocketTerminal, HostedSocketTerminal)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut visitor = RelaySocket::new(Some(visitor));
    let mut host = RelaySocket::new(host_peer.socket.take());
    let mut terminals = [None, None];
    let mut callbacks: [HashSet<Uuid>; 2] = std::array::from_fn(|_| HashSet::new());
    while terminals.iter().any(Option::is_none) {
        let (source, frame) = tokio::select! {
            frame = read(&mut visitor) => (0, frame),
            frame = read(&mut host) => (1, frame),
        };
        let text = match frame {
            Frame::Text(text) => text,
            Frame::Control => continue,
            Frame::Terminal(error) => {
                terminals[source] = Some(error);
                if source == 0 {
                    visitor.socket = None;
                } else {
                    host.socket = None;
                }
                continue;
            }
        };
        let value: Value = serde_json::from_str(&text).unwrap();
        let target = 1 - source;
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
                    assert_eq!(params["toPlayerId"], json!(identities[target]));
                    let id = Uuid::parse_str(params["messageId"].as_str().unwrap()).unwrap();
                    assert!(!id.is_nil());
                    let inner = params["message"].as_str().unwrap();
                    let parsed: Value = serde_json::from_str(inner).unwrap();
                    assert_eq!(parsed["jsonrpc"], "2.0");
                    assert!(matches!(
                        parsed["method"].as_str(),
                        Some(wire::WEBRTC | wire::RECEIPT)
                    ));
                    let callback = if target == 0 {
                        callback(&mut visitor, &mut callbacks[target])
                    } else {
                        callback(&mut host, &mut callbacks[target])
                    };
                    let callback = match callback {
                        Ok(callback) => callback,
                        Err(terminal) => {
                            terminals[target] = Some(terminal);
                            None
                        }
                    };
                    if let Some(callback) = callback {
                        send_to(
                            target,
                            json!({"jsonrpc":"2.0","id":callback,"method":wire::RECEIVE,
                            "params":{"From":identities[source],"Id":id,"Message":inner}}),
                            &mut visitor,
                            &mut host,
                            &mut terminals,
                        );
                    }
                    Value::Null
                }
                _ => panic!("unexpected fixed friend Messaging method"),
            };
            if !send_to(
                source,
                json!({"jsonrpc":"2.0","id":request,"result":result}),
                &mut visitor,
                &mut host,
                &mut terminals,
            ) {
                break;
            }
        }
    }
    let [visitor, host] = terminals.map(Option::unwrap);
    (visitor, host)
}

/// Writes through the same actual selected socket and preserves its first physical failure.
fn send_to<S>(
    target: usize,
    value: Value,
    visitor: &mut RelaySocket<S>,
    host: &mut RelaySocket<TcpStream>,
    terminals: &mut [Option<HostedSocketTerminal>; 2],
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let active = if target == 0 {
        visitor.socket.is_some()
    } else {
        host.socket.is_some()
    };
    if !active {
        return false;
    }
    let result = if target == 0 {
        send(visitor, value)
    } else {
        send(host, value)
    };
    match result {
        Ok(()) => true,
        Err(error) => {
            if terminals[target].is_none() {
                terminals[target] = Some(error);
            }
            false
        }
    }
}
