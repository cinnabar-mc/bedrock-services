//! Fixed two-socket friend routing using the original bounded readers, writers and terminal owners.

use super::*;
use crate::test_support::HostedFriendDialect;
use tokio::net::TcpStream;

/// Relays only the actual account socket and its fixed controlled host; it grants no game admission.
pub(crate) async fn run<S>(
    visitor: WebSocketStream<S>,
    mut host_peer: Peer,
    dialect: HostedFriendDialect,
    identities: [Uuid; 2],
    networks: [u64; 2],
) -> (HostedSocketTerminal, HostedSocketTerminal)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut visitor = Some(visitor);
    let mut host = host_peer.socket.take();
    let mut terminals = [None, None];
    let mut callbacks: [HashSet<Uuid>; 2] = std::array::from_fn(|_| HashSet::new());
    if dialect == HostedFriendDialect::Legacy {
        let credentials = json!({"Type":2,"From":"Server","Message":
            json!({"ExpirationInSeconds":300,"TurnAuthServers":[]}).to_string()});
        send_to(
            0,
            credentials.clone(),
            &mut visitor,
            &mut host,
            &mut terminals,
        )
        .await;
        send_to(1, credentials, &mut visitor, &mut host, &mut terminals).await;
    }
    while terminals.iter().any(Option::is_none) {
        let (source, frame) = tokio::select! {
            frame = read(&mut visitor) => (0, frame),
            frame = read(&mut host) => (1, frame),
        };
        let text = match frame {
            Frame::Text(text) => text,
            Frame::Control => {
                let result = if source == 0 {
                    flush(&mut visitor).await
                } else {
                    flush(&mut host).await
                };
                if let Err(error) = result {
                    terminals[source] = Some(error);
                }
                continue;
            }
            Frame::Close => {
                terminals[source] = Some(if source == 0 {
                    close(&mut visitor).await
                } else {
                    close(&mut host).await
                });
                continue;
            }
            Frame::Terminal(error) => {
                terminals[source] = Some(error);
                if source == 0 {
                    visitor = None;
                } else {
                    host = None;
                }
                continue;
            }
        };
        let value: Value = serde_json::from_str(&text).unwrap();
        let target = 1 - source;
        if dialect == HostedFriendDialect::Legacy {
            match value["Type"].as_u64().unwrap() {
                0 => assert_eq!(value["MessageId"], json!(Uuid::nil())),
                1 => {
                    assert_eq!(value["To"], networks[target].to_string());
                    let id = Uuid::parse_str(value["MessageId"].as_str().unwrap()).unwrap();
                    assert!(!id.is_nil());
                    let signal = value["Message"].as_str().unwrap();
                    assert!(!signal.is_empty());
                    let delivered = send_to(
                        target,
                        json!({"Type":1,"From":networks[source].to_string(),
                        "Message":signal,"MessageId":id}),
                        &mut visitor,
                        &mut host,
                        &mut terminals,
                    )
                    .await;
                    if delivered {
                        send_to(
                            source,
                            json!({"Type":4,"From":"Server","MessageId":id,"Message":"null"}),
                            &mut visitor,
                            &mut host,
                            &mut terminals,
                        )
                        .await;
                    }
                }
                _ => panic!("unexpected fixed friend legacy envelope"),
            }
            continue;
        }
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
                    let active = if target == 0 {
                        visitor.is_some()
                    } else {
                        host.is_some()
                    };
                    if active {
                        assert!(callbacks[target].len() < MAX_PENDING_REQUESTS);
                        let callback = Uuid::new_v4();
                        assert!(callbacks[target].insert(callback));
                        send_to(
                            target,
                            json!({"jsonrpc":"2.0","id":callback,"method":wire::RECEIVE,
                            "params":{"From":identities[source],"Id":id,"Message":inner}}),
                            &mut visitor,
                            &mut host,
                            &mut terminals,
                        )
                        .await;
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
            )
            .await
            {
                break;
            }
        }
    }
    let [visitor, host] = terminals.map(Option::unwrap);
    (visitor, host)
}

/// Writes through the same actual selected socket and preserves its first physical failure.
async fn send_to<S>(
    target: usize,
    value: Value,
    visitor: &mut Option<WebSocketStream<S>>,
    host: &mut Option<WebSocketStream<TcpStream>>,
    terminals: &mut [Option<HostedSocketTerminal>; 2],
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let active = if target == 0 {
        visitor.is_some()
    } else {
        host.is_some()
    };
    if !active {
        return false;
    }
    let result = if target == 0 {
        send(visitor, value).await
    } else {
        send(host, value).await
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
