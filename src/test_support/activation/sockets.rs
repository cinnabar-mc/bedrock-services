//! Actual verified RTA/Messaging service peers, retaining their original physical terminal observations.

use super::*;
use crate::xbox::rta::websocket::test_support as tls;
use futures_util::{SinkExt, StreamExt};
use tokio_websockets::{Config, Limits, ServerBuilder, WebSocketStream};

/// Preserves a specific wire termination without interpreting arbitrary errors as a clean close.
pub(super) async fn terminal<S>(socket: &mut WebSocketStream<S>) -> HostedSocketTerminal
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match socket.next().await {
            Some(Ok(message)) if message.is_close() => {
                return match socket.close().await {
                    Ok(()) => HostedSocketTerminal::Close,
                    Err(error) => failure(error),
                };
            }
            Some(Ok(message)) if message.is_ping() || message.is_pong() => {
                if let Err(error) = socket.flush().await {
                    return failure(error);
                }
            }
            Some(Ok(_)) => return HostedSocketTerminal::Protocol,
            Some(Err(error)) => return failure(error),
            None => return HostedSocketTerminal::Eof,
        }
    }
}

/// Retains only the actual IO kind; protocol errors never become successful EOF observations.
fn failure(error: tokio_websockets::Error) -> HostedSocketTerminal {
    match error {
        tokio_websockets::Error::Io(error) => HostedSocketTerminal::Io(error.kind()),
        _ => HostedSocketTerminal::Protocol,
    }
}

pub(super) type Socket = WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>;

/// Verifies one actual signed upgrade and desired subscription before any service acknowledgment.
pub(super) async fn accept_rta(listener: &TcpListener, state: &Shared) -> (Socket, Value) {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut socket = upgrade_rta(tcp, state).await;
    let sequence = subscription(&mut socket)
        .await
        .expect("actual original RTA subscription");
    (socket, sequence)
}

/// Retains an accepted TCP owner through verified TLS and the original protected upgrade.
pub(super) async fn upgrade_rta(tcp: tokio::net::TcpStream, state: &Shared) -> Socket {
    let stream = tls::acceptor().accept(tcp).await.unwrap();
    let (request, socket) = ServerBuilder::new()
        .config(
            Config::default()
                .frame_size(rta::MAX_MESSAGE_BYTES)
                .flush_threshold(1),
        )
        .limits(Limits::default().max_payload_len(Some(rta::MAX_MESSAGE_BYTES)))
        .add_header(
            reqwest::header::SEC_WEBSOCKET_PROTOCOL,
            reqwest::header::HeaderValue::from_static(tls::subprotocol()),
        )
        .unwrap()
        .accept(stream)
        .await
        .unwrap();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| format!("{}: {}\r\n", name.as_str(), value.to_str().unwrap()))
        .collect::<String>();
    let target = request.uri().to_string();
    let headers = format!("{} {target} HTTP/1.1\r\n{headers}", request.method());
    {
        let mut state = state.lock().unwrap();
        let signed: Vec<_> = state.headers.iter().map(String::as_str).collect();
        crate::xbox::mpsd::test_support::verify(
            &target,
            &headers,
            &[],
            state.proof.as_ref().unwrap(),
            &signed,
        );
        assert_eq!(
            crate::xbox::mpsd::test_support::header(&headers, "authorization"),
            "XBL3.0 x=synthetic;rta"
        );
        state.rta_upgraded = true;
    }
    #[cfg(test)]
    super::reconnect::upgraded(state);
    socket
}

/// Verifies the desired subscription or preserves this same socket's physical terminal.
pub(super) async fn subscription(socket: &mut Socket) -> Result<Value, HostedSocketTerminal> {
    loop {
        let message = match socket.next().await {
            Some(Ok(message)) if message.is_text() => message,
            Some(Ok(message)) if message.is_close() => {
                return Err(match socket.close().await {
                    Ok(()) => HostedSocketTerminal::Close,
                    Err(error) => failure(error),
                });
            }
            Some(Ok(message)) if message.is_ping() || message.is_pong() => {
                socket.flush().await.map_err(failure)?;
                continue;
            }
            Some(Ok(_)) => return Err(HostedSocketTerminal::Protocol),
            Some(Err(error)) => return Err(failure(error)),
            None => return Err(HostedSocketTerminal::Eof),
        };
        let message: Value = serde_json::from_slice(message.as_payload()).unwrap();
        assert_eq!(
            message,
            json!([1, message[1], rta::Resource::session_directory().as_str()])
        );
        return Ok(message[1].clone());
    }
}

/// Independently verifies original protected fields and acknowledges the actual desired subscription.
pub(super) async fn rta(listener: TcpListener, state: Shared) -> HostedSocketTerminal {
    let (mut socket, sequence) = accept_rta(&listener, &state).await;
    let recovery = state.lock().unwrap().reconnect.is_some();
    if recovery {
        return super::reconnect::run(listener, state, socket, sequence).await;
    }
    let friend = state.lock().unwrap().friend.is_some();
    if friend {
        return super::friend::sockets::rta(socket, state, sequence).await;
    }
    let hold = state.lock().unwrap().subscription_hold.take();
    if let Some(hold) = hold {
        hold.wait().await;
    }
    socket
        .send(Message::text(
            json!([1, sequence, 0, 19, {"ConnectionId":super::super::script::CONNECTION}])
                .to_string(),
        ))
        .await
        .unwrap();
    terminal(&mut socket).await
}

/// Provides actual correlated TURN frames on the same protected service socket, without creating a session.
pub(super) async fn messaging(
    listener: TcpListener,
    state: Shared,
    visitors: Option<super::visitors::Services>,
    friend: Option<super::friend::Services>,
) -> HostedSocketTerminal {
    let (tcp, _) = listener.accept().await.unwrap();
    let stream = tls::acceptor().accept(tcp).await.unwrap();
    let (request, mut socket) = ServerBuilder::new()
        .config(
            Config::default()
                .frame_size(crate::signaling::MAX_MESSAGE_BYTES)
                .flush_threshold(1),
        )
        .limits(Limits::default().max_payload_len(Some(crate::signaling::MAX_MESSAGE_BYTES)))
        .accept(stream)
        .await
        .unwrap();
    assert_eq!(request.uri().path(), "/ws/v1.0/messaging/connect");
    assert_eq!(
        request.headers()[reqwest::header::AUTHORIZATION]
            .to_str()
            .unwrap(),
        super::script::service_header()
    );
    if let Some(friend) = friend {
        assert!(request.uri().query().is_none());
        return friend.run(socket, state).await;
    }
    if let Some(visitors) = visitors {
        return visitors.run(socket, state).await;
    }
    let message = socket.next().await.unwrap().unwrap();
    assert!(message.is_text());
    let message: Value = serde_json::from_slice(message.as_payload()).unwrap();
    assert_eq!(
        message["method"],
        crate::signaling::websocket::test_support::turn_method()
    );
    assert!(message["id"].is_u64());
    let initial_turn_seconds = state.lock().unwrap().initial_turn_seconds;
    socket
        .send(Message::text(
            json!({"jsonrpc":"2.0", "id":message["id"], "result":{
                "ExpirationInSeconds":initial_turn_seconds, "TurnAuthServers":[],
            }})
            .to_string(),
        ))
        .await
        .unwrap();
    let original_request = message["id"].as_u64().unwrap();
    let renewal = {
        let mut state = state.lock().unwrap();
        if let Some(renewal) = &mut state.renewal {
            renewal.original_turn_request = Some(original_request);
            true
        } else {
            false
        }
    };
    if renewal {
        let message = socket.next().await.unwrap().unwrap();
        assert!(message.is_text());
        let message: Value = serde_json::from_slice(message.as_payload()).unwrap();
        assert_eq!(
            message["method"],
            crate::signaling::websocket::test_support::turn_method()
        );
        let refreshed_request = message["id"].as_u64().unwrap();
        assert_ne!(refreshed_request, original_request);
        socket
            .send(Message::text(
                json!({"jsonrpc":"2.0", "id":message["id"], "result":{
                    "ExpirationInSeconds":super::renewal::REFRESH_SECONDS, "TurnAuthServers":[],
                }})
                .to_string(),
            ))
            .await
            .unwrap();
        state
            .lock()
            .unwrap()
            .renewal
            .as_mut()
            .unwrap()
            .refreshed_turn_request = Some(refreshed_request);
    }
    terminal(&mut socket).await
}
