use super::*;
use crate::signaling::wire;
use futures_util::{SinkExt, StreamExt};
use reqwest::header::HeaderValue;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Wake, Waker},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_websockets::{MaybeTlsStream, ServerBuilder, WebSocketStream};

/// Opens actual loopback sockets; only this fixture bypasses production verified TLS.
async fn pair() -> (MessagingSocket, WebSocketStream<TcpStream>) {
    pair_with_initial(None).await
}

/// Writes an optional first frame directly after the upgrade response, before returning either owner.
async fn pair_with_initial(
    initial: Option<Message>,
) -> (MessagingSocket, WebSocketStream<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let url = url::Url::parse("wss://messaging.invalid/prefix/ws/v1.0/messaging/connect").unwrap();
    let builder =
        upgrade::builder(&url, HeaderValue::from_static("MCToken synthetic-only")).unwrap();
    let server_builder = ServerBuilder::new();
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
        MessagingSocket::from_socket(socket, 7, Duration::from_secs(3600), Options::default())
            .unwrap(),
        server,
    )
}

/// Extracts one JSON message while ignoring no application frames accidentally.
async fn read_json(server: &mut WebSocketStream<TcpStream>) -> Value {
    let message = server.next().await.unwrap().unwrap();
    assert!(message.is_text());
    serde_json::from_slice(message.as_payload()).unwrap()
}

/// Actual control exchange, callback response, caller-accepted receipt and bounded close.
#[tokio::test]
async fn drives_control_signal_receipt_completion_and_close() {
    let (mut client, mut server) = pair().await;
    let peer = Uuid::from_u128(1);
    let envelope = Uuid::from_u128(2);
    let receipt = Uuid::from_u128(3);
    let callback = json!({"jsonrpc":"2.0","id":"callback","method":wire::RECEIVE,
        "params":{"From":peer,"Id":envelope,"Message":json!({"jsonrpc":"2.0","method":wire::WEBRTC,
            "params":{"netherNetId":"8","message":"opaque-offer"}}).to_string()}});
    let application = async {
        let Event::Signal(signal) = client.drive().await.unwrap() else {
            panic!("expected signal")
        };
        assert_eq!(signal.sender(), peer);
        assert_eq!(signal.signal(), "opaque-offer");
        let accepted = client
            .acknowledge(&signal, receipt, Instant::now() + Duration::from_secs(30))
            .unwrap();
        assert!(
            matches!(client.drive().await.unwrap(), Event::Completed {request, result: Ok(())} if request == accepted)
        );
        client.close();
        assert!(matches!(client.drive().await, Err(SocketError::Closed)));
    };
    let service = async {
        server
            .send(Message::ping(b"control".to_vec()))
            .await
            .unwrap();
        server
            .send(Message::text(callback.to_string()))
            .await
            .unwrap();
        let pong = server.next().await.unwrap().unwrap();
        assert!(pong.is_pong());
        assert_eq!(&**pong.as_payload(), b"control");
        let reply = read_json(&mut server).await;
        assert_eq!(
            reply,
            json!({"jsonrpc":"2.0","id":"callback","result":null})
        );
        let acknowledged = read_json(&mut server).await;
        assert_eq!(acknowledged["method"], wire::SEND);
        let inner: Value =
            serde_json::from_str(acknowledged["params"]["message"].as_str().unwrap()).unwrap();
        assert_eq!(inner["method"], wire::RECEIPT);
        assert_eq!(inner["params"]["messageId"], envelope.to_string());
        server
            .send(Message::text(
                json!({"jsonrpc":"2.0","id":acknowledged["id"],"result":null}).to_string(),
            ))
            .await
            .unwrap();
        server.close().await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(application, service);
    })
    .await
    .unwrap();
}

/// Counts both owned and borrowed wake calls without scheduling a task.
#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// A blocked automatic Pong waits for I/O readiness even when application output is queued.
#[tokio::test]
async fn pending_control_flush_does_not_self_wake_queued_output() {
    let (mut client, mut server) =
        pair_with_initial(Some(Message::ping(b"control".to_vec()))).await;
    client.socket.as_mut().unwrap().get_mut().limit_writes(0);
    poll_fn(|cx| {
        assert!(client.poll_drive(cx).is_pending());
        if client.control_flush {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    let request = client
        .send_signal(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            "queued",
            false,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    for _ in 0..3 {
        assert!(client.poll_drive(&mut cx).is_pending());
        assert!(client.control_flush);
        assert!(!client.write_active);
        assert_eq!(client.outgoing.len(), 1);
        assert_eq!(
            wakes.0.load(Ordering::Relaxed),
            0,
            "queued output must wait for the blocked control flush's I/O waker"
        );
    }
    client.socket.as_mut().unwrap().get_mut().resume_writes();
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);

    let service = async {
        let pong = server.next().await.unwrap().unwrap();
        assert!(pong.is_pong());
        assert_eq!(&**pong.as_payload(), b"control");
        let application = read_json(&mut server).await;
        assert_eq!(application["id"], request.0);
        assert_eq!(application["method"], wire::SEND);
        server
            .send(Message::text(
                json!({"jsonrpc":"2.0","id":application["id"],"result":null}).to_string(),
            ))
            .await
            .unwrap();
        let close = server.next().await.unwrap().unwrap();
        assert!(
            close.is_close(),
            "Pong and application frame must each arrive once"
        );
        server.close().await.unwrap();
    };
    let application = async {
        assert!(
            matches!(client.drive().await.unwrap(), Event::Completed { request: id, result: Ok(()) } if id == request)
        );
        client.close();
        assert!(matches!(client.drive().await, Err(SocketError::Closed)));
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(service, application);
    })
    .await
    .unwrap();
}

/// Canceling a partially flushed drive preserves one complete frame, while unsent cancellation retracts it.
#[tokio::test]
async fn backpressure_admission_and_canceled_drive_do_not_lose_or_duplicate_frames() {
    let (mut client, mut server) = pair().await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let peer = Uuid::from_u128(1);
    let large = "x".repeat(MAX_MESSAGE_BYTES / 2);
    let first = client
        .send_signal(peer, Uuid::from_u128(2), &large, false, deadline)
        .unwrap();
    let mut admitted = vec![first];
    for value in 0..MAX_QUEUED_MESSAGES - 2 {
        admitted.push(
            client
                .send_signal(
                    peer,
                    Uuid::from_u128(3 + value as u128),
                    "small",
                    false,
                    deadline,
                )
                .unwrap(),
        );
    }
    assert!(matches!(
        client.send_signal(peer, Uuid::from_u128(100), "full", false, deadline),
        Err(Error::Limit)
    ));
    let removed = admitted.pop().unwrap();
    assert!(client.cancel(removed));
    admitted.push(
        client
            .send_signal(peer, Uuid::from_u128(101), "replacement", false, deadline)
            .unwrap(),
    );
    client.socket.as_mut().unwrap().get_mut().limit_writes(64);
    poll_fn(|cx| {
        assert!(client.poll_drive(cx).is_pending());
        if client.socket.as_ref().unwrap().get_ref().write_budget() == Some(0) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // Cancel a fresh drive future while its owner retains the partially flushed frame.
    let mut drive = Box::pin(client.drive());
    let pending = poll_fn(|cx| Poll::Ready(drive.as_mut().poll(cx).is_pending())).await;
    drop(drive);
    assert!(pending);
    assert!(
        client.write_active,
        "exhausted write budget must leave an owned pending frame"
    );
    assert!(client.cancel(first));
    client.socket.as_mut().unwrap().get_mut().resume_writes();
    let expected: HashSet<_> = admitted.into_iter().filter(|id| *id != first).collect();
    let service = async {
        server
            .send(Message::text(
                json!({"jsonrpc":"2.0","id":"required","method":"Future_Callback"}).to_string(),
            ))
            .await
            .unwrap();
        let mut seen = HashSet::new();
        let mut callback_replied = false;
        while seen.len() < MAX_QUEUED_MESSAGES - 1 || !callback_replied {
            let request = read_json(&mut server).await;
            if request["id"] == "required" {
                assert_eq!(request["result"], Value::Null);
                assert!(!callback_replied);
                callback_replied = true;
                continue;
            }
            let id = RequestId(request["id"].as_u64().unwrap());
            assert!(seen.insert(id), "request written twice");
            assert_ne!(id, removed);
            if seen.len() == 1 {
                assert_eq!(id, first);
                let inner: Value =
                    serde_json::from_str(request["params"]["message"].as_str().unwrap()).unwrap();
                assert_eq!(inner["params"]["message"], large);
            } else {
                assert!(expected.contains(&id));
            }
            server
                .send(Message::text(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":null}).to_string(),
                ))
                .await
                .unwrap();
        }
        server.close().await.unwrap();
    };
    let application = async {
        let mut completed = HashSet::new();
        loop {
            match client.drive().await {
                Ok(Event::Completed {
                    request,
                    result: Ok(()),
                }) => {
                    assert!(completed.insert(request));
                }
                Ok(Event::Ignored) => {}
                Err(SocketError::Closed) => break,
                _ => panic!("unexpected socket outcome"),
            }
        }
        assert_eq!(completed, expected);
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(service, application);
    })
    .await
    .unwrap();
}

/// Caller-driven service heartbeats use the shared correlation owner and do not leak internal handles.
#[tokio::test]
async fn heartbeat_success_and_failure_drive_connection_lifetime() {
    let (mut client, mut server) = pair().await;
    client.tick(client.next_ping);
    let service = async {
        let request = read_json(&mut server).await;
        assert_eq!(request["method"], wire::PING);
        server
            .send(Message::text(
                json!({"jsonrpc":"2.0","id":request["id"],"result":null}).to_string(),
            ))
            .await
            .unwrap();
        server
            .send(Message::text(
                json!({"jsonrpc":"2.0","method":"Future_Callback"}).to_string(),
            ))
            .await
            .unwrap();
    };
    let application = async {
        // The heartbeat's successful completion is consumed by the owner.
        assert!(matches!(client.drive().await.unwrap(), Event::Ignored));
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(service, application);
    })
    .await
    .unwrap();
    let due = client.next_ping;
    let pending = client
        .request_credentials(due + Duration::from_secs(30))
        .unwrap();
    client.tick(due);
    client.tick(due + client.options.ping_timeout);
    assert!(
        matches!(client.drive().await.unwrap(), Event::Completed {request, result: Err(Failure::Closed)} if request == pending)
    );
    assert!(matches!(
        client.drive().await,
        Err(SocketError::Heartbeat(Failure::TimedOut))
    ));
}

/// Successful upgrade removes its byte budget and retains an immediately arriving first message.
#[tokio::test]
async fn upgrade_overread_and_lifetime_reads_preserve_messages() {
    let message =
        json!({"jsonrpc":"2.0","method":"Future_Callback","params":"x".repeat(1000)}).to_string();
    let (mut client, mut server) = pair_with_initial(Some(Message::text(message.clone()))).await;
    let count = upgrade::MAX_UPGRADE_BYTES / message.len() + 2;
    let service = async {
        for index in 1..count {
            let frame = if index % 2 == 0 {
                Message::text(message.clone())
            } else {
                Message::binary(message.as_bytes().to_vec())
            };
            server.send(frame).await.unwrap();
        }
    };
    let application = async {
        for _ in 0..count {
            assert!(matches!(client.drive().await.unwrap(), Event::Ignored));
        }
        client.abort();
        assert!(matches!(client.drive().await, Err(SocketError::Closed)));
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(service, application);
    })
    .await
    .unwrap();
}

/// A full caller-event queue rolls back correlation before rejecting admission.
#[tokio::test]
async fn event_backpressure_does_not_orphan_a_rejected_request() {
    let (mut client, _server) = pair().await;
    client
        .events
        .extend((0..MAX_QUEUED_EVENTS).map(|_| Event::Ignored));
    let deadline = Instant::now() + Duration::from_secs(30);
    assert!(matches!(
        client.request_credentials(deadline),
        Err(Error::Limit)
    ));
    for _ in 0..MAX_QUEUED_EVENTS {
        assert!(matches!(client.drive().await.unwrap(), Event::Ignored));
    }
    let request = client.request_credentials(deadline).unwrap();
    client.abort();
    assert!(
        matches!(client.drive().await.unwrap(), Event::Completed {request: id, result: Err(Failure::Closed)} if id == request)
    );
    assert!(matches!(client.drive().await, Err(SocketError::Closed)));
}

/// Malformed JSON and oversize reassembly resolve pending handles before the terminal error.
#[tokio::test]
async fn malformed_frames_resolve_pending_requests_before_redacted_failure() {
    for (message, expected) in [
        (
            Message::binary(b"secret-diagnostic".to_vec()),
            SocketError::Protocol,
        ),
        (
            Message::text("x".repeat(MAX_MESSAGE_BYTES + 1)),
            SocketError::Capacity,
        ),
    ] {
        let (mut client, mut server) = pair().await;
        let request = client
            .request_credentials(Instant::now() + Duration::from_secs(30))
            .unwrap();
        let service = async {
            let _ = server.send(message).await;
        };
        let application = async {
            assert!(
                matches!(client.drive().await.unwrap(), Event::Completed {request: id, result: Err(Failure::Closed)} if id == request)
            );
            assert!(matches!(client.drive().await, Err(error) if error == expected));
            assert!(matches!(
                client.request_credentials(Instant::now()),
                Err(Error::Closed)
            ));
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(service, application);
        })
        .await
        .unwrap();
    }
}

/// Credential destinations are rejected before I/O; refusal retains only numeric status, never redirects.
#[tokio::test]
async fn upgrade_destination_refusal_and_incomplete_header_bounds() {
    for invalid in [
        "ws://example.invalid/",
        "wss://user:password@example.invalid/",
        "wss://example.invalid/?secret=token",
    ] {
        let url = url::Url::parse(invalid).unwrap();
        assert!(matches!(
            upgrade::builder(&url, HeaderValue::from_static("MCToken synthetic-only")),
            Err(SocketError::Configuration)
        ));
    }
    for (response, expected) in [
        (
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 17\r\n\r\nsecret-diagnostic".to_vec(),
            SocketError::UpgradeStatus(401),
        ),
        (
            b"HTTP/1.1 302 Found\r\nLocation: wss://elsewhere.invalid/?secret=token\r\n\r\n"
                .to_vec(),
            SocketError::UpgradeStatus(302),
        ),
        (
            [
                b"HTTP/1.1 101 Switching Protocols\r\nX-Padding: ".as_slice(),
                &vec![b'x'; upgrade::MAX_UPGRADE_BYTES + 1],
            ]
            .concat(),
            SocketError::Capacity,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let builder = upgrade::builder(
            &url::Url::parse("wss://messaging.invalid/connect").unwrap(),
            HeaderValue::from_static("MCToken synthetic-only"),
        )
        .unwrap();
        let service = async {
            let mut request = vec![0; 4096];
            let _ = server.read(&mut request).await.unwrap();
            let _ = server.write_all(&response).await;
        };
        let application = async {
            let result = builder.connect_on(upgrade::UpgradeIo::new(client)).await;
            let error = match result {
                Err(tokio_websockets::Error::Io(error))
                    if error.kind() == std::io::ErrorKind::InvalidData =>
                {
                    SocketError::Capacity
                }
                Err(error) => SocketError::from_wire(error),
                Ok(_) => panic!("invalid upgrade accepted"),
            };
            assert_eq!(error, expected);
            assert!(!format!("{error:?} {error}").contains("secret"));
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(service, application);
        })
        .await
        .unwrap();
    }
}
