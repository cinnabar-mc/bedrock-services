use super::test_support::{Server, pair, request};
use super::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Wake, Waker},
};

/// Reads exactly one complete text frame from the real TLS/WebSocket peer.
async fn read_json(server: &mut Server) -> Value {
    let message = server.next().await.unwrap().unwrap();
    assert!(message.is_text());
    serde_json::from_slice(message.as_payload()).unwrap()
}

/// Requires the explicit disconnection marker followed by completed physical close.
async fn closed(client: &mut RtaSocket) {
    assert!(matches!(client.drive().await, Ok(Event::Disconnected)));
    assert!(matches!(client.drive().await, Err(SocketError::Closed)));
}

/// Signed fields survive actual verified TLS; snapshots precede changes and controls/close progress.
#[tokio::test]
async fn protected_tls_orders_snapshot_changes_unsubscribe_and_control_close() {
    let (_, mut request) = request().await;
    let (mut client, mut server) = pair(&mut request, Some(Message::ping(b"probe".to_vec()))).await;
    let (subscription, request_id) = client
        .subscribe(
            client.connection().social_resource(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let application = async {
        assert!(
            matches!(client.drive().await, Ok(Event::Subscribed { request, subscription: id, initial })
            if request == request_id && id == subscription && initial["version"] == 1)
        );
        assert!(
            matches!(client.drive().await, Ok(Event::Changed { subscription: id, data })
            if id == subscription && data["version"] == 2)
        );
        let remove = client
            .unsubscribe(subscription, Instant::now() + Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert!(
            matches!(client.drive().await, Ok(Event::Unsubscribed { request, subscription: id })
            if request == remove && id == subscription)
        );
        client.close();
        closed(&mut client).await;
    };
    let service = async {
        let mut subscribe = None;
        let mut pong = false;
        while subscribe.is_none() || !pong {
            let message = server.next().await.unwrap().unwrap();
            if message.is_pong() {
                assert_eq!(&**message.as_payload(), b"probe");
                assert!(!pong);
                pong = true;
            } else {
                assert!(message.is_text());
                assert!(subscribe.is_none());
                subscribe = Some(serde_json::from_slice::<Value>(message.as_payload()).unwrap());
            }
        }
        let subscribe = subscribe.unwrap();
        assert_eq!(subscribe[0], 1);
        server
            .send(Message::text(
                json!([1,subscribe[1],0,19,{"version":1}]).to_string(),
            ))
            .await
            .unwrap();
        server
            .send(Message::text(json!([3,19,{"version":2}]).to_string()))
            .await
            .unwrap();
        let remove = read_json(&mut server).await;
        assert_eq!(remove[0], 2);
        assert_eq!(remove[2], 19);
        server
            .send(Message::text(json!([2, remove[1], 0]).to_string()))
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

/// A canceled drive cannot lose or replay actual partial frame bytes.
#[tokio::test]
async fn canceled_drive_retains_partial_frame_and_delivers_it_once() {
    let (_, mut request) = request().await;
    let (mut client, mut server) = pair(&mut request, None).await;
    let resource =
        Resource::new(format!("https://social.xboxlive.com/{}", "x".repeat(3000))).unwrap();
    let expected = resource.as_str().to_owned();
    let (_, request_id) = client
        .subscribe(resource, Instant::now() + Duration::from_secs(30))
        .unwrap();
    client
        .socket
        .as_mut()
        .unwrap()
        .get_mut()
        .get_mut()
        .limit_writes(64);
    poll_fn(|cx| {
        assert!(client.poll_drive(cx).is_pending());
        if client
            .socket
            .as_ref()
            .unwrap()
            .get_ref()
            .get_ref()
            .write_budget()
            == Some(0)
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    assert!(client.write_active);
    let mut drive = Box::pin(client.drive());
    poll_fn(|cx| {
        assert!(drive.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drive);
    client
        .socket
        .as_mut()
        .unwrap()
        .get_mut()
        .get_mut()
        .resume_writes();
    let application = async {
        assert!(
            matches!(client.drive().await, Ok(Event::Subscribed { request, .. }) if request == request_id)
        );
        client.close();
        closed(&mut client).await;
    };
    let service = async {
        let frame = read_json(&mut server).await;
        assert_eq!(frame[2], expected);
        server
            .send(Message::text(json!([1, frame[1], 0, 7, {}]).to_string()))
            .await
            .unwrap();
        let next = server.next().await.unwrap().unwrap();
        assert!(
            next.is_close(),
            "a partially written application frame must appear exactly once"
        );
        server.close().await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(application, service);
    })
    .await
    .unwrap();
}

/// Counts explicit wakes without allowing a busy driver to hide behind its executor.
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

/// A blocked automatic Pong parks on the current I/O waker even with queued application output.
#[tokio::test]
async fn pending_control_flush_parks_and_resumes_before_queued_application() {
    let (_, mut request) = request().await;
    let (mut client, mut server) = pair(&mut request, Some(Message::ping(b"probe".to_vec()))).await;
    client
        .socket
        .as_mut()
        .unwrap()
        .get_mut()
        .get_mut()
        .limit_writes(0);
    poll_fn(|cx| {
        assert!(client.poll_drive(cx).is_pending());
        if client.control_flush {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    client
        .subscribe(
            client.connection().social_resource(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    for _ in 0..3 {
        assert!(client.poll_drive(&mut cx).is_pending());
    }
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    client
        .socket
        .as_mut()
        .unwrap()
        .get_mut()
        .get_mut()
        .resume_writes();
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    let application = async {
        assert!(matches!(client.drive().await, Ok(Event::Subscribed { .. })));
        client.close();
        closed(&mut client).await;
    };
    let service = async {
        let pong = server.next().await.unwrap().unwrap();
        assert!(pong.is_pong());
        assert_eq!(&**pong.as_payload(), b"probe");
        let frame = read_json(&mut server).await;
        server
            .send(Message::text(json!([1, frame[1], 0, 9, {}]).to_string()))
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

/// Explicit request cancellation closes the ambiguous wire, drains each request once and keeps only desired state.
#[tokio::test]
async fn cancel_drops_partial_socket_and_never_sends_queued_followup() {
    let (_, mut request) = request().await;
    let (mut client, mut server) = pair(&mut request, None).await;
    let (first, canceled) = client
        .subscribe(
            Resource::new(format!("https://social.xboxlive.com/{}", "x".repeat(3000))).unwrap(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let (retained, interrupted) = client
        .subscribe(
            client.connection().social_resource(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    client
        .socket
        .as_mut()
        .unwrap()
        .get_mut()
        .get_mut()
        .limit_writes(64);
    poll_fn(|cx| {
        assert!(client.poll_drive(cx).is_pending());
        if client
            .socket
            .as_ref()
            .unwrap()
            .get_ref()
            .get_ref()
            .write_budget()
            == Some(0)
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    assert!(client.cancel(canceled));
    assert!(client.socket.is_none());
    assert!(client.outgoing.is_empty());
    assert!(!client.cancel(canceled));
    let mut outcomes = Vec::new();
    loop {
        match client.drive().await {
            Ok(Event::Failed { request, cause, .. }) => outcomes.push((request, cause)),
            Ok(Event::Disconnected) => break,
            _ => panic!("unexpected terminal event"),
        }
    }
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.contains(&(canceled, super::super::Failure::Cancelled)));
    assert!(outcomes.contains(&(interrupted, super::super::Failure::Disconnected)));
    assert!(matches!(client.drive().await, Err(SocketError::Closed)));
    let state = client.into_connection();
    assert_eq!(state.subscriptions().collect::<Vec<_>>(), vec![retained]);
    assert!(!state.subscriptions().any(|id| id == first));
    let next = tokio::time::timeout(Duration::from_secs(10), server.next())
        .await
        .unwrap();
    assert!(!matches!(next, Some(Ok(message)) if message.is_text()));
}

/// Output admission is bounded and a rejected subscription publishes neither handle nor pending frame.
#[tokio::test]
async fn queue_capacity_is_transactional_and_expiry_drops_unsent_frames() {
    let (_, mut request) = request().await;
    let (mut client, mut server) = pair(&mut request, None).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    for _ in 0..MAX_QUEUED_MESSAGES {
        client
            .subscribe(client.connection().social_resource(), deadline)
            .unwrap();
    }
    let before = client.connection().subscriptions().count();
    assert!(matches!(
        client.subscribe(client.connection().social_resource(), deadline),
        Err(Error::Limit)
    ));
    assert_eq!(client.connection().subscriptions().count(), before);
    assert_eq!(client.outgoing.len(), MAX_QUEUED_MESSAGES);
    client.tick(deadline);
    assert!(client.socket.is_none());
    assert!(client.outgoing.is_empty());
    assert_eq!(client.events.len(), before + 1);
    assert!(client.events.len() <= MAX_QUEUED_EVENTS);
    let mut failed = 0;
    while let Ok(event) = client.drive().await {
        if let Event::Failed {
            cause: super::super::Failure::TimedOut,
            ..
        } = event
        {
            failed += 1;
        }
    }
    assert_eq!(failed, before);
    assert!(matches!(client.drive().await, Err(SocketError::TimedOut)));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), server.next())
            .await
            .unwrap(),
        None | Some(Err(_))
    ));
}

/// Wrong generation and already-consumed upgrade rejection happen before old I/O or state is changed.
#[tokio::test]
async fn reconnect_fences_generation_and_single_use_before_touching_live_socket() {
    let (mut account, mut request) = request().await;
    let (mut client, _server) = pair(&mut request, None).await;
    let old = client.connection().epoch();
    assert!(matches!(
        client.reconnect(&mut request, Options::default()).await,
        Err(SocketError::State)
    ));
    assert!(client.socket.is_some());
    assert_eq!(client.connection().epoch(), old);
    assert!(matches!(
        RtaSocket::connect(&mut request, Options::default()).await,
        Err(SocketError::State)
    ));
    let mut replacement = account
        .rta_connection(
            super::super::Generation::new(8).unwrap(),
            upgrade_headers().unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        client.reconnect(&mut replacement, Options::default()).await,
        Err(SocketError::WrongAccount)
    ));
    assert!(client.socket.is_some());
    assert!(client.connection().is_connected());
    assert_eq!(client.connection().epoch(), old);
    assert!(replacement.unused().is_ok());
}

/// Malformed application data retires the actual socket and keeps server diagnostics out of the public error.
#[tokio::test]
async fn malformed_message_retires_socket_with_redacted_failure() {
    let (_, mut request) = request().await;
    let (mut client, mut server) = pair(&mut request, None).await;
    let (_, pending) = client
        .subscribe(
            client.connection().social_resource(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    server.send(Message::binary(b"[4]".to_vec())).await.unwrap();
    assert!(
        matches!(client.drive().await, Ok(Event::Resync { subscriptions }) if subscriptions.is_empty())
    );
    server
        .send(Message::text("private malformed payload"))
        .await
        .unwrap();
    assert!(
        matches!(client.drive().await, Ok(Event::Failed { request, cause: super::super::Failure::Disconnected, .. }) if request == pending)
    );
    assert!(matches!(client.drive().await, Ok(Event::Disconnected)));
    assert!(matches!(client.drive().await, Err(SocketError::Protocol)));
    assert!(client.socket.is_none());
    assert!(!format!("{:?}", SocketError::Protocol).contains("private"));
}

/// Transferring pure state drops the old socket/buffers, and explicit resubscribe keeps handles with fresh correlation.
#[tokio::test]
async fn pure_handoff_reconnects_on_fresh_transport_without_old_events_or_automatic_resubscribe() {
    let (mut account, mut first) = request().await;
    let (mut client, mut old_server) = pair(&mut first, None).await;
    let (id, old_request) = client
        .subscribe(
            client.connection().social_resource(),
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    let (event, ()) = tokio::join!(client.drive(), async {
        let frame = read_json(&mut old_server).await;
        old_server
            .send(Message::text(
                json!([1,frame[1],0,19,{"version":1}]).to_string(),
            ))
            .await
            .unwrap();
    });
    assert!(matches!(event, Ok(Event::Subscribed { subscription, .. }) if subscription == id));
    old_server
        .send(Message::text(json!([3,19,{"stale":true}]).to_string()))
        .await
        .unwrap();
    let mut state = client.into_connection();
    assert!(!state.is_connected());
    assert_eq!(state.subscriptions().collect::<Vec<_>>(), vec![id]);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), old_server.next())
            .await
            .unwrap(),
        None | Some(Err(_))
    ));
    let mut replacement = account
        .rta_connection(state.generation(), upgrade_headers().unwrap())
        .await
        .unwrap();
    let (socket, mut server) = test_support::transport(&replacement, None).await;
    state.reconnect(&mut replacement).unwrap();
    assert!(replacement.unused().is_err());
    let mut client = RtaSocket::from_socket(socket, state, Options::default());
    assert!(client.outgoing.is_empty());
    assert!(client.events.is_empty());
    let new_request = client
        .resubscribe(id, Instant::now() + Duration::from_secs(30))
        .unwrap();
    assert_ne!(new_request, old_request);
    let application = async {
        assert!(
            matches!(client.drive().await, Ok(Event::Subscribed { request, subscription, initial })
            if request == new_request && subscription == id && initial["version"] == 2)
        );
        client.close();
        closed(&mut client).await;
    };
    let service = async {
        let frame = read_json(&mut server).await;
        server
            .send(Message::text(
                json!([1,old_request.sequence,0,19,{"stale":true}]).to_string(),
            ))
            .await
            .unwrap();
        server
            .send(Message::text(
                json!([1,frame[1],0,29,{"version":2}]).to_string(),
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
