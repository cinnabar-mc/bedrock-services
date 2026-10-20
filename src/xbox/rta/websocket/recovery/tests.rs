use super::*;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};

/// Uses real original upgrade credentials and transport, then retires only that socket.
async fn disconnected(desired: usize) -> (Account, RtaSocket) {
    let (account, mut request) = super::super::test_support::request().await;
    let (transport, peer) = super::super::test_support::transport(&request, None).await;
    let state = request.start().unwrap();
    let mut socket = RtaSocket::from_socket(transport, state, Options::default());
    for _ in 0..desired {
        socket
            .subscribe(
                Resource::session_directory(),
                Instant::now() + Duration::from_secs(15),
            )
            .unwrap();
    }
    socket.abort();
    drop(peer);
    (account, socket)
}

/// A canceled recovery retires partial I/O while retaining desired handles and its scheduled wait.
#[tokio::test]
async fn canceled_recovery_retains_desires_and_backoff() {
    let (mut account, mut socket) = disconnected(1).await;
    let until = tokio::time::Instant::now() + Duration::from_secs(60);
    socket.recovery.next = Some(until);
    {
        let recovery = socket.recover(&mut account, Instant::now() + Duration::from_secs(120));
        tokio::pin!(recovery);
        poll_fn(|cx| {
            assert!(recovery.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert!(socket.socket.is_none());
    assert_eq!(socket.state.subscriptions().count(), 1);
    assert_eq!(socket.recovery.next, Some(until));
    assert!(matches!(
        socket
            .recover(&mut account, Instant::now() - Duration::from_secs(1))
            .await,
        Err(RecoveryError::Deadline)
    ));
    assert_eq!(socket.state.subscriptions().count(), 1);
}

/// No desired subscriptions require no upgrade, while another proof owner is rejected before I/O.
#[tokio::test]
async fn empty_recovery_is_network_free_and_wrong_account_is_fenced() {
    let (mut account, mut socket) = disconnected(0).await;
    let (mut other, _) = super::super::test_support::request().await;
    assert!(matches!(
        socket
            .recover(&mut other, Instant::now() + Duration::from_secs(1))
            .await,
        Err(RecoveryError::State(Error::WrongAccount))
    ));
    assert!(
        socket
            .recover(&mut account, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap()
            .is_empty()
    );
}

/// Expired credentials without refresh material require sign-in before any recovery backoff.
#[tokio::test]
async fn terminal_sign_in_failure_survives_recovery() {
    let (mut account, mut socket) = disconnected(1).await;
    account.credentials = crate::oauth::Credentials::from_tokens(
        account.config.client_id.clone(),
        "expired-access".into(),
        String::new(),
        std::time::UNIX_EPOCH,
    )
    .unwrap();
    account.session = None;
    account.authorizations.clear();
    tokio::time::pause();
    let result = socket
        .recover(&mut account, Instant::now() + Duration::from_secs(60))
        .await;
    assert!(matches!(
        result,
        Err(RecoveryError::State(Error::Service(
            crate::Error::SignInRequired
        )))
    ));
    assert_eq!(socket.state.subscriptions().count(), 1);
    assert!(socket.socket.is_none());
    assert!(socket.recovery.next.is_none());
}

/// Only temporary HTTP acquisition statuses and interrupted socket work authorize recovery retries.
#[test]
fn terminal_failures_are_not_retryable() {
    for error in [
        crate::Error::SignInRequired,
        crate::Error::AuthorizationDeclined,
        crate::Error::Invalid("response"),
        crate::Error::ResponseTooLarge,
        crate::Error::TimeRange,
    ] {
        assert!(!crate::http::retry::transient(&error));
    }
    for status in [400, 401, 403, 404, 408, 429, 500, 503, 999] {
        let temporary = matches!(status, 408 | 429 | 500 | 503 | 999);
        assert_eq!(
            crate::http::retry::transient(&crate::Error::Status {
                status: reqwest::StatusCode::from_u16(status).unwrap(),
                xerr: None,
            }),
            temporary
        );
        assert_eq!(
            retryable_socket(SocketError::UpgradeStatus(status)),
            temporary
        );
    }
    for error in [
        SocketError::Configuration,
        SocketError::State,
        SocketError::WrongAccount,
        SocketError::Protocol,
        SocketError::Capacity,
    ] {
        assert!(!retryable_socket(error));
    }
}

/// A real refused title request stays transient on cache replay, then expires at its original cutoff.
#[tokio::test]
async fn cached_transport_failure_preserves_acquisition_retryability() {
    let (mut account, socket) = disconnected(1).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    account.current_title_data = None;
    account.http.endpoints.nsal_current = format!("http://{unavailable}/nsal-current");
    for cached in [false, true] {
        let error = account
            .rta_connection(socket.state.generation(), upgrade_headers().unwrap())
            .await
            .err()
            .unwrap();
        if cached {
            assert!(matches!(error, Error::Service(crate::Error::Invalid(_))));
        } else {
            assert!(matches!(error, Error::Service(crate::Error::Http(_))));
        }
        assert!(account.retryable_rta_acquisition(&error));
    }
    let (address, server) = crate::xbox::test_support::fixture(|_, _, _| {
        (200, json!({"EndPoints":[{"Protocol":"https","Host":"rta.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rta","SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1}]}))
    }, 1).await;
    account.http.endpoints.nsal_current = format!("http://{address}/nsal-current");
    account.advance_fixture_time(Duration::from_secs(15));
    let request = account
        .rta_connection(socket.state.generation(), upgrade_headers().unwrap())
        .await
        .unwrap();
    socket.state.check_reconnect(&request).unwrap();
    assert_eq!(socket.state.subscriptions().count(), 1);
    server.await.unwrap();
}

/// Replaces only the test transport while retaining the real account, generation and desired handles.
async fn replacement(
    account: &mut Account,
    socket: RtaSocket,
) -> (
    RtaSocket,
    super::super::test_support::Server,
    super::super::super::Epoch,
) {
    let mut state = socket.into_connection();
    let mut request = account
        .rta_connection(state.generation(), upgrade_headers().unwrap())
        .await
        .unwrap();
    let epoch = request.epoch();
    let (transport, peer) = super::super::test_support::transport(&request, None).await;
    state.reconnect(&mut request).unwrap();
    (
        RtaSocket::from_socket(transport, state, Options::default()),
        peer,
        epoch,
    )
}

/// A malformed restoration reply remains a protocol failure instead of starting another epoch.
#[tokio::test]
async fn malformed_restoration_is_terminal() {
    let (mut account, socket) = disconnected(1).await;
    let (mut socket, mut peer, _) = replacement(&mut account, socket).await;
    let (result, ()) = tokio::join!(
        socket.restore_subscriptions(Instant::now() + Duration::from_secs(15)),
        async {
            peer.next().await.unwrap().unwrap();
            peer.send(Message::text("invalid-json")).await.unwrap();
        }
    );
    assert!(matches!(
        result,
        Err(RecoveryError::Socket(SocketError::Protocol))
    ));
    assert_eq!(socket.state.subscriptions().count(), 1);
}

/// A rejection survives cancellation during its sibling's real handshake and is delivered exactly once.
#[tokio::test]
async fn rejected_completion_survives_cancellation_of_sibling_restore() {
    let (mut account, socket) = disconnected(2).await;
    let handles = socket.state.subscriptions().collect::<Vec<_>>();
    let (mut socket, mut peer, epoch) = replacement(&mut account, socket).await;
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let message = peer.next().await.unwrap().unwrap();
        let first: Value = serde_json::from_slice(message.as_payload()).unwrap();
        let sequence = u32::try_from(first[1].as_u64().unwrap()).unwrap();
        peer.send(Message::text(json!([1, sequence, 1]).to_string()))
            .await
            .unwrap();
        let second = peer.next().await.unwrap().unwrap();
        assert!(second.is_text());
        seen_tx.send(sequence).unwrap();
        cancel_rx.await.unwrap();
    });
    let sequence;
    {
        let guard = Guard {
            socket: &mut socket,
            complete: false,
        };
        let restoring = guard
            .socket
            .restore_subscriptions(Instant::now() + Duration::from_secs(15));
        tokio::pin!(restoring);
        sequence = tokio::select! {
            result=&mut restoring => { drop(result); panic!("held sibling completed before cancellation"); },
            sequence=seen_rx => sequence.unwrap(),
        };
    }
    cancel_tx.send(()).unwrap();
    server.await.unwrap();
    assert_eq!(
        socket.state.subscriptions().collect::<Vec<_>>(),
        vec![handles[1]]
    );
    let mut failures = 0;
    while let Ok(event) = socket.drive().await {
        if let Event::Failed {
            request,
            subscription,
            cause: crate::xbox::rta::Failure::Status(status),
        } = event
        {
            assert_eq!(status, 1);
            assert_eq!(subscription, handles[0]);
            assert_eq!(request, RequestId { epoch, sequence });
            failures += 1;
        }
    }
    assert_eq!(failures, 1);
    let (mut socket, mut peer, _) = replacement(&mut account, socket).await;
    let (events, peer) = tokio::join!(
        socket.restore_subscriptions(Instant::now() + Duration::from_secs(15)),
        async move {
            let message = peer.next().await.unwrap().unwrap();
            let request: Value = serde_json::from_slice(message.as_payload()).unwrap();
            peer.send(Message::text(
                json!([1,request[1],0,900,{"ConnectionId":uuid::Uuid::from_u128(7)}]).to_string(),
            ))
            .await
            .unwrap();
            peer
        }
    );
    let events = events.unwrap().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0],Event::Subscribed{subscription,..} if *subscription==handles[1]));
    assert!(socket.recovery_events.is_empty());
    drop(peer);
}

/// The schedule caps at 60 seconds before jitter, and cache reads do not move its deadline.
#[tokio::test(start_paused = true)]
async fn recovery_backoff_is_capped_and_retains_its_deadline() {
    let mut backoff = Backoff::default();
    for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
        let now = tokio::time::Instant::now();
        backoff.failed(now, 0.0);
        assert_eq!(backoff.next, Some(now + Duration::from_secs(seconds)));
        tokio::time::advance(Duration::from_secs(seconds)).await;
    }
    let now = tokio::time::Instant::now();
    backoff.failed(now, 1.0);
    assert_eq!(backoff.next, Some(now + Duration::from_secs(90)));
}
