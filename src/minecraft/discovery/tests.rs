use crate::{
    Error,
    minecraft::test_support::services,
    xbox::test_support::{read_request, write_response},
};
use serde_json::json;
use tokio::{net::TcpListener, sync::oneshot};

/// Builds a public discovery response that cannot contain account credentials.
fn metadata(issuer: &str) -> Vec<u8> {
    json!({"result":{"serviceEnvironments":{"auth":{"prod":{
        "serviceUri":"https://service.invalid/", "playFabTitleId":"AB12", "issuer":issuer
    }}}}})
    .to_string()
    .into_bytes()
}

/// Losing every waiter does not abandon the lookup or reanchor its eventual clock sample.
#[tokio::test]
async fn canceled_owner_leaves_one_lookup_for_later_callers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (observed, observation) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (bytes, headers, _) = read_request(&mut stream).await;
        assert!(
            !String::from_utf8_lossy(&bytes[..headers])
                .to_ascii_lowercase()
                .contains("authorization:")
        );
        observed.send(()).unwrap();
        released.await.unwrap();
        write_response(
            &mut stream,
            200,
            vec![],
            &metadata("https://shared.invalid/"),
        )
        .await;
    });
    let mut first = services(address);
    let mut second = services(address);
    second.http.share_fixture_transport(&first.http);
    let mut pending = Box::pin(first.discover());
    tokio::select! {
        result = &mut pending => panic!("lookup completed before release: {result:?}"),
        _ = observation => {}
    }
    drop(pending);
    drop(first);
    release.send(()).unwrap();
    server.await.unwrap();
    second.discover().await.unwrap();
    let observed = second.http.clock_sample();
    let mut third = services(address);
    third.http.share_fixture_transport(&second.http);
    third.discover().await.unwrap();
    assert_eq!(
        third.authorization_issuer().unwrap(),
        "https://shared.invalid/"
    );
    assert_eq!(third.http.clock_sample(), observed);
}

/// A blocked key cannot serialize another URL or share its failure with a different HTTP client.
#[tokio::test]
async fn unrelated_urls_and_transports_remain_independent() {
    for different_client in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (observed, observation) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            read_request(&mut first).await;
            observed.send(()).unwrap();
            let (mut second, _) = listener.accept().await.unwrap();
            read_request(&mut second).await;
            write_response(
                &mut second,
                200,
                vec![],
                &metadata("https://independent.invalid/"),
            )
            .await;
            write_response(&mut first, 404, vec![], b"SENSITIVE").await;
        });
        let mut first = services(address);
        let mut second = services(address);
        if !different_client {
            second.http.share_fixture_transport(&first.http);
            second.http.endpoints.discovery.push_str("/another-url");
        }
        let mut pending = Box::pin(first.discover());
        tokio::select! {
            result = &mut pending => panic!("blocked key completed: {result:?}"),
            _ = observation => {}
        }
        let (failed, succeeded) = tokio::join!(pending, second.discover());
        assert!(matches!(failed, Err(Error::Status { status, .. }) if status.as_u16() == 404));
        succeeded.unwrap();
        server.await.unwrap();
        assert_eq!(
            second.authorization_issuer().unwrap(),
            "https://independent.invalid/"
        );
    }
}

/// Waiters share a typed failure, and a later request can recover without a poisoned entry.
#[tokio::test]
async fn failed_lookup_is_shared_then_evicted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (observed, observation) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        observed.send(()).unwrap();
        released.await.unwrap();
        write_response(&mut stream, 404, vec![], b"SENSITIVE").await;
        let (mut next, _) = listener.accept().await.unwrap();
        read_request(&mut next).await;
        write_response(
            &mut next,
            200,
            vec![],
            &metadata("https://recovered.invalid/"),
        )
        .await;
    });
    let mut first = services(address);
    let mut second = services(address);
    second.http.share_fixture_transport(&first.http);
    let mut first_call = Box::pin(first.discover());
    tokio::select! {
        result = &mut first_call => panic!("lookup completed before release: {result:?}"),
        _ = observation => {}
    }
    let mut second_call = Box::pin(second.discover());
    std::future::poll_fn(|cx| {
        assert!(second_call.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let (first_result, second_result) = tokio::join!(first_call, second_call);
    for result in [first_result, second_result] {
        assert!(matches!(result, Err(Error::Status { status, .. }) if status.as_u16() == 404));
    }
    second.discover().await.unwrap();
    server.await.unwrap();
    assert_eq!(
        second.authorization_issuer().unwrap(),
        "https://recovered.invalid/"
    );
}
