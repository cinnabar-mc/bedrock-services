use super::*;
use crate::xbox::test_support::read_request;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

/// Sends exact token responses or closes after reading the complete grant request.
async fn polling_fixture(
    responses: Vec<Option<impl AsRef<[u8]> + Send + 'static>>,
) -> (
    MicrosoftAuth,
    DeviceAuthorization,
    Arc<AtomicUsize>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (request, header_end, length) = read_request(&mut stream).await;
                assert!(request.starts_with(b"POST /oauth-token HTTP/1.1\r\n"));
                let form = url::form_urlencoded::parse(&request[header_end..header_end + length])
                    .collect::<std::collections::HashMap<_, _>>();
                assert_eq!(form["device_code"], "same-private-grant");
                assert_eq!(form["grant_type"], DEVICE_GRANT);
                seen.fetch_add(1, Ordering::SeqCst);
                if let Some(response) = response {
                    stream.write_all(response.as_ref()).await.unwrap();
                }
            }
        })
        .await
        .expect("bounded token fixture");
    });
    let config = Config::default();
    let attempt = DeviceAuthorization {
        code: Zeroizing::new("same-private-grant".into()),
        user_code: "PUBLIC".into(),
        verification_uri: Url::parse("https://login.live.com/device").unwrap(),
        expires: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        next_poll: SystemTime::UNIX_EPOCH + Duration::from_secs(5),
        interval: Duration::from_secs(5),
        completed: false,
        client_id: config.client_id.clone(),
    };
    (
        MicrosoftAuth {
            http: Http::fixture(address),
            config,
        },
        attempt,
        requests,
        server,
    )
}

/// Keeps slow-down pacing across a non-JSON server failure, then completes the same grant.
#[tokio::test]
async fn device_poll_server_failure_preserves_slow_down_and_authorizes() {
    let (mut auth, mut attempt, requests, server) = polling_fixture(vec![
        Some("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"error\":\"slow_down\"}"),
        Some("HTTP/1.1 503 Unavailable\r\nRetry-After: 1\r\nConnection: close\r\n\r\n<html>unavailable</html>"),
        Some("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"access_token\":\"access\",\"refresh_token\":\"refresh\",\"expires_in\":3600}"),
    ])
    .await;
    for expected_next in [15, 25] {
        let due = attempt.next_poll();
        assert!(matches!(
            auth.poll(&mut attempt, due).await,
            Ok(Poll::Pending)
        ));
        assert_eq!(
            attempt.next_poll(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(expected_next)
        );
        let count = requests.load(Ordering::SeqCst);
        assert!(matches!(
            auth.poll(&mut attempt, due).await,
            Ok(Poll::Pending)
        ));
        assert_eq!(requests.load(Ordering::SeqCst), count);
    }
    let due = attempt.next_poll();
    let Ok(Poll::Authorized(credentials)) = auth.poll(&mut attempt, due).await else {
        panic!("same grant must authorize after transient failure");
    };
    assert_eq!(credentials.refresh_token(), "refresh");
    assert!(matches!(
        auth.poll(&mut attempt, due).await,
        Err(Error::DeviceCodeExpired)
    ));
    server.await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}

/// Provider backoff never shortens pacing or outlives the grant; ambiguous delays forbid retries.
#[tokio::test]
async fn device_poll_retry_after_respects_interval_and_original_expiry() {
    for (headers, expected_next) in [
        ("Retry-After: 20\r\n", 25),
        ("Retry-After: 1\r\n", 10),
        ("Retry-After: 100\r\n", 60),
        ("Retry-After: 18446744073709551615\r\n", 60),
        ("Retry-After: 18446744073709551616\r\n", 60),
        ("Retry-After: 1\r\nRetry-After: 20\r\n", 60),
        ("Retry-After: malformed\r\n", 10),
        ("Retry-After: Thu, 01 Jan 1970 00:00:20 GMT\r\n", 20),
        ("Retry-After: Thu, 01 Jan 1970 00:00:01 GMT\r\n", 10),
    ] {
        let response =
            format!("HTTP/1.1 503 Unavailable\r\n{headers}Connection: close\r\n\r\noffline");
        let (mut auth, mut attempt, requests, server) = polling_fixture(vec![Some(response)]).await;
        let due = attempt.next_poll();
        let started = auth.http.retry_time();
        assert!(matches!(
            auth.poll(&mut attempt, due).await,
            Ok(Poll::Pending)
        ));
        let elapsed = auth.http.retry_time().duration_since(started);
        let next = SystemTime::UNIX_EPOCH + Duration::from_secs(expected_next);
        assert!(attempt.next_poll() >= next, "{headers}");
        assert!(
            attempt.next_poll() <= next.checked_add(elapsed).unwrap(),
            "{headers}"
        );
        assert!(attempt.next_poll() <= attempt.expires, "{headers}");
        assert!(matches!(
            auth.poll(&mut attempt, next - Duration::from_secs(1)).await,
            Ok(Poll::Pending)
        ));
        let expires = attempt.expires;
        assert!(matches!(
            auth.poll(&mut attempt, expires).await,
            Err(Error::DeviceCodeExpired)
        ));
        server.await.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{headers}");
    }
}

/// A delayed response starts relative backoff on receipt, in the caller's UTC clock domain.
#[tokio::test]
async fn device_poll_retry_after_starts_after_response_latency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (received, observed) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (request, _, _) = read_request(&mut stream).await;
            assert!(request.starts_with(b"POST /oauth-token HTTP/1.1\r\n"));
            received.send(()).unwrap();
            released.await.unwrap();
            stream.write_all(b"HTTP/1.1 503 Unavailable\r\nRetry-After: 20\r\nDate: Thu, 01 Jan 2099 00:00:00 GMT\r\nConnection: close\r\n\r\noffline").await.unwrap();
        }).await.expect("response fixture outlives explicit two-second advance");
    });
    let (mut auth, mut attempt, _, unused_server) =
        polling_fixture(Vec::<Option<&str>>::new()).await;
    unused_server.await.unwrap();
    auth.http = Http::fixture(address);
    let due = attempt.next_poll();
    let started = auth.http.retry_time();
    let poll = tokio::spawn(async move {
        let result = auth.poll(&mut attempt, due).await;
        (auth, attempt, result)
    });
    observed.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    release.send(()).unwrap();
    tokio::time::resume();
    let (mut auth, mut attempt, result) = poll.await.unwrap();
    assert!(matches!(result, Ok(Poll::Pending)));
    let elapsed = auth.http.retry_time().duration_since(started);
    let earliest = due + Duration::from_secs(22);
    let latest = (due + Duration::from_secs(20))
        .checked_add(elapsed)
        .unwrap();
    assert!(attempt.next_poll() >= earliest);
    assert!(
        attempt.next_poll() <= latest,
        "service Date cannot replace caller UTC"
    );
    assert!(attempt.next_poll() <= attempt.expires);
    assert!(matches!(
        auth.poll(&mut attempt, earliest - Duration::from_secs(1))
            .await,
        Ok(Poll::Pending)
    ));
    server.await.unwrap();
}

/// Neither an initial interval nor later slow-down or transport failure can delay expiry reporting.
#[tokio::test]
async fn device_poll_all_waits_stop_at_grant_expiry() {
    let (address, server) = crate::xbox::test_support::fixture(
        |target, _, _| {
            assert_eq!(target, "/device-code");
            (
                200,
                serde_json::json!({
                    "device_code":"short-grant", "user_code":"PUBLIC",
                    "verification_uri":"https://login.live.com/device",
                    "expires_in":3, "interval":10,
                }),
            )
        },
        1,
    )
    .await;
    let mut auth = MicrosoftAuth {
        http: Http::fixture(address),
        config: Config::default(),
    };
    let mut attempt = auth.start(SystemTime::UNIX_EPOCH).await.unwrap();
    assert_eq!(attempt.next_poll(), attempt.expires);
    let expires = attempt.expires;
    assert!(matches!(
        auth.poll(&mut attempt, expires).await,
        Err(Error::DeviceCodeExpired)
    ));
    server.await.unwrap();

    for response in [
        None,
        Some("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"error\":\"slow_down\"}"),
    ] {
        let (mut auth, mut attempt, requests, server) = polling_fixture(vec![response]).await;
        let due = attempt.expires - Duration::from_secs(1);
        assert!(matches!(
            auth.poll(&mut attempt, due).await,
            Ok(Poll::Pending)
        ));
        assert_eq!(attempt.next_poll(), attempt.expires);
        let expires = attempt.expires;
        assert!(matches!(
            auth.poll(&mut attempt, expires).await,
            Err(Error::DeviceCodeExpired)
        ));
        server.await.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }
}

/// Retries closed connections and truncated bodies, while an explicit denial stays terminal.
#[tokio::test]
async fn device_poll_transport_failures_preserve_grant_until_denied() {
    let (mut auth, mut attempt, requests, server) = polling_fixture(vec![
        None,
        Some("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{"),
        Some("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"error\":\"access_denied\"}"),
    ])
    .await;
    for expected_next in [10, 15] {
        let due = attempt.next_poll();
        match auth.poll(&mut attempt, due).await {
            Ok(Poll::Pending) => {}
            Ok(Poll::Authorized(_)) => panic!("transport fixture unexpectedly authorized"),
            Err(error) => panic!("transport poll {expected_next} failed: {error}"),
        }
        assert_eq!(
            attempt.next_poll(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(expected_next)
        );
    }
    let due = attempt.next_poll();
    assert!(matches!(
        auth.poll(&mut attempt, due).await,
        Err(Error::AuthorizationDeclined)
    ));
    assert!(matches!(
        auth.poll(&mut attempt, due).await,
        Err(Error::DeviceCodeExpired)
    ));
    server.await.unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}

/// Outages cannot extend a grant's deadline, and malformed successful responses stay errors.
#[tokio::test]
async fn device_poll_transient_failure_keeps_expiry_and_json_validation() {
    for (response, transient) in [
        (
            "HTTP/1.1 500 Unavailable\r\nConnection: close\r\n\r\noffline",
            true,
        ),
        (
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nnot-json",
            false,
        ),
    ] {
        let (mut auth, mut attempt, requests, server) = polling_fixture(vec![Some(response)]).await;
        let due = attempt.next_poll();
        let result = auth.poll(&mut attempt, due).await;
        if transient {
            assert!(matches!(result, Ok(Poll::Pending)));
        } else {
            assert!(matches!(result, Err(Error::Invalid("response JSON"))));
        }
        let expires = attempt.expires;
        assert!(matches!(
            auth.poll(&mut attempt, expires).await,
            Err(Error::DeviceCodeExpired)
        ));
        server.await.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }
}
