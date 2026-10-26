use super::*;
use crate::xbox::test_support::read_request;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

/// Sends exact token responses or closes after reading the complete grant request.
async fn polling_fixture(
    responses: Vec<Option<&'static str>>,
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
                    stream.write_all(response.as_bytes()).await.unwrap();
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
        Some("HTTP/1.1 503 Unavailable\r\nConnection: close\r\n\r\n<html>unavailable</html>"),
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
