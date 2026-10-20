use super::*;
use crate::http::retry::Policy;
use serde_json::Value;

/// A real acquisition returns its last response when the server's delay exceeds its total budget.
#[tokio::test]
async fn acquisition_keeps_retry_after_beyond_its_original_budget() {
    let (address, server) = crate::xbox::test_support::fixture_headers(
        |target, _, body| {
            assert_eq!(target, "/mint");
            assert_eq!(body, b"original buffered request");
            (503, vec![("Retry-After", "30")], Value::Null)
        },
        1,
    )
    .await;
    let mut http = Http::fixture(address);
    let request = http
        .request(Method::POST, &format!("http://{address}/mint"))
        .body("original buffered request")
        .build()
        .unwrap();
    let result = tokio::time::timeout(
        REQUEST_TIMEOUT,
        http.send_retrying(request, Policy::Credential),
    )
    .await;
    drop(http);
    if !matches!(&result, Ok(Ok(_))) {
        server.abort();
    }
    server.await.unwrap();
    assert_eq!(
        result.unwrap().unwrap().status,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// A shorter caller deadline cancels the actual in-flight request and retires its original peer.
#[tokio::test]
async fn acquisition_retains_caller_cancellation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (observed, observation) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        crate::xbox::test_support::read_request(&mut stream).await;
        observed.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let mut http = Http::fixture(address);
    let request = http
        .request(Method::POST, &format!("http://{address}/mint"))
        .body("original buffered request")
        .build()
        .unwrap();
    let result;
    let entered;
    {
        let operation = tokio::time::timeout(
            Duration::from_secs(2),
            http.send_retrying(request, Policy::Credential),
        );
        tokio::pin!(operation);
        let early = tokio::select! {
            observed = observation => {
                entered = observed.is_ok();
                None
            },
            result = &mut operation => {
                entered = false;
                Some(result)
            },
        };
        result = if let Some(result) = early {
            result
        } else {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(2)).await;
            let result = operation.await;
            tokio::time::resume();
            result
        };
    }
    drop(http);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    let rebound = TcpListener::bind(address).await.unwrap();
    drop(rebound);
    assert!(
        entered,
        "original server must observe the request before cancellation"
    );
    assert!(
        result.is_err(),
        "the caller's shorter cutoff must remain authoritative"
    );
}
