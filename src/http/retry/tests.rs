use super::*;
use reqwest::{Method, header::HeaderMap};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

/// Builds a bounded response at the retry decision boundary without a transport task.
fn unavailable(delay: &'static str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("retry-after", delay.parse().unwrap());
    Response {
        status: StatusCode::SERVICE_UNAVAILABLE,
        headers,
        body: Vec::new().into(),
    }
}

/// Observes whether the original wait remains pending at an explicitly advanced instant.
async fn pending(mut future: Pin<&mut impl Future<Output = bool>>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

/// Later attempts inherit the first cutoff, including a server delay that cannot fit.
#[tokio::test(start_paused = true)]
async fn attempts_share_one_original_budget() {
    let mut retry = Retry::new(Policy::Credential);
    let mut request = Request::new(
        Method::POST,
        "https://fixture.invalid/mint".parse().unwrap(),
    );
    retry.begin(&mut request);
    assert_eq!(request.timeout(), Some(&REQUEST_TIMEOUT));
    tokio::time::advance(REQUEST_TIMEOUT - Duration::from_secs(5)).await;
    let mut next = request.try_clone().unwrap();
    retry.begin(&mut next);
    assert_eq!(next.timeout(), Some(&Duration::from_secs(5)));
    let before = Instant::now();
    assert!(
        !retry
            .wait(&Ok(unavailable("5")), SystemTime::UNIX_EPOCH)
            .await
    );
    assert_eq!(
        Instant::now(),
        before,
        "an unfittable delay cannot authorize a retry"
    );
}

/// A date-based wait cannot run early; dropping that wait leaves continuation caller-owned.
#[tokio::test(start_paused = true)]
async fn retry_after_wait_respects_date_and_cancellation() {
    let utc = httpdate::parse_http_date("Wed, 01 Jan 2025 00:00:00 GMT").unwrap();
    let response = Ok(unavailable("Wed, 01 Jan 2025 00:00:10 GMT"));
    let mut retry = Retry::new(Policy::Presence);
    let mut request = Request::new(
        Method::POST,
        "https://fixture.invalid/title".parse().unwrap(),
    );
    retry.begin(&mut request);
    {
        let wait = retry.wait(&response, utc);
        tokio::pin!(wait);
        pending(wait.as_mut()).await;
        tokio::time::advance(Duration::from_secs(9)).await;
        pending(wait.as_mut()).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(wait.await);
    }
    let mut continued = false;
    {
        let wait = async {
            if retry.wait(&response, utc).await {
                continued = true;
            }
            continued
        };
        tokio::pin!(wait);
        pending(wait.as_mut()).await;
    }
    tokio::time::advance(REQUEST_TIMEOUT).await;
    assert!(
        !continued,
        "a dropped wait cannot resume its caller's operation"
    );
}

/// Invalid or conflicting positive delays cannot authorize an earlier fallback attempt.
#[tokio::test(start_paused = true)]
async fn unusable_positive_retry_after_does_not_retry_early() {
    let mut retry = Retry::new(Policy::Credential);
    let mut request = Request::new(
        Method::POST,
        "https://fixture.invalid/mint".parse().unwrap(),
    );
    retry.begin(&mut request);
    let mut conflicting = unavailable("1");
    conflicting
        .headers
        .append("retry-after", "2".parse().unwrap());
    for response in [unavailable("18446744073709551616"), conflicting] {
        let before = Instant::now();
        assert!(!retry.wait(&Ok(response), SystemTime::UNIX_EPOCH).await);
        assert_eq!(Instant::now(), before);
    }
}
