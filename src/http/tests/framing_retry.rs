use super::*;
use crate::http::retry::Policy;

/// Incomplete response framing preserves its decode error instead of replaying an acquisition.
#[tokio::test]
async fn acquisition_does_not_retry_response_framing_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        crate::xbox::test_support::read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nx")
            .await
            .unwrap();
    });
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
    server.await.unwrap();
    assert!(matches!(result.unwrap(), Err(Error::Http(error)) if error.is_decode()));
}
