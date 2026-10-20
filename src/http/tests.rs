use super::*;
use crate::{oauth::MicrosoftAuth, xbox::Config};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

#[cfg(feature = "rta-tokio")]
mod authority;
mod framing_retry;
mod retry;

const FIXTURE_DATE: &str = "Wed, 01 Jan 2025 00:00:00 GMT";
const LIMITS: [Option<usize>; 3] = [
    None,
    Some(SERVICE_RESPONSE_LIMIT),
    Some(crate::xbox::achievements::MAX_PAGE_BYTES),
];

#[derive(Clone, Copy, Debug)]
enum Framing {
    Declared(usize),
    Chunked,
}

/// Serves one real HTTP response with independent declared or streamed framing.
async fn fixture(
    body: Vec<u8>,
    framing: Framing,
    request_line: &'static str,
) -> (SocketAddr, JoinHandle<io::Result<()>>, Arc<AtomicU8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let progress = Arc::new(AtomicU8::new(0));
    let phase = Arc::clone(&progress);
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let (mut stream, _) = listener.accept().await?;
            phase.store(1, Ordering::Relaxed);
            let (request, header_end, _) =
                crate::xbox::test_support::read_request(&mut stream).await;
            phase.store(2, Ordering::Relaxed);
            assert!(
                std::str::from_utf8(&request[..header_end])
                    .unwrap()
                    .starts_with(request_line)
            );
            let length = match framing {
                Framing::Declared(length) => format!("Content-Length: {length}\r\n"),
                Framing::Chunked => "Transfer-Encoding: chunked\r\n".into(),
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nDate: {FIXTURE_DATE}\r\n{length}Connection: close\r\n\r\n"
            );
            stream.write_all(header.as_bytes()).await?;
            phase.store(3, Ordering::Relaxed);
            match framing {
                Framing::Declared(_) => stream.write_all(&body).await?,
                Framing::Chunked => {
                    for chunk in body.chunks(16 * 1024) {
                        stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await?;
                        stream.write_all(chunk).await?;
                        stream.write_all(b"\r\n").await?;
                    }
                    stream.write_all(b"0\r\n\r\n").await?;
                }
            }
            phase.store(4, Ordering::Relaxed);
            Ok(())
        })
        .await
        .expect("bounded HTTP fixture")
    });
    (address, task, progress)
}

/// Observes the actual reader result before retiring a writer closed by a rejected response.
async fn read(body: Vec<u8>, framing: Framing, limit: Option<usize>) -> Result<Response, Error> {
    let (address, server, _) = fixture(body, framing, "GET /body HTTP/1.1\r\n").await;
    let mut http = Http::fixture(address);
    let request = http
        .request(Method::GET, &format!("http://{address}/body"))
        .build()
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        match limit {
            Some(limit) => http.send_with_limit(request, limit).await,
            None => http.send(request).await,
        }
    })
    .await
    .expect("bounded HTTP read");
    if result.is_err() {
        server.abort();
    }
    let served = server.await;
    if result.is_ok() {
        served.unwrap().unwrap();
    }
    assert_eq!(
        http.response_time(),
        Some(httpdate::parse_http_date(FIXTURE_DATE).unwrap())
    );
    result
}

/// Includes the exact default and concrete service bounds without truncating retained bytes.
#[tokio::test]
async fn response_body_limits_include_exact_declared_bodies() {
    for limit in LIMITS {
        let length = limit.unwrap_or(RESPONSE_LIMIT);
        let response = read(vec![b'x'; length], Framing::Declared(length), limit)
            .await
            .unwrap();
        assert_eq!(response.body.len(), length);
        assert!(response.body.iter().all(|byte| *byte == b'x'));
    }
}

/// Rejects an over-limit declaration even when the peer sends none of the advertised body.
#[tokio::test]
async fn response_body_limits_reject_excess_declarations_before_reading() {
    for limit in LIMITS {
        let length = limit.unwrap_or(RESPONSE_LIMIT) + 1;
        assert!(matches!(
            read(Vec::new(), Framing::Declared(length), limit).await,
            Err(Error::ResponseTooLarge)
        ));
    }
}

/// Enforces the cumulative decoded byte bound without trusting a Content-Length header.
#[tokio::test]
async fn response_body_limits_bound_chunked_bodies() {
    for limit in LIMITS {
        let length = limit.unwrap_or(RESPONSE_LIMIT);
        let response = read(vec![b'x'; length], Framing::Chunked, limit)
            .await
            .unwrap();
        assert_eq!(response.body.len(), length);
        assert!(response.body.iter().all(|byte| *byte == b'x'));
        assert!(matches!(
            read(vec![b'x'; length + 1], Framing::Chunked, limit).await,
            Err(Error::ResponseTooLarge)
        ));
    }
}

/// A valid oversized device-code document cannot inherit a profile service's larger budget.
#[tokio::test]
async fn response_body_limits_preserve_public_device_acquisition_bound() {
    let body = serde_json::to_vec(&serde_json::json!({
        "device_code":"synthetic", "user_code":"PUBLIC",
        "verification_uri":"https://login.live.com/device",
        "expires_in":900, "interval":5,
        "unused":"x".repeat(RESPONSE_LIMIT),
    }))
    .unwrap();
    assert!(body.len() > RESPONSE_LIMIT);
    assert!(body.len() < SERVICE_RESPONSE_LIMIT);
    for framing in [Framing::Declared(body.len()), Framing::Chunked] {
        let (address, server, phase) =
            fixture(body.clone(), framing, "POST /device-code HTTP/1.1\r\n").await;
        let mut auth = MicrosoftAuth {
            http: Http::fixture(address),
            config: Config::default(),
        };
        let result =
            tokio::time::timeout(Duration::from_secs(10), auth.start(SystemTime::UNIX_EPOCH))
                .await
                .expect("bounded device-code acquisition");
        let failure = match &result {
            Ok(_) => "unexpected success",
            Err(Error::ResponseTooLarge) => "ResponseTooLarge",
            Err(Error::Http(error)) if error.is_timeout() => "HTTP timeout",
            Err(Error::Http(error)) if error.is_connect() => "HTTP connection failure",
            Err(Error::Http(error)) if error.is_body() => "HTTP body failure",
            Err(Error::Http(_)) => "other HTTP failure",
            Err(_) => "other SDK failure",
        };
        let completed = server.is_finished();
        eprintln!(
            "device acquisition diagnostic: framing={framing:?}, result={failure}, fixture_phase={}, fixture_finished={completed}; phases: 0=accept pending,1=accepted,2=complete request,3=response headers,4=response body",
            phase.load(Ordering::Relaxed)
        );
        if !completed {
            server.abort();
        }
        match server.await {
            Ok(Ok(())) => eprintln!("device acquisition fixture: completed"),
            Ok(Err(error)) => eprintln!("device acquisition fixture: IO {:?}", error.kind()),
            Err(error) if error.is_cancelled() => eprintln!("device acquisition fixture: aborted"),
            Err(_) => eprintln!("device acquisition fixture: panicked"),
        }
        assert!(matches!(result, Err(Error::ResponseTooLarge)));
    }
}
