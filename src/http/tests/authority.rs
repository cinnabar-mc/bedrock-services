use super::*;
use crate::signature::SignaturePolicy;
use http::{HeaderMap, Uri, header::AUTHORIZATION};
use p256::ecdsa::SigningKey;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

const BODY: &[u8] = b"{\"fixture\":true}\n";
const REPLY: &[u8] = b"{}";
const ROOT: &[u8] = include_bytes!("../../../tests/fixtures/rta-tls/root.der");
const CERT: &[u8] = include_bytes!("../../../tests/fixtures/rta-tls/server.der");
const KEY: &[u8] = include_bytes!("../../../tests/fixtures/rta-tls/server.key.der");

#[derive(Clone, Copy)]
enum Host {
    Default,
    Override,
    Multiple,
}

struct Received {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Vec<u8>,
    alpn: Option<Vec<u8>>,
}

/// Uses the original public localhost test certificate and requires ordinary TLS ALPN for H2.
fn acceptor() -> TlsAcceptor {
    let mut config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

/// Prepares and signs the same buffered request, retaining its final signature for wire comparison.
fn request(http: &Http, url: &str, host: Host) -> (Request, HeaderValue) {
    let mut request = http
        .request(Method::POST, url)
        .header(AUTHORIZATION, "synthetic-authorization")
        .header("content-type", "application/json")
        .header("content-length", BODY.len())
        .body(BODY)
        .build()
        .unwrap();
    http.prepare_signature(&mut request).unwrap();
    match host {
        Host::Default => {}
        Host::Override => {
            request
                .headers_mut()
                .insert(HOST, HeaderValue::from_static("explicit.invalid"));
        }
        Host::Multiple => {
            let host = request.headers()[HOST].clone();
            request.headers_mut().append(HOST, host);
        }
    }
    SignaturePolicy {
        extra_headers: vec!["host".into(), "content-type".into()],
        ..Default::default()
    }
    .sign(
        &mut request,
        &SigningKey::from_slice(&[1; 32]).unwrap(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )
    .unwrap();
    let signature = request.headers()["signature"].clone();
    (request, signature)
}

/// Captures real H2 pseudo-fields and ordinary headers, then drains the sole connection to EOF.
async fn exchange(
    host: Host,
) -> (
    Result<Response, Error>,
    io::Result<Received>,
    String,
    HeaderValue,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let authority = format!("localhost:{}", address.port());
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let (stream, _) = listener.accept().await?;
            let stream = acceptor().accept(stream).await?;
            let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            let mut connection = h2::server::Builder::new()
                .handshake::<_, &'static [u8]>(stream)
                .await
                .map_err(io::Error::other)?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or_else(|| io::Error::other("missing fixture request"))?
                .map_err(io::Error::other)?;
            let received = {
                let serve = async move {
                    let (parts, mut input) = request.into_parts();
                    let mut body = Vec::new();
                    while let Some(chunk) = input.data().await {
                        let chunk = chunk.map_err(io::Error::other)?;
                        if chunk.len() > BODY.len().saturating_sub(body.len()) {
                            return Err(io::Error::other("oversized fixture request"));
                        }
                        body.extend_from_slice(&chunk);
                        input
                            .flow_control()
                            .release_capacity(chunk.len())
                            .map_err(io::Error::other)?;
                    }
                    drop(input);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-length", REPLY.len())
                        .body(())
                        .unwrap();
                    let mut output = respond
                        .send_response(response, false)
                        .map_err(io::Error::other)?;
                    output.send_data(REPLY, true).map_err(io::Error::other)?;
                    Ok(Received {
                        method: parts.method,
                        uri: parts.uri,
                        headers: parts.headers,
                        body,
                        alpn,
                    })
                };
                tokio::pin!(serve);
                tokio::select! {
                    result = &mut serve => result?,
                    next = connection.accept() => {
                        if let Some(request) = next {
                            request.map_err(io::Error::other)?;
                        }
                        return Err(io::Error::other("fixture connection ended before response"));
                    }
                }
            };
            connection.graceful_shutdown();
            if let Some(request) = connection.accept().await {
                request.map_err(io::Error::other)?;
                return Err(io::Error::other("unexpected second fixture request"));
            }
            Ok(received)
        })
        .await
        .map_err(io::Error::other)?
    });
    let mut http = Http::fixture(address);
    http.client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve("localhost", address)
        .tls_certs_only([reqwest::Certificate::from_der(ROOT).unwrap()])
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let (request, signature) = request(
        &http,
        &format!("https://{authority}/protected?operation=read"),
        host,
    );
    let response = http.send_with_limit(request, RESPONSE_LIMIT).await;
    drop(http);
    let received = server.await.expect("original TLS fixture task joined");
    (response, received, authority, signature)
}

/// Defaults use only authority, while explicit and multiple Host values retain their wire meaning.
#[tokio::test]
async fn signed_http2_uses_authority_without_a_redundant_default_host() {
    let mut captures = Vec::new();
    for host in [Host::Default, Host::Override, Host::Multiple] {
        captures.push(exchange(host).await);
    }
    let mut ordinary_hosts = Vec::new();
    for (response, received, authority, signature) in captures {
        let response = response.expect("original signed H2 request completed");
        let received = received.expect("original TLS/H2 owner drained and joined");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_slice(), REPLY);
        assert_eq!(received.alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(received.method, Method::POST);
        assert_eq!(
            received.uri.authority().map(|value| value.as_str()),
            Some(authority.as_str())
        );
        assert_eq!(
            received.uri.path_and_query().map(|value| value.as_str()),
            Some("/protected?operation=read")
        );
        assert_eq!(received.body, BODY);
        assert_eq!(received.headers["signature"], signature);
        assert_eq!(received.headers[AUTHORIZATION], "synthetic-authorization");
        ordinary_hosts.push(
            received
                .headers
                .get_all(HOST)
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(ordinary_hosts[1], [b"explicit.invalid".to_vec()]);
    assert_eq!(ordinary_hosts[2].len(), 2);
    assert_eq!(ordinary_hosts[2][0], ordinary_hosts[2][1]);
    assert!(
        ordinary_hosts[0].is_empty(),
        "the signed H2 request sent both authority and its redundant default Host"
    );
}

/// HTTP/1 still materializes its mandatory Host after the same prepared and signed request.
#[tokio::test]
async fn signed_http1_retains_its_default_host() {
    let captured = Arc::new(std::sync::Mutex::new(None));
    let received = Arc::clone(&captured);
    let (address, server) = crate::xbox::test_support::fixture_bytes(
        move |path, headers, body| {
            *received.lock().unwrap() = Some((path.to_owned(), headers.to_owned(), body.to_vec()));
            (200, Vec::new(), REPLY.to_vec())
        },
        1,
    )
    .await;
    let mut http = Http::fixture(address);
    let (request, signature) = request(
        &http,
        &format!("http://{address}/protected?operation=read"),
        Host::Default,
    );
    let response = http.send_with_limit(request, RESPONSE_LIMIT).await;
    drop(http);
    if response.is_err() {
        server.abort();
    }
    let joined = server.await;
    let received = captured.lock().unwrap().take();
    let response = response.expect("original signed HTTP/1 request completed");
    joined.expect("original HTTP/1 owner joined");
    let (path, headers, body) = received.expect("original HTTP/1 owner received the request");
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_slice(), REPLY);
    assert_eq!(path, "/protected?operation=read");
    assert_eq!(body, BODY);
    let field = |name: &str| {
        headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>()
    };
    let authority = address.to_string();
    assert_eq!(field("host"), [authority.as_str()]);
    assert_eq!(field("signature"), [signature.to_str().unwrap()]);
}
