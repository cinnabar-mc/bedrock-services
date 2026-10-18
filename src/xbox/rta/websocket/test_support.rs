use super::*;
#[cfg(test)]
use crate::{
    http::Http,
    oauth::Credentials,
    xbox::{
        Account, Config, XBOX_RELYING_PARTY,
        test_support::{fixture, token},
    },
};
use futures_util::SinkExt;
use reqwest::header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL};
#[cfg(test)]
use serde_json::json;
use std::sync::Arc;
#[cfg(test)]
use std::time::UNIX_EPOCH;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};
use tokio_websockets::{Connector, ServerBuilder, WebSocketStream};

pub(crate) type Server = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;
const ROOT: &[u8] = include_bytes!("../../../../tests/fixtures/rta-tls/root.der");
const CERT: &[u8] = include_bytes!("../../../../tests/fixtures/rta-tls/server.der");
const KEY: &[u8] = include_bytes!("../../../../tests/fixtures/rta-tls/server.key.der");

/// Acquires real signed protected fields using only the existing original synthetic account server.
#[cfg(test)]
pub(super) async fn request() -> (Account, ConnectionRequest) {
    let headers = upgrade_headers().unwrap();
    let mut signed: Vec<String> = headers.keys().map(|k| k.as_str().into()).collect();
    signed.sort();
    signed.extend(["user-agent".into(), "accept".into()]);
    let mut step = 0;
    let (address, server) = fixture(move |path, _, _| {
        step += 1;
        let body = match step {
            1 => { assert_eq!(path,"/device-token"); token("device", false) },
            2 => { assert_eq!(path,"/nsal"); json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn","RelyingParty":XBOX_RELYING_PARTY,"SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1}]}) },
            3 => { assert_eq!(path,"/sisu"); json!({"TitleToken":token("title",false),"UserToken":token("user",false),"AuthorizationToken":token("xbox",true)}) },
            4 => { assert_eq!(path,"/nsal-current"); json!({"EndPoints":[{"Protocol":"https","Host":"rta.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rta","SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1,"ExtraHeaders":signed}]}) },
            5 => { assert_eq!(path,"/xsts"); token("rta",true) },
            _ => panic!("unexpected account request"),
        }; (200,body)
    }, 5).await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let request = account
        .rta_connection(super::super::Generation::new(7).unwrap(), headers)
        .await
        .unwrap();
    server.await.unwrap();
    (account, request)
}

/// Creates verified fixture TLS with an explicit original root; never changes production trust.
pub(super) fn connector() -> Connector {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ROOT.to_vec())).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config).into())
}

/// Owns the original localhost-only server certificate and its intentionally public test key.
pub(super) fn acceptor() -> TlsAcceptor {
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

/// Opens actual loopback TLS and verifies every received final protected header, including the key.
pub(super) async fn transport(
    request: &ConnectionRequest,
    initial: Option<Message>,
) -> (upgrade::Socket, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let connector = connector();
    let acceptor = acceptor();
    let (client, server) = tokio::join!(connector.wrap("localhost", tcp), acceptor.accept(server));
    let builder = ServerBuilder::new()
        .add_header(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(super::super::connection::SUBPROTOCOL),
        )
        .unwrap();
    let (client, server) = tokio::join!(upgrade::handshake(client.unwrap(), request), async {
        let (received, mut socket) = builder.accept(server.unwrap()).await.unwrap();
        if let Some(initial) = initial {
            socket.send(initial).await.unwrap();
        }
        socket.flush().await.unwrap();
        (received, socket)
    });
    let (received, server) = server;
    assert_eq!(received.method(), "GET");
    assert_eq!(received.uri().path(), request.url().path());
    assert_eq!(received.headers(), request.headers());
    (client.unwrap(), server)
}

/// Starts one pure owner only after its exact verified transport upgrade completed.
pub(crate) async fn pair(
    request: &mut ConnectionRequest,
    initial: Option<Message>,
) -> (RtaSocket, Server) {
    let (socket, server) = transport(request, initial).await;
    let state = request.start().unwrap();
    (
        RtaSocket::from_socket(socket, state, Options::default()),
        server,
    )
}
