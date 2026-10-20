//! Exact finite loopback transport metadata; no server handle, global override or account state.

use super::{AUTH_ORIGIN, SIGNALING_ORIGIN, TITLE};
use crate::{Error, http::Http, xbox::rta::websocket::test_support as tls};
use reqwest::{Client, Request, header::HOST};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpStream;
use tokio_websockets::MaybeTlsStream;
use url::Url;

/// Selects one original protected request's concrete verified socket boundary.
#[derive(Clone, Copy)]
pub(crate) enum SocketKind {
    Rta,
    Messaging,
}

/// Only fixed ephemeral endpoints and public TLS metadata are shared with account requests.
pub(crate) struct Transport {
    pub(super) http: SocketAddr,
    pub(super) rta: SocketAddr,
    pub(super) messaging: SocketAddr,
    /// Only the fixed friend sibling accepts the canonical local-ID legacy upgrade path.
    pub(super) friend_legacy: bool,
}

impl Transport {
    /// Keeps each physical fixture endpoint on loopback before any account can retain it.
    pub(super) fn new(http: SocketAddr, rta: SocketAddr, messaging: SocketAddr) -> Self {
        assert!(
            [http, rta, messaging]
                .iter()
                .all(|address| address.ip().is_loopback())
        );
        Self {
            http,
            rta,
            messaging,
            friend_legacy: false,
        }
    }

    /// Uses only the original test root with ordinary verified localhost TLS and no redirects/proxy.
    pub(crate) fn client(&self) -> Client {
        Client::builder()
            .no_proxy()
            .resolve("localhost", self.http)
            .redirect(reqwest::redirect::Policy::none())
            .tls_certs_only([reqwest::Certificate::from_der(tls::root()).unwrap()])
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    /// Routes only exact finite scenario origins after original authorization/signature preparation.
    /// Materializing an absent Host preserves what the original URL would transmit before TLS routing.
    pub(crate) fn request(&self, mut request: Request) -> Result<Request, Error> {
        let original = request.url();
        let acquisition = Url::parse(&format!("http://{}", self.http)).unwrap();
        let playfab = crate::playfab::login_url(TITLE)?;
        let directory = Url::parse(crate::xbox::mpsd::test_support::DIRECTORY_ENDPOINT).unwrap();
        let auth = Url::parse(AUTH_ORIGIN).unwrap();
        let signaling = Url::parse(SIGNALING_ORIGIN).unwrap();
        if !original.username().is_empty()
            || original.password().is_some()
            || original.fragment().is_some()
            || ![acquisition, playfab, directory, auth, signaling]
                .iter()
                .any(|allowed| original.origin() == allowed.origin())
        {
            return Err(Error::Invalid("hosted fixture HTTP destination"));
        }
        if !request.headers().contains_key(HOST) {
            let host = &request.url()[url::Position::BeforeHost..url::Position::AfterPort];
            let host = reqwest::header::HeaderValue::from_str(host)
                .map_err(|_| Error::Invalid("hosted fixture Host"))?;
            request.headers_mut().insert(HOST, host);
        }
        let url = request.url_mut();
        url.set_scheme("https")
            .map_err(|_| Error::Invalid("hosted fixture TLS scheme"))?;
        url.set_host(Some("localhost"))
            .map_err(|_| Error::Invalid("hosted fixture TLS host"))?;
        url.set_port(Some(self.http.port()))
            .map_err(|_| Error::Invalid("hosted fixture TLS port"))?;
        Ok(request)
    }

    /// Dials only the selected owned socket and verifies the existing fixture root and localhost SNI.
    /// The original caller retains its timeout and performs its unchanged bounded protected upgrade.
    pub(crate) async fn socket(
        &self,
        url: &Url,
        kind: SocketKind,
    ) -> Result<MaybeTlsStream<TcpStream>, ()> {
        let (expected, address) = match kind {
            SocketKind::Rta => (tls::endpoint(), self.rta),
            SocketKind::Messaging => {
                let mut expected = Url::parse(SIGNALING_ORIGIN).unwrap();
                expected.set_scheme("wss").unwrap();
                let local;
                let path = if self.friend_legacy {
                    local = super::friend::sockets::legacy_id(url)
                        .ok_or(())?
                        .to_string();
                    ["ws", "v1.0", "signaling", local.as_str()]
                } else {
                    ["ws", "v1.0", "messaging", "connect"]
                };
                expected
                    .path_segments_mut()
                    .unwrap()
                    .pop_if_empty()
                    .extend(path);
                (expected, self.messaging)
            }
        };
        if url != &expected {
            return Err(());
        }
        let tcp = TcpStream::connect(address).await.map_err(|_| ())?;
        tls::connector()
            .wrap("localhost", tcp)
            .await
            .map_err(|_| ())
    }

    /// Initializes the same fixture Http owner before its first acquisition, never a separate client task.
    pub(crate) fn account_http(self: &std::sync::Arc<Self>, agent: &str) -> Http {
        let mut http = Http::fixture_agent(self.http, agent);
        #[cfg(test)]
        {
            http.endpoints.playfab = None;
        }
        http.hosted_fixture_transport(std::sync::Arc::clone(self));
        http
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unregistered origins fail locally, while routing retains the original protected wire fields.
    #[test]
    fn finite_fixture_routes_reject_foreign_origins_and_preserve_protected_requests() {
        let address = SocketAddr::from(([127, 0, 0, 1], 9));
        let transport = Transport::new(address, address, address);
        for target in [
            "https://foreign.invalid/path",
            "https://user@hosted-world-service.invalid/path",
            "https://hosted-world-service.invalid:444/path",
        ] {
            let request = Request::new(reqwest::Method::GET, Url::parse(target).unwrap());
            assert!(transport.request(request).is_err());
        }
        let mut request = Request::new(
            reqwest::Method::POST,
            Url::parse(&format!("{AUTH_ORIGIN}original?query=kept")).unwrap(),
        );
        request.headers_mut().insert(
            HOST,
            reqwest::header::HeaderValue::from_static("protected-original"),
        );
        request.headers_mut().insert(
            "signature",
            reqwest::header::HeaderValue::from_static("synthetic-proof"),
        );
        *request.body_mut() = Some(reqwest::Body::from("original-body"));
        let routed = transport.request(request).unwrap();
        assert_eq!(routed.url().host_str(), Some("localhost"));
        assert_eq!(routed.url().port(), Some(address.port()));
        assert_eq!(routed.url().path(), "/original");
        assert_eq!(routed.url().query(), Some("query=kept"));
        assert_eq!(routed.headers()[HOST], "protected-original");
        assert_eq!(routed.headers()["signature"], "synthetic-proof");
        assert_eq!(
            routed.body().unwrap().as_bytes(),
            Some(b"original-body".as_slice())
        );
    }
}
