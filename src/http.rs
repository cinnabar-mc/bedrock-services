//! Bounded, unauthenticated HTTP acquisition and response-clock correction.

pub(crate) mod retry;

use crate::Error;
use reqwest::{
    Client, Method, Request, RequestBuilder, StatusCode,
    header::{ACCEPT, HOST, HeaderMap, HeaderValue},
};
use serde::de::DeserializeOwned;
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

pub(crate) const RESPONSE_LIMIT: usize = 1024 * 1024;
/// Shared source-backed response budget for persona, statistics and Minecraft messaging.
pub(crate) const SERVICE_RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
const DEFAULT_ACCEPT: &str = "*/*";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const SISU_ORIGIN: &str = "https://sisu.xboxlive.com";

pub(crate) struct Endpoints {
    pub device_code: String,
    pub oauth_token: String,
    pub device_token: String,
    pub sisu: String,
    pub xsts: String,
    pub nsal: String,
    pub nsal_current: String,
    pub discovery: String,
    #[cfg(test)]
    pub playfab: Option<String>,
}

impl Default for Endpoints {
    /// Keeps the acquisition destinations together, separate from service traffic.
    fn default() -> Self {
        Self {
            device_code: "https://login.live.com/oauth20_connect.srf".into(),
            oauth_token: "https://login.live.com/oauth20_token.srf".into(),
            device_token: "https://device.auth.xboxlive.com/device/authenticate".into(),
            sisu: format!("{SISU_ORIGIN}/authorize"),
            xsts: "https://xsts.auth.xboxlive.com/xsts/authorize".into(),
            nsal: "https://title.mgt.xboxlive.com/titles/default/endpoints?type=1".into(),
            nsal_current: "https://title.mgt.xboxlive.com/titles/current/endpoints".into(),
            discovery: "https://client.discovery.minecraft-services.net".into(),
            #[cfg(test)]
            playfab: None,
        }
    }
}

pub(crate) struct Http {
    client: Client,
    user_agent: HeaderValue,
    pub endpoints: Endpoints,
    clock: Option<(SystemTime, Instant)>,
    #[cfg(test)]
    elapsed: FixtureElapsed,
    #[cfg(feature = "test-support")]
    hosted_transport: Option<std::sync::Arc<crate::test_support::activation::transport::Transport>>,
}

/// Simulated time passing for fixture clocks, so tests advance without sleeping.
#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct FixtureElapsed {
    total: Duration,       // added to the host clock while no Date was seen
    at_response: Duration, // total when the last Date arrived
}

pub(crate) struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl Http {
    /// Builds the plain acquisition client; redirects cannot carry credentials away.
    pub fn new(user_agent: &str) -> Result<Self, Error> {
        let user_agent = HeaderValue::from_str(user_agent)
            .map_err(|_| Error::Invalid("acquisition user agent"))?;
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            user_agent,
            endpoints: Endpoints::default(),
            clock: None,
            #[cfg(test)]
            elapsed: FixtureElapsed::default(),
            #[cfg(feature = "test-support")]
            hosted_transport: None,
        })
    }

    /// Materializes the acquisition User-Agent before building or signing a request.
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client
            .request(method, url)
            .header("user-agent", self.user_agent.clone())
    }

    /// Materializes this client's absent transport defaults before advertised-policy signing.
    /// Explicit service headers are preserved; compression defaults are disabled on the client.
    pub fn prepare_signature(&self, request: &mut Request) -> Result<(), Error> {
        if !request.headers().contains_key(HOST) {
            let url = request.url();
            if !url.has_host() {
                return Err(Error::Invalid("signed request host"));
            }
            let host =
                HeaderValue::from_str(&url[url::Position::BeforeHost..url::Position::AfterPort])
                    .map_err(|_| Error::Invalid("signed request host"))?;
            request.headers_mut().insert(HOST, host);
        }
        request
            .headers_mut()
            .entry(ACCEPT)
            .or_insert(HeaderValue::from_static(DEFAULT_ACCEPT));
        Ok(())
    }

    /// Advances the last server Date with monotonic elapsed time at the HTTP edge.
    pub fn now(&self) -> SystemTime {
        #[cfg(test)]
        let (local, since_response) = (
            self.elapsed.total,
            self.elapsed.total - self.elapsed.at_response,
        );
        #[cfg(not(test))]
        let (local, since_response) = (Duration::ZERO, Duration::ZERO);
        match self.clock {
            Some((server, received)) => server
                .checked_add(received.elapsed() + since_response)
                .unwrap_or_else(SystemTime::now),
            None => SystemTime::now() + local,
        }
    }

    /// Retains the original response observation when the sealed fixture changes HTTP owners.
    #[cfg(feature = "test-support")]
    pub(crate) fn inherit_fixture_clock(&mut self, source: &Self) {
        self.clock = Some(source.clock.expect("original fixture response has a Date"));
        #[cfg(test)]
        {
            self.elapsed = source.elapsed;
        }
    }

    /// Borrows the original response UTC sample without persisting its monotonic anchor.
    pub(crate) fn response_time(&self) -> Option<SystemTime> {
        self.clock.map(|(server, _)| server)
    }

    /// Shares a fresh authenticated transport observation without reanchoring its lifetime.
    pub(crate) fn inherit_clock(&mut self, source: &Self) {
        self.clock = source.clock;
        #[cfg(test)]
        {
            self.elapsed = source.elapsed;
        }
    }

    /// Keeps acquisition and ordinary service reads within the default byte budget.
    pub async fn send(&mut self, request: Request) -> Result<Response, Error> {
        self.send_with_limit(request, RESPONSE_LIMIT).await
    }

    /// Replays only an explicitly selected buffered acquisition under one original budget.
    pub(crate) async fn send_retrying(
        &mut self,
        request: Request,
        policy: retry::Policy,
    ) -> Result<Response, Error> {
        let mut retry = retry::Retry::new(policy);
        loop {
            let mut attempt = request
                .try_clone()
                .ok_or(Error::Invalid("non-replayable acquisition request"))?;
            retry.begin(&mut attempt);
            let result = self.send(attempt).await;
            if !retry.wait(&result, self.now()).await {
                return result;
            }
        }
    }

    /// Bounds declared and streamed bodies by the concrete service owner's budget.
    pub(crate) async fn send_with_limit(
        &mut self,
        request: Request,
        response_limit: usize,
    ) -> Result<Response, Error> {
        #[cfg(feature = "test-support")]
        let request = match &self.hosted_transport {
            Some(transport) => transport.request(request)?,
            None => request,
        };
        let mut request = request;
        let mut hosts = request.headers().get_all(HOST).iter();
        let redundant_host = hosts.next().is_some_and(|host| {
            host.as_bytes()
                == request.url()[url::Position::BeforeHost..url::Position::AfterPort].as_bytes()
        }) && hosts.next().is_none();
        if redundant_host {
            // HTTP/2 carries authority separately; HTTP/1 supplies its mandatory Host.
            request.headers_mut().remove(HOST);
        }
        let mut response = self.client.execute(request).await?;
        if let Some(date) = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
        {
            self.clock = Some((date, Instant::now()));
            #[cfg(test)]
            {
                self.elapsed.at_response = self.elapsed.total;
            }
        }
        if response
            .content_length()
            .is_some_and(|length| length > response_limit as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > response_limit.saturating_sub(body.len()) {
                return Err(Error::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    /// Sends a buffered JSON request whose exact bytes are signed when requested.
    pub fn post_json(&self, url: &str, value: &impl serde::Serialize) -> Result<Request, Error> {
        let mut body = serde_json::to_vec(value).map_err(|_| Error::Invalid("request JSON"))?;
        // The behavioral baseline encodes JSON requests with a trailing newline.
        body.push(b'\n');
        Ok(self
            .request(Method::POST, url)
            .header("accept", DEFAULT_ACCEPT)
            .header("content-type", "application/json")
            .header("content-length", body.len())
            .body(body)
            .build()?)
    }

    /// Retains only the finite opt-in fixture's metadata, with no socket/task ownership.
    #[cfg(feature = "test-support")]
    pub(crate) fn hosted_transport(
        &self,
    ) -> Option<std::sync::Arc<crate::test_support::activation::transport::Transport>> {
        self.hosted_transport.clone()
    }

    /// Installs verified loopback routing only on the actual explicitly acquired fixture Http owner.
    #[cfg(feature = "test-support")]
    pub(crate) fn hosted_fixture_transport(
        &mut self,
        transport: std::sync::Arc<crate::test_support::activation::transport::Transport>,
    ) {
        self.client = transport.client();
        self.hosted_transport = Some(transport);
    }

    #[cfg(test)]
    /// Simulates `by` of host and monotonic time passing; Date samples are kept.
    pub(crate) fn advance_fixture_time(&mut self, by: Duration) {
        self.elapsed.total += by;
    }

    #[cfg(test)]
    /// Advances fixture UTC explicitly without sleeping or changing the host clock.
    pub(crate) fn set_fixture_time(&mut self, now: SystemTime) {
        self.clock = Some((now, Instant::now()));
        self.elapsed.at_response = self.elapsed.total;
    }

    #[cfg(test)]
    /// Uses only the test's loopback endpoint without changing production TLS policy.
    pub fn fixture(address: std::net::SocketAddr) -> Self {
        Self::fixture_agent(address, "fixture-acquisition-agent")
    }

    #[cfg(test)]
    /// Reaches the shared trace peer under the real service hostnames: every name
    /// resolves to its loopback address, and only its fixture CA is trusted.
    pub(crate) fn trace_fixture(
        address: std::net::SocketAddr,
        ca_pem: &[u8],
        user_agent: &str,
    ) -> Self {
        struct Loopback(std::net::SocketAddr);
        impl reqwest::dns::Resolve for Loopback {
            fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
                let addresses: reqwest::dns::Addrs = Box::new(std::iter::once(self.0));
                Box::pin(std::future::ready(Ok::<
                    _,
                    Box<dyn std::error::Error + Send + Sync>,
                >(addresses)))
            }
        }
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .tls_certs_only([reqwest::Certificate::from_pem(ca_pem).unwrap()])
            .dns_resolver(std::sync::Arc::new(Loopback(address)))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            client,
            user_agent: HeaderValue::from_str(user_agent).unwrap(),
            endpoints: Endpoints::default(),
            clock: None,
            #[cfg(test)]
            elapsed: FixtureElapsed::default(),
            #[cfg(feature = "test-support")]
            hosted_transport: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Exercises an edge owner's explicit agent against a local HTTP fixture.
    pub fn fixture_agent(address: std::net::SocketAddr, user_agent: &str) -> Self {
        let base = format!("http://{address}");
        Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .no_gzip()
                .no_brotli()
                .no_zstd()
                .no_deflate()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            user_agent: HeaderValue::from_str(user_agent).unwrap(),
            endpoints: Endpoints {
                device_code: format!("{base}/device-code"),
                oauth_token: format!("{base}/oauth-token"),
                device_token: format!("{base}/device-token"),
                sisu: format!("{base}/sisu"),
                xsts: format!("{base}/xsts"),
                nsal: format!("{base}/nsal"),
                nsal_current: format!("{base}/nsal-current"),
                discovery: base.clone(),
                #[cfg(test)]
                playfab: Some(format!("{base}/Client/LoginWithXbox")),
            },
            clock: None,
            #[cfg(test)]
            elapsed: FixtureElapsed::default(),
            #[cfg(feature = "test-support")]
            hosted_transport: None,
        }
    }
}

#[cfg(test)]
mod tests;

impl Response {
    /// Rejects non-success authentication responses without retaining their text.
    pub fn success(&self) -> Result<(), Error> {
        if self.status == StatusCode::OK {
            return Ok(());
        }
        Err(Error::Status {
            status: self.status,
            xerr: self
                .headers
                .get("x-err")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok()),
        })
    }

    /// Deserializes a bounded response without echoing secret invalid field values.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(|_| Error::Invalid("response JSON"))
    }
}
