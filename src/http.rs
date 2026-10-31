//! Bounded, unauthenticated HTTP acquisition and response-clock correction.

pub(crate) mod call;
pub(crate) mod retry;

use crate::Error;
use reqwest::{
    Client, Method, Request, RequestBuilder, StatusCode,
    header::{ACCEPT, HOST, HeaderMap, HeaderValue},
};
use serde::de::DeserializeOwned;
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime},
};
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
    client: Arc<Client>,
    user_agent: HeaderValue,
    pub endpoints: Endpoints,
    clock: Option<(SystemTime, Instant)>,
    minimum_date: Option<SystemTime>,
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

/// Selects whether an owner needs a server-error body after receiving its headers.
enum BodyPolicy {
    Read,
    DevicePoll,
}

impl Http {
    /// Couples fixture owners to the same transport without sharing account clocks or credentials.
    #[cfg(test)]
    pub(crate) fn share_fixture_transport(&mut self, other: &Self) {
        self.client = other.client.clone();
    }

    /// Identifies the plain HTTP transport; account authorization is always attached to a request.
    pub(crate) fn transport(&self) -> &Arc<Client> {
        &self.client
    }

    /// Creates an anonymous request owner without importing account clocks or restore admission rules.
    pub(crate) fn detached(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            user_agent: self.user_agent.clone(),
            endpoints: Endpoints::default(),
            clock: None,
            minimum_date: None,
            #[cfg(test)]
            elapsed: self.elapsed,
            #[cfg(feature = "test-support")]
            hosted_transport: self.hosted_transport.clone(),
        }
    }

    /// Retains the original response observation when sharing a public lookup.
    pub(crate) fn clock_sample(&self) -> Option<(SystemTime, Instant)> {
        self.clock
    }

    /// Adopts a shared observation without reanchoring it or regressing this owner's newer clock.
    pub(crate) fn apply_clock_sample(&mut self, sample: Option<(SystemTime, Instant)>) {
        if let Some((date, observed)) = sample
            && self.minimum_date.is_none_or(|floor| date >= floor)
            && self.clock.is_none_or(|(_, current)| observed >= current)
        {
            self.clock = Some((date, observed));
            #[cfg(test)]
            {
                self.elapsed.at_response = self.elapsed.total;
            }
        }
    }

    /// Samples process-local retry time independently from service Date corrections.
    pub(crate) fn retry_time(&self) -> tokio::time::Instant {
        let now = tokio::time::Instant::now();
        #[cfg(test)]
        let now = now + self.elapsed.total;
        now
    }

    /// Builds the plain acquisition client; redirects cannot carry credentials away.
    pub fn new(user_agent: &str) -> Result<Self, Error> {
        let user_agent = HeaderValue::from_str(user_agent)
            .map_err(|_| Error::Invalid("acquisition user agent"))?;
        static DEFAULT_CLIENT: OnceLock<Arc<Client>> = OnceLock::new();
        let client = if let Some(client) = DEFAULT_CLIENT.get() {
            Arc::clone(client)
        } else {
            let client = Arc::new(
                Client::builder()
                    .https_only(true)
                    .redirect(reqwest::redirect::Policy::none())
                    .no_gzip()
                    .no_brotli()
                    .no_zstd()
                    .no_deflate()
                    .timeout(REQUEST_TIMEOUT)
                    .connect_timeout(Duration::from_secs(10))
                    .build()?,
            );
            Arc::clone(DEFAULT_CLIENT.get_or_init(|| client))
        };
        Ok(Self {
            client,
            user_agent,
            endpoints: Endpoints::default(),
            clock: None,
            minimum_date: None,
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
        self.minimum_date = source.minimum_date;
        #[cfg(test)]
        {
            self.elapsed = source.elapsed;
        }
    }

    /// Borrows the original response UTC sample without persisting its monotonic anchor.
    pub(crate) fn response_time(&self) -> Option<SystemTime> {
        self.minimum_date
            .or_else(|| self.clock.map(|(server, _)| server))
    }

    /// Captures host UTC at the HTTP edge, including explicitly simulated fixture elapsed time.
    pub(crate) fn local_time(&self) -> SystemTime {
        #[cfg(test)]
        let elapsed = self.elapsed.total;
        #[cfg(not(test))]
        let elapsed = Duration::ZERO;
        SystemTime::now() + elapsed
    }

    /// Advances saved service time by host elapsed time, rejecting a host-clock rollback or overflow.
    pub(crate) fn resumed_time(
        &self,
        service: SystemTime,
        local: SystemTime,
    ) -> Option<SystemTime> {
        let now = service.checked_add(self.local_time().duration_since(local).ok()?)?;
        let nanos =
            i128::try_from(now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_nanos()).ok()?;
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
        Some(now)
    }

    /// Starts a validated restart estimate; the next successful response must supply a nonregressing Date.
    pub(crate) fn resume_clock(&mut self, now: SystemTime, observed: SystemTime) {
        self.clock = Some((now, Instant::now()));
        self.minimum_date = Some(observed);
        #[cfg(test)]
        {
            self.elapsed.at_response = self.elapsed.total;
        }
    }

    /// Shares a fresh authenticated transport observation without reanchoring its lifetime.
    pub(crate) fn inherit_clock(&mut self, source: &Self) {
        self.clock = source.clock;
        self.minimum_date = source.minimum_date;
        #[cfg(test)]
        {
            self.elapsed = source.elapsed;
        }
    }

    /// Keeps acquisition and ordinary service reads within the default byte budget.
    pub async fn send(&mut self, request: Request) -> Result<Response, Error> {
        self.send_with_limit(request, RESPONSE_LIMIT).await
    }

    /// Retains device-poll backoff headers without reading unused server-error bodies.
    pub(crate) async fn send_device_poll(&mut self, request: Request) -> Result<Response, Error> {
        self.send_with_body_policy(request, RESPONSE_LIMIT, BodyPolicy::DevicePoll)
            .await
    }

    /// Replays only an explicitly selected buffered acquisition under one original budget.
    pub(crate) async fn send_retrying(
        &mut self,
        request: Request,
        policy: retry::Policy,
    ) -> Result<Response, Error> {
        self.send_retrying_with_limit(request, policy, RESPONSE_LIMIT)
            .await
    }

    /// Applies the owner's resend policy without changing its response byte limit.
    pub(crate) async fn send_retrying_with_limit(
        &mut self,
        request: Request,
        policy: retry::Policy,
        response_limit: usize,
    ) -> Result<Response, Error> {
        let mut retry = retry::Retry::new(policy);
        let template = request.try_clone();
        let mut attempt = request;
        loop {
            retry.begin(&mut attempt);
            let result = self.send_with_limit(attempt, response_limit).await;
            if !retry.wait(&result, self.now()).await {
                return result;
            }
            let Some(next) = template.as_ref().and_then(Request::try_clone) else {
                return result;
            };
            attempt = next;
        }
    }

    /// Bounds declared and streamed bodies by the concrete service owner's budget.
    pub(crate) async fn send_with_limit(
        &mut self,
        request: Request,
        response_limit: usize,
    ) -> Result<Response, Error> {
        self.send_with_body_policy(request, response_limit, BodyPolicy::Read)
            .await
    }

    /// Shares request preparation and clocks while keeping body admission owner-specific.
    async fn send_with_body_policy(
        &mut self,
        request: Request,
        response_limit: usize,
        policy: BodyPolicy,
    ) -> Result<Response, Error> {
        #[cfg(feature = "test-support")]
        let request = match &self.hosted_transport {
            Some(transport) => transport.request(request)?,
            None => request,
        };
        let mut request = request;
        if let Some(deadline) = call::deadline() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            *request.timeout_mut() = Some(
                request
                    .timeout()
                    .copied()
                    .unwrap_or(remaining)
                    .min(remaining),
            );
        }
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
        let date = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok());
        if let Some(date) = date.filter(|date| self.minimum_date.is_none_or(|floor| *date >= floor))
        {
            self.clock = Some((date, Instant::now()));
            #[cfg(test)]
            {
                self.elapsed.at_response = self.elapsed.total;
            }
        }
        let status = response.status();
        let headers = response.headers().clone();
        if matches!(policy, BodyPolicy::DevicePoll) && status.is_server_error() {
            return Ok(Response {
                status,
                headers,
                body: Vec::new().into(),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > response_limit as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > response_limit.saturating_sub(body.len()) {
                return Err(Error::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if status.is_success()
            && let Some(floor) = self.minimum_date
        {
            if date.is_none_or(|date| date < floor) {
                return Err(Error::Invalid("restored service response Date"));
            }
            self.minimum_date = None;
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
        self.client = Arc::new(transport.client());
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
            client: Arc::new(client),
            user_agent: HeaderValue::from_str(user_agent).unwrap(),
            endpoints: Endpoints::default(),
            clock: None,
            minimum_date: None,
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
            client: Arc::new(
                Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .no_gzip()
                    .no_brotli()
                    .no_zstd()
                    .no_deflate()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap(),
            ),
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
            minimum_date: None,
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
