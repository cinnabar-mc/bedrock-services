//! Bounded, unauthenticated HTTP acquisition and response-clock correction.

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
    #[cfg(feature = "test-support")]
    hosted_transport: Option<std::sync::Arc<crate::test_support::activation::transport::Transport>>,
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
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            user_agent,
            endpoints: Endpoints::default(),
            clock: None,
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
        match self.clock {
            Some((server, received)) => server
                .checked_add(received.elapsed())
                .unwrap_or_else(SystemTime::now),
            None => SystemTime::now(),
        }
    }

    /// Borrows the original response UTC sample without persisting its monotonic anchor.
    pub(crate) fn response_time(&self) -> Option<SystemTime> {
        self.clock.map(|(server, _)| server)
    }

    /// Keeps acquisition and ordinary service reads within the default byte budget.
    pub async fn send(&mut self, request: Request) -> Result<Response, Error> {
        self.send_with_limit(request, RESPONSE_LIMIT).await
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
        let mut response = self.client.execute(request).await?;
        if let Some(date) = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
        {
            self.clock = Some((date, Instant::now()));
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
    /// Advances fixture UTC explicitly without sleeping or changing the host clock.
    pub(crate) fn set_fixture_time(&mut self, now: SystemTime) {
        self.clock = Some((now, Instant::now()));
    }

    #[cfg(test)]
    /// Uses only the test's loopback endpoint without changing production TLS policy.
    pub fn fixture(address: std::net::SocketAddr) -> Self {
        Self::fixture_agent(address, "fixture-acquisition-agent")
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
