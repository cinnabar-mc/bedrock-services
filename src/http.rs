//! Bounded, unauthenticated HTTP acquisition and response-clock correction.

use crate::Error;
use reqwest::{Client, Request, StatusCode, header::HeaderMap};
use serde::de::DeserializeOwned;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

pub(crate) const RESPONSE_LIMIT: usize = 1024 * 1024;

pub(crate) struct Endpoints {
    pub device_code: String,
    pub oauth_token: String,
    pub device_token: String,
    pub sisu: String,
    pub xsts: String,
    pub nsal: String,
}

impl Default for Endpoints {
    /// Keeps the acquisition destinations together, separate from service traffic.
    fn default() -> Self {
        Self {
            device_code: "https://login.live.com/oauth20_connect.srf".into(),
            oauth_token: "https://login.live.com/oauth20_token.srf".into(),
            device_token: "https://device.auth.xboxlive.com/device/authenticate".into(),
            sisu: "https://sisu.xboxlive.com/authorize".into(),
            xsts: "https://xsts.auth.xboxlive.com/xsts/authorize".into(),
            nsal: "https://title.mgt.xboxlive.com/titles/default/endpoints?type=1".into(),
        }
    }
}

pub(crate) struct Http {
    pub client: Client,
    pub endpoints: Endpoints,
    skew: Option<(bool, Duration)>,
}

pub(crate) struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl Http {
    /// Builds the plain acquisition client; redirects cannot carry credentials away.
    pub fn new(user_agent: &str) -> Result<Self, Error> {
        let client = Client::builder()
            .user_agent(user_agent)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            endpoints: Endpoints::default(),
            skew: None,
        })
    }

    /// Reads the edge clock and applies the last successfully parsed server Date.
    pub fn now(&self) -> SystemTime {
        let local = SystemTime::now();
        match self.skew {
            Some((true, delta)) => local.checked_add(delta).unwrap_or(local),
            Some((false, delta)) => local.checked_sub(delta).unwrap_or(local),
            None => local,
        }
    }

    /// Bounds both declared and streamed bodies, retaining only redacted failures.
    pub async fn send(&mut self, request: Request) -> Result<Response, Error> {
        let mut response = self.client.execute(request).await?;
        if let Some(date) = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
        {
            let local = SystemTime::now();
            self.skew = Some(match date.duration_since(local) {
                Ok(delta) => (true, delta),
                Err(error) => (false, error.duration()),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > RESPONSE_LIMIT as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > RESPONSE_LIMIT.saturating_sub(body.len()) {
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
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .build()?)
    }

    #[cfg(test)]
    /// Uses only the test's loopback endpoint without changing production TLS policy.
    pub fn fixture(address: std::net::SocketAddr) -> Self {
        let base = format!("http://{address}");
        Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            endpoints: Endpoints {
                device_code: format!("{base}/device-code"),
                oauth_token: format!("{base}/oauth-token"),
                device_token: format!("{base}/device-token"),
                sisu: format!("{base}/sisu"),
                xsts: format!("{base}/xsts"),
                nsal: format!("{base}/nsal"),
            },
            skew: None,
        }
    }
}

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
