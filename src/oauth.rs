//! Microsoft device-code sign-in and account-bound refresh credentials.

use crate::{
    Error,
    http::Http,
    xbox::{Account, Config},
};
use serde::Deserialize;
use std::time::{Duration, SystemTime};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const SCOPE: &str = "service::user.auth.xboxlive.com::MBI_SSL";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Microsoft credentials bound to the client ID that acquired them.
/// Debug output is deliberately unavailable; fields are not implicitly serialized.
pub struct Credentials {
    pub(crate) client_id: String,
    pub(crate) access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    expires: SystemTime,
}

impl Credentials {
    /// Imports existing credentials; the caller must preserve their original client ID.
    pub fn from_tokens(
        client_id: String,
        access: String,
        refresh: String,
        expires: SystemTime,
    ) -> Result<Self, Error> {
        if client_id.is_empty() || (access.is_empty() && refresh.is_empty()) {
            return Err(Error::Invalid("empty Microsoft credential"));
        }
        Ok(Self {
            client_id,
            access: Zeroizing::new(access),
            refresh: Zeroizing::new(refresh),
            expires,
        })
    }

    /// Explicitly exposes the current refresh token for an owner's secure persistence.
    /// This borrowed value must never be logged or placed in URLs.
    pub fn refresh_token(&self) -> &str {
        &self.refresh
    }

    /// Checks the access token against a conservative renewal margin.
    pub(crate) fn valid(&self, now: SystemTime) -> bool {
        !self.access.is_empty()
            && self
                .expires
                .duration_since(now)
                .is_ok_and(|remaining| remaining > Duration::from_secs(60))
    }

    /// Renews using plain HTTP, publishing a rotated refresh token before returning.
    pub(crate) async fn renew(&mut self, http: &mut Http) -> Result<(), Error> {
        if self.valid(http.now()) {
            return Ok(());
        }
        if self.refresh.is_empty() {
            return Err(Error::SignInRequired);
        }
        let request = http
            .request(reqwest::Method::POST, &http.endpoints.oauth_token)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", self.refresh.as_str()),
                ("scope", SCOPE),
                ("client_id", self.client_id.as_str()),
            ])
            .build()?;
        let response = http.send(request).await?;
        if !response.status.is_success() {
            if response
                .json::<OAuthError>()
                .is_ok_and(|error| error.error == "invalid_grant")
            {
                return Err(Error::SignInRequired);
            }
            response.success()?;
        }
        let token: TokenResponse = response.json()?;
        let replacement = token.credentials(self.client_id.clone(), http.now())?;
        self.access = replacement.access;
        self.expires = replacement.expires;
        if !replacement.refresh.is_empty() {
            self.refresh = replacement.refresh;
        }
        Ok(())
    }
}

/// One pending interactive device-code attempt. The device code remains private.
pub struct DeviceAuthorization {
    code: Zeroizing<String>,
    user_code: String,
    verification_uri: Url,
    expires: SystemTime,
    next_poll: SystemTime,
    interval: Duration,
    completed: bool,
    client_id: String,
}

impl DeviceAuthorization {
    /// Returns the short code intended for display to the signing-in user.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }
    /// Returns the HTTPS page where the user enters their short code.
    pub fn verification_uri(&self) -> &Url {
        &self.verification_uri
    }
    /// Returns the earliest allowed poll time, incorporating service slow-down responses.
    pub fn next_poll(&self) -> SystemTime {
        self.next_poll
    }
}

/// The result of a single device-code poll, without internal sleeping or background tasks.
pub enum Poll {
    /// The caller should wait until the attempt's next_poll time.
    Pending,
    /// Sign-in completed; the attempt cannot be polled again.
    Authorized(Credentials),
}

/// Owns the plain Microsoft acquisition client, which can move into a signed-in account.
pub struct MicrosoftAuth {
    pub(crate) http: Http,
    pub(crate) config: Config,
}

impl MicrosoftAuth {
    /// Creates an acquisition client with finite HTTP deadlines and disabled redirects.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            http: Http::new(&config.user_agent)?,
            config,
        })
    }

    /// Starts one device-code attempt; callers display the returned code and HTTPS URI.
    pub async fn start(&mut self, now: SystemTime) -> Result<DeviceAuthorization, Error> {
        let request = self
            .http
            .request(reqwest::Method::POST, &self.http.endpoints.device_code)
            .header("accept", "application/json")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("scope", SCOPE),
                ("response_type", "device_code"),
            ])
            .build()?;
        let response = self.http.send(request).await?;
        response.success()?;
        let value: DeviceResponse = response.json()?;
        let uri = Url::parse(&value.verification_uri)
            .map_err(|_| Error::Invalid("device verification URI"))?;
        if value.device_code.is_empty()
            || value.user_code.is_empty()
            || value.expires_in == 0
            || uri.scheme() != "https"
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
        {
            return Err(Error::Invalid("device-code response"));
        }
        let interval =
            Duration::from_secs(value.interval.filter(|seconds| *seconds != 0).unwrap_or(5));
        Ok(DeviceAuthorization {
            code: Zeroizing::new(value.device_code),
            user_code: value.user_code,
            verification_uri: uri,
            expires: now
                .checked_add(Duration::from_secs(value.expires_in))
                .ok_or(Error::TimeRange)?,
            next_poll: now.checked_add(interval).ok_or(Error::TimeRange)?,
            interval,
            completed: false,
            client_id: self.config.client_id.clone(),
        })
    }

    /// Polls once when due. Dropping this future cancels only this HTTP attempt.
    pub async fn poll(
        &mut self,
        attempt: &mut DeviceAuthorization,
        now: SystemTime,
    ) -> Result<Poll, Error> {
        if attempt.client_id != self.config.client_id {
            return Err(Error::Invalid("device-code client ID"));
        }
        if attempt.completed || now >= attempt.expires {
            return Err(Error::DeviceCodeExpired);
        }
        if now < attempt.next_poll {
            return Ok(Poll::Pending);
        }
        // Commit pacing before awaiting, so canceled attempts cannot bypass the interval.
        attempt.next_poll = now.checked_add(attempt.interval).ok_or(Error::TimeRange)?;
        let request = self
            .http
            .request(reqwest::Method::POST, &self.http.endpoints.oauth_token)
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("grant_type", DEVICE_GRANT),
                ("device_code", attempt.code.as_str()),
                ("scope", SCOPE),
            ])
            .build()?;
        let response = self.http.send(request).await?;
        if response.status == reqwest::StatusCode::OK {
            let token: TokenResponse = response.json()?;
            let credentials = token.credentials(self.config.client_id.clone(), self.http.now())?;
            attempt.completed = true;
            attempt.code.zeroize();
            return Ok(Poll::Authorized(credentials));
        }
        match response.json::<OAuthError>()?.error.as_str() {
            "authorization_pending" => Ok(Poll::Pending),
            "slow_down" => {
                attempt.interval = attempt
                    .interval
                    .checked_add(Duration::from_secs(5))
                    .ok_or(Error::TimeRange)?;
                attempt.next_poll = now.checked_add(attempt.interval).ok_or(Error::TimeRange)?;
                Ok(Poll::Pending)
            }
            "authorization_declined" | "access_denied" => {
                attempt.completed = true;
                Err(Error::AuthorizationDeclined)
            }
            "expired_token" => {
                attempt.completed = true;
                Err(Error::DeviceCodeExpired)
            }
            _ => {
                response.success()?;
                Err(Error::Invalid("OAuth device response"))
            }
        }
    }

    /// Moves the acquisition owner and Microsoft credentials into one Xbox account.
    pub fn into_account(self, credentials: Credentials) -> Result<Account, Error> {
        if credentials.client_id != self.config.client_id {
            return Err(Error::Invalid("credential client ID"));
        }
        Account::new(self.http, self.config, credentials)
    }
}

#[derive(Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    #[serde(alias = "verification_url")]
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    expires_in: Seconds,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Seconds {
    Integer(u64),
    Text(String),
}

impl TokenResponse {
    /// Validates fresh credentials before allowing them to replace account state.
    fn credentials(self, client_id: String, now: SystemTime) -> Result<Credentials, Error> {
        let seconds = match self.expires_in {
            Seconds::Integer(value) => value,
            Seconds::Text(value) => value.parse().map_err(|_| Error::Invalid("OAuth expiry"))?,
        };
        if self.access_token.is_empty() || seconds <= 60 {
            return Err(Error::Invalid("OAuth token lifetime"));
        }
        Credentials::from_tokens(
            client_id,
            self.access_token,
            self.refresh_token,
            now.checked_add(Duration::from_secs(seconds))
                .ok_or(Error::TimeRange)?,
        )
    }
}
