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
    access_admitted: bool,
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
            access_admitted: true,
        })
    }

    /// Explicitly exposes the current refresh token for an owner's secure persistence.
    /// This borrowed value must never be logged or placed in URLs.
    pub fn refresh_token(&self) -> &str {
        &self.refresh
    }

    /// Explicitly borrows the current access credential for protected persistence.
    /// This value is sensitive and must never appear in logs or ordinary configuration.
    /// Borrowing saved material does not admit a dormant restored token for service use.
    pub fn access_token(&self) -> &str {
        &self.access
    }

    /// Returns the access credential's expiry alongside its persisted value.
    pub fn expires_at(&self) -> SystemTime {
        self.expires
    }

    /// Compares acquisition material without allowing an identical import to change admission.
    pub(crate) fn same_material(&self, other: &Self) -> bool {
        let Self {
            client_id,
            access,
            refresh,
            expires,
            access_admitted: _,
        } = self;
        client_id == &other.client_id
            && access == &other.access
            && refresh == &other.refresh
            && expires == &other.expires
    }

    /// Keeps restored access operationally dormant while retaining its protected material.
    pub(crate) fn suspend_access(&mut self) {
        self.access_admitted = false;
    }

    /// Admits restored access only after its account qualifies fresh service time.
    pub(crate) fn admit_access(&mut self) {
        self.access_admitted = true;
    }

    /// Checks operational admission and the original conservative renewal deadline.
    pub(crate) fn valid(&self, now: SystemTime) -> bool {
        self.access_admitted
            && !self.access.is_empty()
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
        self.access_admitted = replacement.access_admitted;
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

    /// Extends the scheduled interval from response receipt without moving the grant expiry.
    fn defer_poll(&mut self, receipt: SystemTime, delay: Result<Option<Duration>, ()>) {
        self.next_poll = match delay {
            Ok(Some(delay)) => self
                .next_poll
                .max(poll_deadline(receipt, delay, self.expires)),
            Ok(None) => self.next_poll,
            Err(()) => self.expires,
        };
    }
}

/// Caps every caller-owned wait at the original grant expiry, including overflowing delays.
fn poll_deadline(now: SystemTime, delay: Duration, expires: SystemTime) -> SystemTime {
    now.checked_add(delay).unwrap_or(expires).min(expires)
}

/// The result of a single device-code poll, without internal sleeping or background tasks.
pub enum Poll {
    /// The caller should wait until the attempt's next_poll time.
    Pending,
    /// Sign-in completed; the attempt cannot be polled again.
    Authorized(Credentials),
}

/// Starts device-code sign-in and restores previously saved accounts.
///
/// Call [`start`](Self::start), display the code/URI, and call [`poll`](Self::poll)
/// when [`DeviceAuthorization::next_poll`] is due. Move authorized credentials into
/// [`into_account`](Self::into_account), or use [`restore_account`](Self::restore_account)
/// with protected checkpoint bytes. HTTP calls run on your Tokio runtime.
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
        let expires = now
            .checked_add(Duration::from_secs(value.expires_in))
            .ok_or(Error::TimeRange)?;
        Ok(DeviceAuthorization {
            code: Zeroizing::new(value.device_code),
            user_code: value.user_code,
            verification_uri: uri,
            expires,
            next_poll: poll_deadline(now, interval, expires),
            interval,
            completed: false,
            client_id: self.config.client_id.clone(),
        })
    }

    /// Polls once when due. Dropping this future cancels only this HTTP attempt.
    /// Temporary transport and server failures preserve the grant and its poll interval.
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
        attempt.next_poll = poll_deadline(now, attempt.interval, attempt.expires);
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
        let sent = self.http.retry_time();
        let result = self.http.send(request).await;
        let receipt = now
            .checked_add(self.http.retry_time().duration_since(sent))
            .unwrap_or(attempt.expires);
        let response = match result {
            Ok(response) => response,
            Err(error) if crate::http::retry::transient_poll(&error) => return Ok(Poll::Pending),
            Err(error) => return Err(error),
        };
        if response.status.is_server_error() {
            attempt.defer_poll(
                receipt,
                crate::http::retry::response_delay(&response, receipt),
            );
            return Ok(Poll::Pending);
        }
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
                attempt.next_poll = poll_deadline(now, attempt.interval, attempt.expires);
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

    /// Restores the current refresh credential and proof key from protected storage.
    ///
    /// The caller must check its account generation and latest stored revision before
    /// restoring. Optional derived entries retain their original absolute expiries
    /// and remain dormant until fresh public title policy supplies a valid response
    /// Date. Missing or unusable cached state is reacquired with the saved proof key.
    ///
    /// # Errors
    /// Returns a redacted error for malformed state, an invalid proof key, or any
    /// authentication-policy mismatch. This method sends no network requests.
    pub fn restore_account(self, checkpoint: crate::xbox::Checkpoint) -> Result<Account, Error> {
        Account::restore(self.http, self.config, checkpoint)
    }
}

#[cfg(test)]
mod tests;

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
