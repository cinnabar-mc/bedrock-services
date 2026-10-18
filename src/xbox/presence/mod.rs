//! One-shot authenticated title presence publication and removal.
//!
//! The caller owns activity selection, heartbeat scheduling, deadlines and cleanup.
//! No retry, task, timer or remote operation on Drop exists. A canceled or failed
//! write may have applied remotely; explicitly remove presence on shutdown, even
//! when an earlier update did not complete. Keep account generation and persistence
//! fenced in the caller, as with other account-borrowed service operations.

mod types;

pub use types::{MAX_PARAMETERS, MAX_TEXT_BYTES, Placement, RichPresence, State, TitleUpdate};

use super::{Account, DEFAULT_LANGUAGE, XBOX_RELYING_PARTY, social::validate_xuid};
use crate::{Error, http::Response};
use reqwest::{Method, StatusCode};
use std::time::Duration;
use url::Url;

pub(super) const ENDPOINT: &str = "https://userpresence.xboxlive.com";
pub(super) const CONTRACT: &str = "3";

/// Metadata for one successful update, without a scheduling policy or local deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateResult {
    /// Positive server-requested delay, or absent for a missing/invalid header.
    /// The caller chooses a fallback and uses checked arithmetic when scheduling it.
    pub heartbeat_after: Option<Duration>,
}

/// Borrows one account's HTTP client, proof key and authorization cache.
pub struct TitlePresence<'a> {
    account: &'a mut Account,
    #[cfg(test)]
    fixture_base: Option<Url>,
}

impl Account {
    /// Borrows title presence writes without acquiring credentials or starting a worker.
    pub fn title_presence(&mut self) -> TitlePresence<'_> {
        TitlePresence {
            account: self,
            #[cfg(test)]
            fixture_base: None,
        }
    }
}

impl TitlePresence<'_> {
    /// Publishes one update or heartbeat for the authenticated title, with no title-ID override.
    /// Repeat explicitly with the current activity after the returned heartbeat delay.
    /// Cancellation may leave active presence; it never schedules another request.
    ///
    /// # Errors
    /// Returns redacted acquisition, transport or service-status errors, without retrying.
    pub async fn update(&mut self, update: &TitleUpdate<'_>) -> Result<UpdateResult, Error> {
        let bytes = update.encode()?;
        let response = self.send(Method::POST, Some(bytes)).await?;
        require_success(&response)?;
        Ok(UpdateResult {
            heartbeat_after: heartbeat_after(&response),
        })
    }

    /// Removes the authenticated title's presence once, including after an uncertain update.
    /// No local success flag suppresses cleanup, and dropping this view does not remove presence.
    ///
    /// # Errors
    /// Returns redacted acquisition, transport or service-status errors, without retrying.
    /// A failed or canceled removal may have applied; the caller owns reconciliation.
    pub async fn remove(&mut self) -> Result<(), Error> {
        require_success(&self.send(Method::DELETE, None).await?)
    }

    /// Acquires policy once, binds the path to its XUID, then signs the final request once.
    async fn send(&mut self, method: Method, body: Option<Vec<u8>>) -> Result<Response, Error> {
        let mut url = Url::parse(ENDPOINT).map_err(|_| Error::Invalid("presence endpoint"))?;
        #[cfg(test)]
        if let Some(base) = &self.fixture_base {
            url = base.clone();
        }
        let identity = self.account.authorize(XBOX_RELYING_PARTY).await?;
        validate_xuid(identity.xuid())?;
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("presence endpoint path"))?
            .pop_if_empty()
            .extend([
                "users",
                &format!("xuid({})", identity.xuid()),
                "devices",
                "current",
                "titles",
                "current",
            ]);
        let token = self.account.authorize_service(&url).await?;
        if token.xuid() != identity.xuid() {
            return Err(Error::Invalid("presence account identity"));
        }
        let mut request = self
            .account
            .http
            .request(method, url.as_str())
            .header("x-xbl-contract-version", CONTRACT)
            .header("cache-control", "no-cache")
            .header("content-type", "application/json")
            .header("accept-language", DEFAULT_LANGUAGE)
            .header("content-length", body.as_ref().map_or(0, Vec::len));
        if let Some(body) = body {
            request = request.body(body);
        }
        let request = request.build()?;
        self.account.send_service(request, token).await
    }
}

/// Accepts Presence's update/removal statuses without broadening other service contracts.
fn require_success(response: &Response) -> Result<(), Error> {
    if response.status == StatusCode::CREATED {
        Ok(())
    } else {
        response.success()
    }
}

/// Parses only positive integral seconds without overflow or a caller-specific fallback.
fn heartbeat_after(response: &Response) -> Option<Duration> {
    // Multiple conflicting scheduling headers do not establish a usable interval.
    let mut headers = response.headers.get_all("x-heartbeat-after").iter();
    let value = headers.next()?.to_str().ok()?;
    if headers.next().is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests;
