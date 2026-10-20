//! Bounded authenticated title presence updates and one-shot removal.
//!
//! The caller owns activity selection, heartbeat scheduling, deadlines and cleanup.
//! Throttled updates retry within the original HTTP budget without background work.
//! A canceled or failed write may have applied remotely; explicitly remove presence
//! on shutdown, even when an earlier update did not complete. Keep account generation
//! and persistence fenced in the caller, as with other account-borrowed operations.

mod types;

pub use types::{MAX_PARAMETERS, MAX_TEXT_BYTES, Placement, RichPresence, State, TitleUpdate};

use super::{Account, DEFAULT_LANGUAGE, XBOX_RELYING_PARTY, social::validate_xuid};
use crate::{
    Error,
    http::{Response, retry},
};
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
    /// Publishes an update or heartbeat for the authenticated title, with no title-ID override.
    /// Retries only throttled/unavailable responses, up to three sends in one HTTP budget.
    /// Repeat explicitly with the current activity after the returned heartbeat delay.
    /// Cancellation may leave active presence; dropping the future ends its retries.
    ///
    /// # Errors
    /// Returns redacted acquisition, transport or final service-status errors.
    pub async fn update(&mut self, update: &TitleUpdate<'_>) -> Result<UpdateResult, Error> {
        self.update_with_dispatch(update, || {}).await
    }

    /// Publishes one update and reports conservative dispatch after final signing, before HTTP.
    /// The callback runs once only after acquisition and request preparation succeed. It does
    /// not prove remote receipt or success; later failure or cancellation may leave presence.
    /// Retain caller-owned dispatch state across cancellation to track that uncertainty.
    /// Use an infallible local state update; an unpolled future never invokes the callback.
    ///
    /// # Errors
    /// Returns the same redacted acquisition, transport or service-status errors as [`Self::update`].
    pub async fn update_with_dispatch(
        &mut self,
        update: &TitleUpdate<'_>,
        dispatched: impl FnOnce(),
    ) -> Result<UpdateResult, Error> {
        let bytes = update.encode()?;
        let response = self.send(Method::POST, Some(bytes), dispatched).await?;
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
        require_success(&self.send(Method::DELETE, None, || {}).await?)
    }

    /// Acquires policy once and binds the path to its XUID; each update retry is signed anew.
    async fn send(
        &mut self,
        method: Method,
        body: Option<Vec<u8>>,
        dispatched: impl FnOnce(),
    ) -> Result<Response, Error> {
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
        let retry_update = method == Method::POST;
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
        if !retry_update {
            return self
                .account
                .send_service_with_dispatch(request, token, dispatched)
                .await;
        }
        let mut retry = retry::Retry::new(retry::Policy::Presence);
        let mut dispatched = Some(dispatched);
        loop {
            let mut attempt = request
                .try_clone()
                .ok_or(Error::Invalid("non-replayable presence update"))?;
            retry.begin(&mut attempt);
            let result = self
                .account
                .send_service_with_dispatch(attempt, token.clone(), || {
                    if let Some(dispatched) = dispatched.take() {
                        dispatched();
                    }
                })
                .await;
            if !retry.wait(&result, self.account.http.now()).await {
                return result;
            }
        }
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
