//! Account-borrowed discovery, population snapshots and explicit experience joins.
//!
//! Catalog metadata is not connection authority. Listing never joins or fetches artwork.
//! Calls have a shared preparation/send deadline; callers own polling and uncertain join outcomes.

mod types;
pub use types::{
    AvailableGame, CatalogItem, DestinationInfo, DisplayProperties, ExperiencePlayerCount, Image,
    JoinAddress, SearchFilter, SearchResult,
};

use super::{Minecraft, append, validate_service_url};
use crate::{Error, http::Response};
use reqwest::{Method, Request, StatusCode, header::HeaderValue};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::time::{Duration, Instant};
use types::Object;
use url::Url;
use uuid::Uuid;

/// Minimum interval between completed player-count attempts, measured from request start.
pub const PLAYER_COUNTS_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub(super) struct State {
    counts: Vec<ExperiencePlayerCount>,
    requested: Option<Instant>,
}

/// Borrows the same Minecraft authorization, discovery and retained population cache.
pub struct Gatherings<'a> {
    minecraft: &'a mut Minecraft,
    base: Url,
}

impl Minecraft {
    /// Resolves the optional retail service without acquiring a new authorization.
    ///
    /// # Errors
    /// Rejects absent/unsafe discovery before sending credentials to the service.
    pub async fn gatherings(&mut self) -> Result<Gatherings<'_>, Error> {
        crate::http::call::run(async {
            self.discover().await?;
            let uri = self
                .environments
                .as_ref()
                .and_then(|environments| environments.gatherings.as_ref())
                .and_then(|environment| environment.get("prod"))
                .and_then(|environment| environment.get("serviceUri"))
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Invalid("missing gatherings discovery"))?;
            validate_service_url(uri)?;
            let base = Url::parse(uri).map_err(|_| Error::Invalid("gatherings URL"))?;
            Ok(Gatherings {
                minecraft: self,
                base,
            })
        })
        .await
    }
}

impl Gatherings<'_> {
    /// Returns one catalog page in service order; continuation is explicit caller policy.
    /// Hidden/type/rank/localization filtering belongs to the application.
    ///
    /// # Errors
    /// Rejects invalid filters, malformed envelopes and bounded HTTP/auth failures.
    pub async fn search_items(&mut self, filter: &SearchFilter) -> Result<SearchResult, Error> {
        if filter.count.is_some_and(|count| count == 0 || count > 50) {
            return Err(Error::Invalid("gatherings search count"));
        }
        let url = append(
            self.base.as_str(),
            &["api", "v2.0", "discovery", "blob", "client"],
        )?;
        let mut request = self.minecraft.http.post_json(url.as_str(), filter)?;
        request
            .headers_mut()
            .insert("accept-language", HeaderValue::from_static("en-US"));
        let response = self
            .send(
                "search_items",
                request,
                crate::http::retry::Policy::Replayable,
            )
            .await?;
        #[derive(Deserialize)]
        struct Envelope {
            data: Object<SearchResult>,
        }
        Ok(response.json::<Object<Envelope>>()?.0.data.0)
    }

    /// Returns the last complete population snapshot, including after a refresh error.
    /// No request, throttle change or credential acquisition occurs.
    pub fn cached_player_counts(&self) -> &[ExperiencePlayerCount] {
        &self.minecraft.gatherings_state.counts
    }

    /// Reads populations at most once per interval, preserving missing counts and service order.
    /// A completed failure retains the previous values and attempt throttle. Cancellation leaves
    /// the old cache/throttle untouched; there is no detached request or automatic retry.
    ///
    /// # Errors
    /// Returns malformed envelope/HTTP/auth errors; cached values remain separately available.
    pub async fn player_counts(&mut self) -> Result<Vec<ExperiencePlayerCount>, Error> {
        let started = Instant::now();
        if self.minecraft.gatherings_state.requested.is_some_and(|at| {
            started.saturating_duration_since(at) < PLAYER_COUNTS_REFRESH_INTERVAL
        }) {
            return Ok(self.minecraft.gatherings_state.counts.clone());
        }
        let result = self.fetch_counts().await;
        self.minecraft.gatherings_state.requested = Some(started);
        if let Ok(counts) = &result {
            self.minecraft.gatherings_state.counts.clone_from(counts);
        }
        result
    }

    /// Fetches and validates the complete snapshot before any retained state is changed.
    async fn fetch_counts(&mut self) -> Result<Vec<ExperiencePlayerCount>, Error> {
        let url = append(
            self.base.as_str(),
            &["api", "v2.0", "dataquery", "playercounts"],
        )?;
        let request = self
            .minecraft
            .http
            .request(Method::GET, url.as_str())
            .build()?;
        let response = self
            .send("player_counts", request, crate::http::retry::Policy::Single)
            .await?;
        #[derive(Deserialize)]
        struct Envelope {
            result: Vec<Box<RawValue>>,
        }
        let entries = response.json::<Object<Envelope>>()?.0.result;
        Ok(entries
            .into_iter()
            .filter_map(|raw| {
                serde_json::from_str::<Object<ExperiencePlayerCount>>(raw.get())
                    .ok()
                    .map(|count| count.0)
                    .filter(|count| !count.experience_id.is_nil())
            })
            .collect())
    }

    /// Resolves one explicitly selected experience with a single possible mutation.
    /// The returned transport/destination comes only from this response, never a catalog card.
    /// Dropping a polled future may leave an uncertain remote result; the caller owns observation.
    ///
    /// # Errors
    /// Rejects nil IDs before authorization and malformed/invalid assignments or HTTP failures.
    pub async fn join_experience(&mut self, id: Uuid) -> Result<JoinAddress, Error> {
        if id.is_nil() {
            return Err(Error::Invalid("gatherings experience ID"));
        }
        let url = append(self.base.as_str(), &["api", "v2.0", "join", "experience"])?;
        let request = self
            .minecraft
            .http
            .post_json(url.as_str(), &serde_json::json!({"experienceId":id}))?;
        let response = self
            .send(
                "join_experience",
                request,
                crate::http::retry::Policy::Single,
            )
            .await?;
        #[derive(Deserialize)]
        struct Envelope {
            result: Object<JoinAddress>,
        }
        let address = response.json::<Object<Envelope>>()?.0.result.0;
        address.target()?;
        Ok(address)
    }

    /// Applies this operation's resend policy with the exact current Minecraft issuance.
    async fn send(
        &mut self,
        operation: &'static str,
        mut request: Request,
        policy: crate::http::retry::Policy,
    ) -> Result<Response, Error> {
        crate::http::call::run(async {
            let token = self
                .minecraft
                .authorize()
                .await
                .inspect_err(|error| record_failure(operation, "authorization", error))?;
            let authorization = token
                .header_value()
                .inspect_err(|error| record_failure(operation, "authorization", error))?;
            request.headers_mut().insert("authorization", authorization);
            request
                .headers_mut()
                .insert("accept", HeaderValue::from_static("application/json"));
            let response = self
                .minecraft
                .http
                .send_retrying_with_limit(request, policy, crate::http::SERVICE_RESPONSE_LIMIT)
                .await
                .inspect_err(|error| record_failure(operation, "request", error))?;
            if response.status == StatusCode::UNAUTHORIZED {
                self.minecraft.reject(&token);
            }
            if response.status != StatusCode::OK {
                response
                    .success()
                    .inspect_err(|error| record_failure(operation, "request", error))?;
                return Err(Error::Invalid("gatherings response status"));
            }
            Ok(response)
        })
        .await
    }
}

/// Emits only finite caller/phase labels and safe error scalars, preserving the original error.
fn record_failure(operation: &'static str, phase: &'static str, error: &Error) {
    let (class, http_status) = match error {
        Error::DeadlineExceeded => ("deadline_exceeded", None),
        Error::Shared(_) => ("shared_acquisition", None),
        Error::Http(source) => ("http", source.status().map(|status| status.as_u16())),
        Error::Status { status, .. } => ("status", Some(status.as_u16())),
        Error::AccountCreationRequired(_) => ("account_creation_required", None),
        Error::Invalid(_) => ("invalid", None),
        Error::UnsupportedNetworkProtocol => ("unsupported_network_protocol", None),
        Error::ResponseTooLarge => ("response_too_large", None),
        Error::TimeRange => ("time_range", None),
        Error::DeviceCodeExpired => ("device_code_expired", None),
        Error::AuthorizationDeclined => ("authorization_declined", None),
        Error::SignInRequired => ("sign_in_required", None),
    };
    tracing::warn!(
        operation,
        phase,
        class,
        http_status,
        "gatherings operation failed"
    );
}

#[cfg(test)]
mod tests;
