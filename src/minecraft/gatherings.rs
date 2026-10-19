//! Account-borrowed discovery, population snapshots and explicit experience joins.
//!
//! Catalog metadata is not connection authority. Listing never joins or fetches artwork.
//! Callers own deadlines, polling and possible-write observation; joining is never retried.

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
        self.discover().await?;
        let uri = self
            .gatherings_environment
            .as_ref()
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
        let response = self.send(request).await?;
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
        let response = self.send(request).await?;
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
        let response = self.send(request).await?;
        #[derive(Deserialize)]
        struct Envelope {
            result: Object<JoinAddress>,
        }
        let address = response.json::<Object<Envelope>>()?.0.result.0;
        address.validate()?;
        Ok(address)
    }

    /// Sends once with the exact current Minecraft issuance; rejection cannot evict a replacement.
    async fn send(&mut self, mut request: Request) -> Result<Response, Error> {
        let token = self.minecraft.authorize().await?;
        request
            .headers_mut()
            .insert("authorization", token.header_value()?);
        request
            .headers_mut()
            .insert("accept", HeaderValue::from_static("application/json"));
        let response = self
            .minecraft
            .http
            .send_with_limit(request, crate::http::SERVICE_RESPONSE_LIMIT)
            .await?;
        if response.status == StatusCode::UNAUTHORIZED {
            self.minecraft.reject(&token);
        }
        if response.status != StatusCode::OK {
            response.success()?;
            return Err(Error::Invalid("gatherings response status"));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
