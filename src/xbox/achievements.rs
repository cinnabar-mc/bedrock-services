//! Authenticated Xbox achievement reads with explicit bounded pagination.

use super::{Account, XBOX_RELYING_PARTY, social::validate_xuid};
use crate::Error;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use url::Url;

const ENDPOINT: &str = "https://achievements.xboxlive.com";
/// Largest encoded response body for one achievement page.
pub(crate) const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Largest retained page, independent of server behavior.
pub const MAX_PAGE_ITEMS: usize = 1024;
/// Largest number of explicit collection requests.
pub const MAX_PAGES: usize = 128;
/// Largest complete collection, after duplicate removal.
pub const MAX_ACHIEVEMENTS: usize = 65_536;
/// Largest cumulative response bytes across one collection.
pub const MAX_COLLECTION_BYTES: usize = 16 * crate::http::RESPONSE_LIMIT;
const MAX_CONTINUATION_BYTES: usize = 8192;

/// Localized definition and progress, retaining unknown progress/reward types.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Achievement {
    /// Achievement identity within its service configuration.
    pub id: String,
    /// Service configuration reported by the service.
    #[serde(default)]
    pub service_config_id: String,
    /// Localized display name.
    #[serde(default)]
    pub name: String,
    /// Localized description after unlocking.
    #[serde(default)]
    pub description: String,
    /// Localized description before unlocking.
    #[serde(default)]
    pub locked_description: String,
    /// Raw progress state, without treating unknown values as unlocked.
    pub progress_state: Option<String>,
    /// Raw progression, including original unlock timestamp and requirements.
    pub progression: Option<Value>,
    /// Reported artwork, never fetched with an Xbox credential by this API.
    #[serde(default, deserialize_with = "nullable_list")]
    pub media_assets: Vec<MediaAsset>,
    /// Reported rewards, without fabricated score defaults.
    #[serde(default, deserialize_with = "nullable_list")]
    pub rewards: Vec<Reward>,
}

/// Untrusted artwork metadata; download policy belongs to the consumer.
#[derive(Deserialize)]
pub struct MediaAsset {
    /// Localized asset name.
    #[serde(default)]
    pub name: String,
    /// Raw asset category, such as Icon.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// Reported location; this API does not follow it.
    #[serde(default)]
    pub url: String,
}

/// Raw reward data. Missing or malformed score text never becomes zero.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reward {
    /// Localized reward name.
    pub name: Option<String>,
    /// Localized reward description.
    pub description: Option<String>,
    /// Raw reward category, such as Gamerscore.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Value as reported by the service.
    pub value: Option<String>,
    /// Service-defined interpretation of the value.
    pub value_type: Option<String>,
    /// Optional reward artwork.
    pub media_asset: Option<MediaAsset>,
}

/// One account-bound page. Continuation is data, never a URL or a reset lifetime.
pub struct Page {
    /// Authenticated account whose progress was requested.
    pub owner_xuid: String,
    /// Valid entries in original service order.
    pub achievements: Vec<Achievement>,
    /// Malformed or missing-ID entries skipped without losing valid neighbors.
    pub malformed_items: usize,
    /// Original service continuation; empty means no remaining page.
    pub continuation: String,
    /// Optional service-reported total, distinct from the count actually returned.
    pub total_records: Option<u64>,
    bytes: usize,
}

/// A complete collection; HTTP/continuation/resource failures return no partial success.
pub struct Collection {
    /// Authenticated account whose progress was requested.
    pub owner_xuid: String,
    /// First occurrence of each configuration/achievement pair, in service order.
    pub achievements: Vec<Achievement>,
    /// Malformed or missing-ID entries omitted across all accepted pages.
    pub malformed_items: usize,
}

/// Borrows the existing proof, cache, policy and HTTP owner.
pub struct Achievements<'a> {
    account: &'a mut Account,
    #[cfg(test)]
    fixture_base: Option<Url>,
}

impl Account {
    /// Borrows one-shot achievement reads without starting pagination or acquisition.
    pub fn achievements(&mut self) -> Achievements<'_> {
        Achievements {
            account: self,
            #[cfg(test)]
            fixture_base: None,
        }
    }
}

impl Achievements<'_> {
    /// Reads one title's authenticated progress page using an original service continuation.
    ///
    /// # Errors
    /// Rejects invalid title/continuation, mismatched account issuances, missing collections,
    /// resource bounds and redacted service failures. No retry or mutation occurs.
    pub async fn page(&mut self, title: u32, continuation: &str) -> Result<Page, Error> {
        if title == 0
            || continuation.len() > MAX_CONTINUATION_BYTES
            || continuation.chars().any(char::is_control)
        {
            return Err(Error::Invalid("achievement selection"));
        }
        let identity = self.account.authorize(XBOX_RELYING_PARTY).await?;
        validate_xuid(identity.xuid())?;
        let mut url = Url::parse(ENDPOINT).map_err(|_| Error::Invalid("achievement endpoint"))?;
        #[cfg(test)]
        if let Some(base) = &self.fixture_base {
            url = base.clone();
        }
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("achievement path"))?
            .pop_if_empty()
            .extend([
                "users",
                &format!("xuid({})", identity.xuid()),
                "achievements",
            ]);
        url.query_pairs_mut()
            .append_pair("titleId", &title.to_string())
            .append_pair("maxItems", &MAX_PAGE_ITEMS.to_string());
        if !continuation.is_empty() {
            url.query_pairs_mut()
                .append_pair("continuationToken", continuation);
        }
        let token = self.account.authorize_service(&url).await?;
        if token.xuid() != identity.xuid() {
            return Err(Error::Invalid("achievement account identity"));
        }
        let request = self
            .account
            .http
            .request(Method::GET, url.as_str())
            .header("x-xbl-contract-version", "2")
            .header("accept", "application/json")
            .header("accept-language", super::DEFAULT_LANGUAGE)
            .build()?;
        let response = self
            .account
            .send_service_with_limit(request, token, MAX_PAGE_BYTES)
            .await?;
        if response.status != StatusCode::OK {
            return Err(Error::Status {
                status: response.status,
                xerr: None,
            });
        }
        let bytes = response.body.len();
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Paging {
            #[serde(default)]
            continuation_token: Option<String>,
            total_records: Option<u64>,
        }
        #[derive(Deserialize)]
        struct Envelope {
            achievements: Option<Vec<Value>>,
            #[serde(default, rename = "pagingInfo")]
            paging: Option<Paging>,
        }
        let envelope: Envelope = response.json()?;
        let rows = envelope
            .achievements
            .ok_or(Error::Invalid("achievement collection"))?;
        if rows.len() > MAX_PAGE_ITEMS {
            return Err(Error::Invalid("achievement page count"));
        }
        let paging = envelope.paging.unwrap_or_default();
        let continuation = paging.continuation_token.unwrap_or_default();
        if continuation.len() > MAX_CONTINUATION_BYTES || continuation.chars().any(char::is_control)
        {
            return Err(Error::Invalid("achievement continuation"));
        }
        let mut page = Page {
            owner_xuid: identity.xuid().to_owned(),
            achievements: Vec::new(),
            malformed_items: 0,
            continuation,
            total_records: paging.total_records,
            bytes,
        };
        for row in rows {
            match serde_json::from_value::<Achievement>(row) {
                Ok(value) if !value.id.is_empty() => page.achievements.push(value),
                _ => page.malformed_items += 1,
            }
        }
        Ok(page)
    }

    /// Reads a complete bounded title collection on the caller's runtime, without hidden retry.
    /// Cancellation drops only this read; acquired account credentials remain owned.
    ///
    /// # Errors
    /// Returns page failures, repeated continuation, changed account identity, or collection bounds.
    pub async fn all(&mut self, title: u32) -> Result<Collection, Error> {
        let mut result = Collection {
            owner_xuid: String::new(),
            achievements: Vec::new(),
            malformed_items: 0,
        };
        let mut continuation = String::new();
        let mut seen_tokens = HashSet::new();
        let mut seen = HashSet::new();
        let mut bytes = 0usize;
        for _ in 0..MAX_PAGES {
            let page = self.page(title, &continuation).await?;
            bytes = bytes
                .checked_add(page.bytes)
                .filter(|bytes| *bytes <= MAX_COLLECTION_BYTES)
                .ok_or(Error::Invalid("achievement collection bytes"))?;
            if result.owner_xuid.is_empty() {
                result.owner_xuid = page.owner_xuid;
            } else if result.owner_xuid != page.owner_xuid {
                return Err(Error::Invalid("achievement collection identity"));
            }
            result.malformed_items += page.malformed_items;
            for value in page.achievements {
                if seen.insert((value.service_config_id.clone(), value.id.clone())) {
                    if result.achievements.len() == MAX_ACHIEVEMENTS {
                        return Err(Error::Invalid("achievement collection count"));
                    }
                    result.achievements.push(value);
                }
            }
            continuation = page.continuation;
            if continuation.is_empty() {
                return Ok(result);
            }
            if !seen_tokens.insert(continuation.clone()) {
                return Err(Error::Invalid("achievement continuation did not advance"));
            }
        }
        Err(Error::Invalid("achievement page count"))
    }
}

/// Treats absent/null optional lists as empty without inferring a reward value.
fn nullable_list<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests;
