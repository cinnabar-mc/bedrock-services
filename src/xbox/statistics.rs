//! Explicit statistics batches using the existing account's signed Xbox service owner.

use super::{Account, social::validate_xuid};
use crate::Error;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, value::RawValue};
use std::borrow::Cow;
use url::Url;
use uuid::Uuid;

const ENDPOINT: &str = "https://userstats.xboxlive.com";
const USER_AGENT: &str = "XboxServicesAPI/2025.10.20251000.0";
/// Largest number of requested service configurations.
pub const MAX_CONFIGURATIONS: usize = 64;
/// Largest number of requested names per service configuration.
pub const MAX_STATISTICS: usize = 128;
const MAX_NAME_BYTES: usize = 256;

/// Title-owned selection; validation happens before acquisition or service I/O.
#[derive(Serialize)]
pub struct Selection {
    /// Non-nil service configuration owning the requested statistics.
    #[serde(rename = "scid")]
    pub service_config_id: Uuid,
    /// Explicit statistic names, retaining case and punctuation.
    #[serde(rename = "requestedstats")]
    pub names: Vec<String>,
}

/// One returned user's statistics. Missing users are not fabricated as empty successes.
#[derive(Deserialize)]
pub struct UserStatistics {
    /// Exact canonical Xbox identity, accepting a JSON integer or string.
    #[serde(deserialize_with = "xuid")]
    pub xuid: String,
    /// Service configurations present in the response.
    #[serde(default, rename = "scids", deserialize_with = "nullable_list")]
    pub configurations: Vec<ServiceStatistics>,
}

/// Statistics belonging to one service configuration, including unrequested future metadata.
#[derive(Deserialize)]
pub struct ServiceStatistics {
    /// Reported service configuration.
    #[serde(rename = "scid")]
    pub service_config_id: Uuid,
    /// Reported named values.
    #[serde(default, rename = "stats", deserialize_with = "nullable_list")]
    pub statistics: Vec<Statistic>,
}

/// A value retaining its original numeric digits rather than passing through a floating JSON tree.
#[derive(Deserialize)]
pub struct Statistic {
    /// Original statistic name.
    #[serde(default, rename = "statname")]
    pub name: String,
    /// Original service type; unknown types are retained.
    #[serde(default, rename = "type")]
    pub value_type: String,
    #[serde(default)]
    value: Option<Box<RawValue>>,
}

impl Statistic {
    /// Borrows the exact JSON value; absent/null values remain distinct from zero.
    pub fn raw_value(&self) -> Option<&str> {
        self.value.as_deref().map(RawValue::get)
    }

    /// Reads finite nonnegative numeric text without rounding its original digits.
    /// Unrecognized, missing, negative and overflowing values remain unavailable.
    pub fn non_negative_number(&self) -> Option<Cow<'_, str>> {
        let raw = self.raw_value()?.trim();
        let text = if raw.starts_with('"') {
            let decoded: String = serde_json::from_str(raw).ok()?;
            Cow::Owned(decoded.trim().to_owned())
        } else {
            Cow::Borrowed(raw)
        };
        let number: f64 = text.parse().ok()?;
        let negative = text.starts_with('-')
            && text
                .split(['e', 'E'])
                .next()?
                .bytes()
                .any(|digit| matches!(digit, b'1'..=b'9'));
        (number.is_finite() && number >= 0.0 && !negative).then_some(text)
    }
}

/// A complete batch response with malformed user rows counted separately.
pub struct Batch {
    /// Valid requested users in service order; missing users remain absent.
    pub users: Vec<UserStatistics>,
    /// Malformed rows omitted without losing valid neighbors.
    pub malformed_users: usize,
}

/// Borrows the account's proof, policy, HTTP client and exact-issuance cache.
pub struct Statistics<'a> {
    account: &'a mut Account,
    #[cfg(test)]
    fixture_base: Option<Url>,
}

impl Account {
    /// Borrows explicit statistics reads without acquiring credentials or starting tasks.
    pub fn statistics(&mut self) -> Statistics<'_> {
        Statistics {
            account: self,
            #[cfg(test)]
            fixture_base: None,
        }
    }
}

impl Statistics<'_> {
    /// Reads one bounded user/configuration batch; aggregation and retail policy belong to the caller.
    ///
    /// # Errors
    /// Rejects invalid/oversized selections before acquisition, malformed envelopes,
    /// unrequested response identities and redacted service/HTTP failures.
    pub async fn read(&mut self, users: &[&str], selections: &[Selection]) -> Result<Batch, Error> {
        crate::http::call::run(async {
            if users.is_empty()
                || users.len() > super::social::MAX_BATCH_USERS
                || selections.is_empty()
                || selections.len() > MAX_CONFIGURATIONS
            {
                return Err(Error::Invalid("statistics selection count"));
            }
            for user in users {
                validate_xuid(user)?;
            }
            for selection in selections {
                if selection.service_config_id.is_nil()
                    || selection.names.is_empty()
                    || selection.names.len() > MAX_STATISTICS
                    || selection.names.iter().any(|name| {
                        name.is_empty()
                            || name.len() > MAX_NAME_BYTES
                            || name.chars().any(char::is_control)
                    })
                {
                    return Err(Error::Invalid("statistics selection"));
                }
            }
            #[derive(Serialize)]
            struct Request<'a, 'b> {
                requestedusers: &'a [&'b str],
                requestedscids: &'a [Selection],
            }
            let mut body = serde_json::to_vec(&Request {
                requestedusers: users,
                requestedscids: selections,
            })
            .map_err(|_| Error::Invalid("statistics request"))?;
            if body.len() >= crate::http::RESPONSE_LIMIT {
                return Err(Error::Invalid("statistics request size"));
            }
            body.push(b'\n');
            let mut url =
                Url::parse(ENDPOINT).map_err(|_| Error::Invalid("statistics endpoint"))?;
            #[cfg(test)]
            if let Some(base) = &self.fixture_base {
                url = base.clone();
            }
            url.path_segments_mut()
                .map_err(|_| Error::Invalid("statistics path"))?
                .pop_if_empty()
                .push("batch");
            url.set_query(Some("operation=read"));
            let token = self.account.authorize_service(&url).await?;
            let mut request = self
                .account
                .http
                .request(Method::POST, url.as_str())
                .header("x-xbl-contract-version", "1")
                .header("accept-language", super::DEFAULT_LANGUAGE)
                .header("content-type", "application/json; charset=utf-8")
                .header("content-length", body.len())
                .body(body)
                .build()?;
            request.headers_mut().insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_static(USER_AGENT),
            );
            let response = self
                .account
                .send_service_with_limit(request, token, crate::http::SERVICE_RESPONSE_LIMIT)
                .await?;
            if response.status != StatusCode::OK {
                return Err(Error::Status {
                    status: response.status,
                    xerr: None,
                });
            }
            #[derive(Deserialize)]
            struct Envelope {
                users: Option<Vec<Box<RawValue>>>,
            }
            let rows = response
                .json::<Envelope>()?
                .users
                .ok_or(Error::Invalid("statistics users"))?;
            if rows.len() > super::social::MAX_BATCH_USERS {
                return Err(Error::Invalid("statistics response count"));
            }
            let mut batch = Batch {
                users: Vec::new(),
                malformed_users: 0,
            };
            for row in rows {
                match serde_json::from_str::<UserStatistics>(row.get()) {
                    Ok(user) => {
                        if !users.contains(&user.xuid.as_str()) {
                            return Err(Error::Invalid("unrequested statistics user"));
                        }
                        batch.users.push(user);
                    }
                    Err(_) => batch.malformed_users += 1,
                }
            }
            Ok(batch)
        })
        .await
    }
}

/// Accepts only an exact canonical unsigned Xbox identity, without floating conversion.
fn xuid<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = Value::deserialize(d)?;
    let value = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|value| value.to_string()))
        .ok_or_else(|| serde::de::Error::custom("statistics identity"))?;
    validate_xuid(&value).map_err(|_| serde::de::Error::custom("statistics identity"))?;
    Ok(value)
}

/// Accepts absent/null collections without fabricating any statistic rows.
fn nullable_list<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests;
