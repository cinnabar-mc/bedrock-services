//! Account-borrowed Realms browsing and caller-driven join resolution.
//!
//! Obtain a service view with [`crate::minecraft::Minecraft::realms`]. Each call
//! uses the caller's async runtime. Dropping a future cancels its HTTP operation;
//! the account's cached authorizations and completed negotiation remain reusable.

mod types;
mod version;

pub use types::{
    Join, JoinTarget, NetworkProtocol, PingResult, Player, Realm, RealmAddress, SessionRegion,
};
pub(crate) use version::State;

use crate::{
    http::{Http, Response},
    minecraft::Config,
    xbox,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU64, time::Duration};
use url::Url;

const RELYING_PARTY: &str = "https://pocket.realms.minecraft.net/";
const CLIENT_PLATFORM: &str = "Android";
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);

/// A redacted Realms request failure, preserving membership failures separately.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Discovery, authentication, HTTP or response decoding failed.
    #[error(transparent)]
    Service(#[from] crate::Error),
    /// The service returned HTTP 404 for the requested Realm or invitation.
    #[error("realm was not found")]
    NotFound,
    /// The service returned HTTP 403 for an operation requiring Realm membership.
    #[error("account cannot access this realm")]
    NotMember,
}

/// Borrows one account and its persistent negotiation state; it owns no runtime or tasks.
/// A service view cannot outlive or change its Minecraft account's device/version policy.
pub struct Realms<'a> {
    pub(crate) xbox: &'a mut xbox::Account,
    pub(crate) http: &'a mut Http,
    pub(crate) config: &'a Config,
    pub(crate) state: &'a mut State,
    pub(crate) base: Url,
}

impl Realms<'_> {
    /// Lists accessible Realms without accepting invitations or resolving addresses.
    pub async fn list(&mut self) -> Result<Vec<Realm>, Error> {
        #[derive(Deserialize)]
        struct Catalog {
            servers: Vec<Realm>,
        }
        let response = self
            .request(
                Method::GET,
                &["worlds"],
                None,
                crate::http::retry::Policy::Service,
            )
            .await?;
        success(&response)?;
        Ok(response.json::<Catalog>()?.servers)
    }

    /// Fetches details and player metadata for a positive Realm identifier.
    pub async fn details(&mut self, id: NonZeroU64) -> Result<Realm, Error> {
        let response = self
            .request(
                Method::GET,
                &["worlds", &id.to_string()],
                None,
                crate::http::retry::Policy::Service,
            )
            .await?;
        success(&response)?;
        let realm = response.json::<Realm>()?;
        if realm.id != id {
            return Err(crate::Error::Invalid("Realm detail identity").into());
        }
        Ok(realm)
    }

    /// Previews an opaque invitation code without accepting it or connecting.
    /// Link extraction belongs to the caller; URL paths are not accepted as codes.
    pub async fn preview_invite(&mut self, code: &str) -> Result<Realm, Error> {
        validate_code(code)?;
        let response = self
            .request(
                Method::GET,
                &["worlds", "v1", "link", code],
                None,
                crate::http::retry::Policy::Service,
            )
            .await?;
        success(&response)?;
        Ok(response.json()?)
    }

    /// Accepts an invitation explicitly; callers should first obtain user confirmation.
    /// This changes membership but does not resolve an address or connect to the Realm.
    pub async fn accept_invite(&mut self, code: &str) -> Result<Realm, Error> {
        validate_code(code)?;
        let response = self
            .request(
                Method::POST,
                &["invites", "v1", "link", "accept", code],
                None,
                crate::http::retry::Policy::Service,
            )
            .await?;
        success(&response)?;
        Ok(response.json()?)
    }

    /// Returns the nonnegative pending invitation count without echoing invalid body text.
    pub async fn pending_invites(&mut self) -> Result<u32, Error> {
        let response = self
            .request(
                Method::GET,
                &["invites", "count", "pending"],
                None,
                crate::http::retry::Policy::Service,
            )
            .await?;
        success(&response)?;
        std::str::from_utf8(&response.body)
            .ok()
            .and_then(|body| body.trim().parse().ok())
            .ok_or_else(|| crate::Error::Invalid("Realm pending invitation count").into())
    }

    /// Resolves one join attempt. The caller schedules `Pending` retries and owns its deadline.
    /// Empty ping results are sent as an empty array; successful addresses preserve IPv6 text.
    pub async fn join(&mut self, id: NonZeroU64, regions: &[PingResult]) -> Result<Join, Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct JoinRequest<'a> {
            join_intention: &'static str,
            ping_regions: &'a [PingResult],
        }
        let body = serde_json::to_vec(&JoinRequest {
            join_intention: "VANILLA",
            ping_regions: regions,
        })
        .map_err(|_| crate::Error::Invalid("Realm join request"))?;
        let response = self
            .request(
                Method::POST,
                &["worlds", &id.to_string(), "join"],
                Some(&body),
                crate::http::retry::Policy::Single,
            )
            .await?;
        if matches!(response.status.as_u16(), 277 | 503)
            && let Some(retry_after) = retry_after(&response)
        {
            return Ok(Join::Pending { retry_after });
        }
        success(&response)?;
        let address = response.json::<RealmAddress>()?;
        address.target()?;
        Ok(Join::Ready(address))
    }

    /// Shares one call budget across safe resends and version compatibility negotiation.
    async fn request(
        &mut self,
        method: Method,
        path: &[&str],
        body: Option<&[u8]>,
        policy: crate::http::retry::Policy,
    ) -> Result<Response, Error> {
        crate::http::call::run(async {
            let sent = self
                .state
                .accepted_version
                .as_deref()
                .unwrap_or(&self.config.game_version)
                .to_owned();
            let response = self.send(method.clone(), path, body, &sent, policy).await?;
            if !version::rejected(&response) || !self.state.may_search(self.http.now()) {
                return Ok(response);
            }
            for candidate in version::candidates(&self.config.game_version) {
                if candidate == sent {
                    continue;
                }
                let compatible = self
                    .send(
                        Method::GET,
                        &["mco", "client", "compatible"],
                        None,
                        &candidate,
                        crate::http::retry::Policy::Service,
                    )
                    .await;
                let Ok(compatible) = compatible else {
                    self.state.failed(self.http.now());
                    return Ok(response);
                };
                if compatible.status != StatusCode::OK {
                    self.state.failed(self.http.now());
                    return Ok(response);
                }
                if std::str::from_utf8(&compatible.body)
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("COMPATIBLE"))
                {
                    self.state.accepted(candidate.clone());
                    return self.send(method, path, body, &candidate, policy).await;
                }
            }
            self.state.failed(self.http.now());
            Ok(response)
        })
        .await
    }

    /// Builds one version-pinned request before execution and invalidates an unauthorized issuance.
    async fn send(
        &mut self,
        method: Method,
        path: &[&str],
        body: Option<&[u8]>,
        version: &str,
        policy: crate::http::retry::Policy,
    ) -> Result<Response, Error> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| crate::Error::Invalid("Realms service path"))?
            .pop_if_empty()
            .extend(path);
        let token = self.xbox.authorize(RELYING_PARTY).await?;
        let mut request = self
            .http
            .request(method, url.as_str())
            .header("authorization", token.header_value()?)
            .header("client-version", version)
            .header("x-clientplatform", CLIENT_PLATFORM)
            .header(
                "x-networkprotocolversion",
                self.config.network_protocol_version,
            );
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_owned());
        }
        let response = self
            .http
            .send_retrying(request.build().map_err(crate::Error::from)?, policy)
            .await?;
        if response.status == StatusCode::UNAUTHORIZED {
            self.xbox.reject(&token);
        }
        Ok(response)
    }
}

/// Requires one opaque invitation segment rather than interpreting arbitrary URLs or paths.
fn validate_code(code: &str) -> Result<(), Error> {
    if code.is_empty()
        || code.len() > 255
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(crate::Error::Invalid("Realm invitation code").into());
    }
    Ok(())
}

/// Maps access failures without retaining response text or unrelated server diagnostics.
fn success(response: &Response) -> Result<(), Error> {
    match response.status {
        StatusCode::FORBIDDEN => Err(Error::NotMember),
        StatusCode::NOT_FOUND => Err(Error::NotFound),
        _ => Ok(response.success()?),
    }
}

/// Parses integer Retry-After seconds; a present invalid value uses the bounded fallback.
fn retry_after(response: &Response) -> Option<Duration> {
    let value = response.headers.get("retry-after")?;
    let value = match value.to_str() {
        Ok(value) => value.trim(),
        Err(_) => return Some(DEFAULT_RETRY_AFTER),
    };
    if value.is_empty() {
        return None;
    }
    Some(
        value
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds <= (i64::MAX as u64) / 1_000_000_000)
            .map_or(DEFAULT_RETRY_AFTER, Duration::from_secs),
    )
}
