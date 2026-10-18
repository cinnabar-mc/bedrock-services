//! Account-borrowed PeopleHub, Presence and multiplayer activity reads.
//!
//! Calls run once on the caller's async runtime. There is no poller, subscription,
//! background refresh or inferred permission to join a reported session.

mod types;

pub use types::{
    Activity, ActivityInfo, DevicePresence, LastSeen, PeopleList, Presence, ProfileDetail,
    SessionReference, TitlePresence, User, UserPresence,
};

use super::{Account, DEFAULT_LANGUAGE, XBOX_RELYING_PARTY};
use crate::{Error, http::Response};
use reqwest::{Method, StatusCode, header::HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

const DECORATIONS: &str = "bio,detail,multiplayerSummary,preferredColor,presenceDetail";

/// Largest explicit user batch accepted by this SDK, matching the Presence query limit.
pub const MAX_BATCH_USERS: usize = 1100;

/// Borrows one Xbox account without owning a second proof, client or credential cache.
pub struct Social<'a> {
    account: &'a mut Account,
    language: HeaderValue,
    #[cfg(test)]
    fixture_base: Option<Url>,
}

impl Account {
    /// Borrows concrete social read services, retaining this account's acquisition state.
    pub fn social(&mut self) -> Social<'_> {
        Social {
            account: self,
            language: HeaderValue::from_static(DEFAULT_LANGUAGE),
            #[cfg(test)]
            fixture_base: None,
        }
    }
}

impl Social<'_> {
    /// Sets preferred language tags ahead of the service's English fallbacks.
    /// Returns a redacted error for an empty, oversized or invalid HTTP header value.
    pub fn with_language(mut self, language: &str) -> Result<Self, Error> {
        if language.is_empty() || language.len() > 1024 {
            return Err(Error::Invalid("social language"));
        }
        self.language = HeaderValue::from_str(&format!("{language}, {DEFAULT_LANGUAGE}"))
            .map_err(|_| Error::Invalid("social language"))?;
        Ok(self)
    }

    /// Reads a friend/follower list, with optional profile and presence decorations.
    /// Basic rows retain relationship identity without claiming missing presence is offline.
    pub async fn people(
        &mut self,
        list: PeopleList,
        detail: ProfileDetail,
    ) -> Result<Vec<User>, Error> {
        self.users(list.selector(), detail, None).await
    }

    /// Reads one decorated profile, requiring a response for the requested numeric XUID.
    pub async fn profile(&mut self, xuid: &str) -> Result<User, Error> {
        validate_xuid(xuid)?;
        let selector = format!("xuids({xuid})");
        self.users(&selector, ProfileDetail::Full, None)
            .await?
            .into_iter()
            .find(|user| user.xuid == xuid)
            .ok_or(Error::Invalid("missing requested Xbox profile"))
    }

    /// Reads the signed-in profile without asking the caller to repeat its XUID.
    pub async fn current_profile(&mut self) -> Result<User, Error> {
        let token = self.account.authorize(XBOX_RELYING_PARTY).await?;
        self.profile(token.xuid()).await
    }

    /// Reads decorated profiles in one bounded batch. Missing/private profiles may be omitted.
    /// Empty input returns an empty list without issuing an account or service request.
    pub async fn profiles(&mut self, xuids: &[&str]) -> Result<Vec<User>, Error> {
        validate_batch(xuids)?;
        if xuids.is_empty() {
            return Ok(Vec::new());
        }
        let users = self
            .users("batch", ProfileDetail::Full, Some(json!({"xuids": xuids})))
            .await?;
        if users
            .iter()
            .any(|user| !user.xuid.is_empty() && !xuids.contains(&user.xuid.as_str()))
        {
            return Err(Error::Invalid("unrequested Xbox profile"));
        }
        Ok(users)
    }

    /// Reads all reported devices and titles for the signed-in account.
    pub async fn current_presence(&mut self) -> Result<Presence, Error> {
        let token = self.account.authorize(XBOX_RELYING_PARTY).await?;
        validate_xuid(token.xuid())?;
        let result = self.read_presence("me").await?;
        if result.xuid != token.xuid() {
            return Err(Error::Invalid("Xbox presence identity"));
        }
        Ok(result)
    }

    /// Reads all reported devices and titles for one numeric XUID.
    pub async fn presence(&mut self, xuid: &str) -> Result<Presence, Error> {
        validate_xuid(xuid)?;
        let result = self.read_presence(&format!("xuid({xuid})")).await?;
        if result.xuid != xuid {
            return Err(Error::Invalid("Xbox presence identity"));
        }
        Ok(result)
    }

    /// Reads full presence trees for a bounded set of users without device/title filtering.
    pub async fn presences(&mut self, xuids: &[&str]) -> Result<Vec<Presence>, Error> {
        validate_batch(xuids)?;
        if xuids.is_empty() {
            return Ok(Vec::new());
        }
        let url = self.destination(Service::Presence, &["users", "batch"])?;
        let response = self
            .send(
                Service::Presence,
                url,
                Some(json!({"users": xuids, "level": "all"})),
            )
            .await?;
        let presences: Vec<Presence> = response
            .json::<Option<Vec<Presence>>>()?
            .unwrap_or_default();
        if presences
            .iter()
            .any(|presence| !xuids.contains(&presence.xuid.as_str()))
        {
            return Err(Error::Invalid("unrequested Xbox presence"));
        }
        Ok(presences)
    }

    /// Reads multiplayer activity handles for a service configuration.
    /// Empty users query the signed-in account's followed social group; explicit users
    /// are sent alone. Returned restrictions and custom metadata are not join approval.
    pub async fn activities(
        &mut self,
        service_config: uuid::Uuid,
        xuids: &[&str],
    ) -> Result<Vec<Activity>, Error> {
        if service_config.is_nil() {
            return Err(Error::Invalid("activity service configuration"));
        }
        validate_batch(xuids)?;
        let owners = if xuids.is_empty() {
            let token = self.account.authorize(XBOX_RELYING_PARTY).await?;
            validate_xuid(token.xuid())?;
            json!({"people": {"moniker": "people", "monikerXuid": token.xuid()}})
        } else {
            json!({"xuids": xuids})
        };
        let mut url = self.destination(Service::Activities, &["handles", "query"])?;
        url.set_query(Some("include=relatedInfo,customProperties"));
        let response = self
            .send(
                Service::Activities,
                url,
                Some(json!({"type": "activity", "scid": service_config, "owners": owners})),
            )
            .await?;
        #[derive(Deserialize)]
        struct Results {
            #[serde(default, deserialize_with = "types::nullable_list")]
            results: Vec<Activity>,
        }
        Ok(response.json::<Results>()?.results)
    }

    /// Builds the exact PeopleHub selector and optional decoration path.
    async fn users(
        &mut self,
        selector: &str,
        detail: ProfileDetail,
        body: Option<Value>,
    ) -> Result<Vec<User>, Error> {
        let mut path = vec!["users", "me", "people", selector];
        if matches!(detail, ProfileDetail::Full) {
            path.extend(["decoration", DECORATIONS]);
        }
        let url = self.destination(Service::People, &path)?;
        let response = self.send(Service::People, url, body).await?;
        #[derive(Deserialize)]
        struct People {
            #[serde(default, deserialize_with = "types::nullable_list")]
            people: Vec<User>,
        }
        Ok(response.json::<People>()?.people)
    }

    /// Reads a single presence tree with full device/title depth.
    async fn read_presence(&mut self, selector: &str) -> Result<Presence, Error> {
        let mut url = self.destination(Service::Presence, &["users", selector])?;
        url.query_pairs_mut().append_pair("level", "all");
        self.send(Service::Presence, url, None).await?.json()
    }

    /// Resolves one of the fixed concrete service destinations and escaped path segments.
    fn destination(&self, service: Service, path: &[&str]) -> Result<Url, Error> {
        let mut url = Url::parse(service.base()).map_err(|_| Error::Invalid("social endpoint"))?;
        #[cfg(test)]
        if let Some(base) = &self.fixture_base {
            url = base.clone();
        }
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("social endpoint path"))?
            .pop_if_empty()
            .extend(path);
        Ok(url)
    }

    /// Signs one concrete read request only after its policy-specific headers are materialized.
    async fn send(
        &mut self,
        service: Service,
        url: Url,
        body: Option<Value>,
    ) -> Result<Response, Error> {
        let token = self.account.authorize_service(&url).await?;
        let mut request = self
            .account
            .http
            .request(
                if body.is_some() {
                    Method::POST
                } else {
                    Method::GET
                },
                url.as_str(),
            )
            .header("x-xbl-contract-version", service.contract());
        match service {
            Service::People => {
                request = request
                    .header("accept", "application/json")
                    .header("accept-language", self.language.clone());
            }
            Service::Presence => {
                request = request
                    .header("cache-control", "no-cache")
                    .header("content-type", "application/json")
                    .header("accept-language", self.language.clone());
            }
            Service::Activities => {}
        }
        if let Some(body) = body {
            let mut bytes =
                serde_json::to_vec(&body).map_err(|_| Error::Invalid("social request"))?;
            bytes.push(b'\n');
            request = request
                .header("content-type", "application/json")
                .header("content-length", bytes.len())
                .body(bytes);
        }
        let request = request.build()?;
        let response = self.account.send_service(request, token).await?;
        if response.status != StatusCode::CREATED || matches!(service, Service::People) {
            response.success()?;
        }
        Ok(response)
    }
}

#[derive(Clone, Copy)]
enum Service {
    People,
    Presence,
    Activities,
}

impl Service {
    /// Keeps the service destinations in one exhaustive owner.
    fn base(self) -> &'static str {
        match self {
            Self::People => "https://peoplehub.xboxlive.com",
            Self::Presence => super::presence::ENDPOINT,
            Self::Activities => super::mpsd::ENDPOINT,
        }
    }

    /// Selects the inspected contract for each concrete API, including undecorated lists.
    fn contract(self) -> &'static str {
        match self {
            Self::People => "7",
            Self::Presence => super::presence::CONTRACT,
            Self::Activities => super::mpsd::CONTRACT,
        }
    }
}

/// Accepts only bounded decimal Xbox identifiers before constructing a service path or body.
pub(crate) fn validate_xuid(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || !value.parse::<u64>().is_ok_and(|value| value != 0)
    {
        return Err(Error::Invalid("Xbox user identifier"));
    }
    Ok(())
}

/// Bounds explicit user batches before JSON allocation or account acquisition.
fn validate_batch(values: &[&str]) -> Result<(), Error> {
    if values.len() > MAX_BATCH_USERS {
        return Err(Error::Invalid("social user batch size"));
    }
    for value in values {
        validate_xuid(value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
