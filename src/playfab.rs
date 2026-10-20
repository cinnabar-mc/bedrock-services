//! PlayFab credentials acquired through the account's title-scoped Xbox policy.

use crate::{Error, http::Http, xbox::Account};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

const REUSE: Duration = Duration::from_secs(24 * 60 * 60 - 15 * 60);

pub(crate) mod checkpoint;

/// One PlayFab login; secret ticket and entity credential have no Debug implementation.
pub struct Session {
    pub(crate) ticket: Zeroizing<String>,
    player_id: String,
    pub(crate) entity: Arc<Entity>,
    reusable_until: SystemTime,
}

/// The identity and credential of a PlayFab title-player account.
pub struct Entity {
    id: String,
    kind: String,
    token: Zeroizing<String>,
    expires: OffsetDateTime,
}

/// Player identity used by a concrete PlayFab service.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EntityKind {
    /// Player identity scoped to the discovered game title.
    TitlePlayerAccount,
    /// Player identity shared across the publisher's titles.
    MasterPlayerAccount,
}

impl EntityKind {
    /// Returns the PlayFab entity type used in exchange requests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TitlePlayerAccount => "title_player_account",
            Self::MasterPlayerAccount => "master_player_account",
        }
    }
}

impl Session {
    /// Returns the identity shared across the publisher's titles.
    pub fn player_id(&self) -> &str {
        &self.player_id
    }

    /// Borrows the title-player entity issued by this login.
    pub fn entity(&self) -> &Entity {
        &self.entity
    }

    /// Reuses the login for 24 hours less its refresh margin, using caller time.
    pub(crate) fn reusable(&self, now: SystemTime) -> bool {
        now < self.reusable_until
    }
}

impl Entity {
    /// Returns the title-player entity identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the entity category supplied by PlayFab.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Reports whether the credential has reached its refresh margin.
    pub fn valid(&self, now: SystemTime) -> bool {
        OffsetDateTime::from(now) < self.expires - time::Duration::minutes(15)
    }

    /// Allows exchange during the renewal margin, but never after hard expiry.
    pub(crate) fn unexpired(&self, now: SystemTime) -> bool {
        OffsetDateTime::from(now) < self.expires
    }

    /// Returns the sensitive credential for a concrete PlayFab service request.
    pub fn header_value(&self) -> Result<reqwest::header::HeaderValue, Error> {
        let mut header = reqwest::header::HeaderValue::from_str(&self.token)
            .map_err(|_| Error::Invalid("PlayFab entity header"))?;
        header.set_sensitive(true);
        Ok(header)
    }
}

#[derive(Deserialize)]
struct ResultBody {
    data: Login,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Login {
    session_ticket: String,
    #[serde(rename = "PlayFabId")]
    player_id: String,
    entity_token: EntityResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EntityResponse {
    entity_token: String,
    token_expiration: String,
    entity: EntityKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EntityKey {
    id: String,
    #[serde(rename = "Type")]
    kind: String,
}

impl EntityResponse {
    /// Parses credential metadata before it can enter a reusable account cache.
    fn into_entity(self, now: SystemTime) -> Result<Entity, Error> {
        let expires = OffsetDateTime::parse(&self.token_expiration, &Rfc3339)
            .map_err(|_| Error::Invalid("PlayFab entity expiry"))?;
        if self.entity_token.is_empty()
            || self.entity.id.is_empty()
            || self.entity.kind.is_empty()
            || expires <= OffsetDateTime::from(now)
        {
            return Err(Error::Invalid("PlayFab entity credential"));
        }
        Ok(Entity {
            id: self.entity.id,
            kind: self.entity.kind,
            token: Zeroizing::new(self.entity_token),
            expires,
        })
    }
}

/// Derives the title host from validated discovery data rather than a second title table.
pub(crate) fn login_url(title: &str) -> Result<Url, Error> {
    if title.is_empty() || title.len() > 16 || !title.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid("PlayFab title ID"));
    }
    Url::parse(&format!(
        "https://{}.playfabapi.com/Client/LoginWithXbox",
        title.to_ascii_lowercase()
    ))
    .map_err(|_| Error::Invalid("PlayFab login URL"))
}

/// Sends the Xbox credential in the login body; no generic Xbox HTTP middleware is involved.
pub(crate) async fn login(
    http: &mut Http,
    xbox: &mut Account,
    title: &str,
) -> Result<Session, Error> {
    let url = login_endpoint(http, title)?;
    let authorization = xbox.authorize_service(&url).await?;
    let header = authorization.header_value()?;
    let body = serde_json::json!({"TitleId": title, "CreateAccount": true,
        "XboxToken": header.to_str().map_err(|_| Error::Invalid("Xbox login credential"))?});
    let mut request = http.post_json(url.as_str(), &body)?;
    request.headers_mut().insert(
        "accept-language",
        reqwest::header::HeaderValue::from_static("en-US, en"),
    );
    let response = http.send(request).await?;
    if response.status == reqwest::StatusCode::UNAUTHORIZED {
        xbox.reject(&authorization);
    }
    response.success()?;
    let login = response.json::<ResultBody>()?.data;
    let entity = login.entity_token.into_entity(http.now())?;
    if login.session_ticket.is_empty()
        || login.player_id.is_empty()
        || entity.kind != EntityKind::TitlePlayerAccount.as_str()
    {
        return Err(Error::Invalid("PlayFab login credential"));
    }
    Ok(Session {
        ticket: Zeroizing::new(login.session_ticket),
        player_id: login.player_id,
        entity: Arc::new(entity),
        reusable_until: http.now().checked_add(REUSE).ok_or(Error::TimeRange)?,
    })
}

/// Resolves the validated title host, with a loopback override confined to tests.
fn login_endpoint(_http: &Http, title: &str) -> Result<Url, Error> {
    let url = login_url(title)?;
    #[cfg(test)]
    if let Some(url) = &_http.endpoints.playfab {
        return Url::parse(url).map_err(|_| Error::Invalid("PlayFab fixture URL"));
    }
    Ok(url)
}

/// Exchanges one retained credential for exactly the requested player identity.
pub(crate) async fn exchange(
    http: &mut Http,
    title: &str,
    source: &Entity,
    kind: EntityKind,
    id: &str,
) -> Result<Entity, Error> {
    let mut url = login_endpoint(http, title)?;
    url.set_path("/Authentication/GetEntityToken");
    let body = serde_json::json!({"Entity":{"Id":id,"Type":kind.as_str()}});
    let mut request = http.post_json(url.as_str(), &body)?;
    request
        .headers_mut()
        .insert("x-entitytoken", source.header_value()?);
    let response = http.send(request).await?;
    response.success()?;
    #[derive(Deserialize)]
    struct ResultBody {
        data: EntityResponse,
    }
    let entity = response
        .json::<ResultBody>()?
        .data
        .into_entity(http.now())?;
    if entity.id != id || entity.kind != kind.as_str() || !entity.valid(http.now()) {
        return Err(Error::Invalid("PlayFab exchanged identity or expiry"));
    }
    Ok(entity)
}
