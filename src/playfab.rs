//! PlayFab credentials acquired through the account's title-scoped Xbox policy.

use crate::{Error, http::Http, xbox::Account};
use serde::Deserialize;
use std::time::{Duration, SystemTime};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

const REUSE: Duration = Duration::from_secs(24 * 60 * 60 - 15 * 60);

/// One PlayFab login; secret ticket and entity credential have no Debug implementation.
pub struct Session {
    pub(crate) ticket: Zeroizing<String>,
    player_id: String,
    entity: Entity,
    reusable_until: SystemTime,
}

/// The identity and credential of a PlayFab title-player account.
pub struct Entity {
    id: String,
    kind: String,
    token: Zeroizing<String>,
    expires: OffsetDateTime,
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
    let url = login_url(title)?;
    #[cfg(test)]
    let url = match &http.endpoints.playfab {
        Some(url) => Url::parse(url).unwrap(),
        None => url,
    };
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
    let expires = OffsetDateTime::parse(&login.entity_token.token_expiration, &Rfc3339)
        .map_err(|_| Error::Invalid("PlayFab entity expiry"))?;
    if login.session_ticket.is_empty()
        || login.player_id.is_empty()
        || login.entity_token.entity_token.is_empty()
        || login.entity_token.entity.id.is_empty()
        || login.entity_token.entity.kind != "title_player_account"
        || expires <= OffsetDateTime::from(http.now())
    {
        return Err(Error::Invalid("PlayFab login credential"));
    }
    Ok(Session {
        ticket: Zeroizing::new(login.session_ticket),
        player_id: login.player_id,
        entity: Entity {
            id: login.entity_token.entity.id,
            kind: login.entity_token.entity.kind,
            token: Zeroizing::new(login.entity_token.entity_token),
            expires,
        },
        reusable_until: http.now().checked_add(REUSE).ok_or(Error::TimeRange)?,
    })
}
