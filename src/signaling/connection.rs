use super::{Error, MAX_SERVICE_SECONDS};
use crate::minecraft::Authorization;
use reqwest::header::HeaderValue;
use std::{sync::Arc, time::Duration};
use url::Url;
use uuid::Uuid;

/// One validated messaging upgrade, tied to its exact service credential issuance.
/// It has no Debug or serialization implementation. Use promptly, reacquire on
/// reconnect, and follow no WebSocket redirects.
pub struct ConnectionRequest {
    pub(crate) url: Url,
    pub(crate) authorization: Arc<Authorization>,
    pub(crate) ping_interval: Duration,
}

impl ConnectionRequest {
    /// Returns the validated WSS destination, including its advertised path prefix.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Explicitly exposes the sensitive Authorization header for this upgrade only.
    pub fn authorization(&self) -> Result<HeaderValue, crate::Error> {
        self.authorization.header_value()
    }

    /// Returns the account identity used by the Player Messaging service.
    pub fn player_messaging_id(&self) -> Uuid {
        self.authorization.messaging_id()
    }

    /// Returns the service's application-ping interval; scheduling belongs to the caller.
    pub fn ping_interval(&self) -> Duration {
        self.ping_interval
    }
}

/// Accepts only a credential-free absolute WSS service destination.
pub(crate) fn websocket_url(value: &str) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error::Invalid("WebSocket destination"))?;
    if url.scheme() != "wss"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("WebSocket destination policy"));
    }
    Ok(url)
}

/// Converts the service's hours:minutes:seconds interval with checked arithmetic.
pub(crate) fn ping_interval(value: Option<&str>) -> Result<Duration, Error> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(Duration::from_secs(15));
    };
    let mut fields = value.split(':');
    let mut parts = [0_u64; 3];
    for part in &mut parts {
        *part = fields
            .next()
            .and_then(|field| field.parse().ok())
            .ok_or(Error::Invalid("ping interval"))?;
    }
    let [hours, minutes, seconds] = parts;
    let seconds = hours
        .checked_mul(3600)
        .and_then(|hours| {
            minutes
                .checked_mul(60)
                .and_then(|minutes| hours.checked_add(minutes))
        })
        .and_then(|total| total.checked_add(seconds))
        .filter(|seconds| *seconds != 0 && *seconds <= MAX_SERVICE_SECONDS)
        .filter(|_| fields.next().is_none())
        .ok_or(Error::Invalid("ping interval"))?;
    Ok(Duration::from_secs(seconds))
}
