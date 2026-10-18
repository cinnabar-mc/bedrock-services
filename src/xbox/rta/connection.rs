//! Account-borrowed protected upgrade acquisition, separate from pure subscription state.

use super::state::Scope;
use super::{Connection, Epoch, Error, Event, Generation};
use crate::xbox::{Account, Authorization, XBOX_RELYING_PARTY};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Method, header::HeaderMap};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

const ENDPOINT: &str = "https://rta.xboxlive.com/connect";
const SUBPROTOCOL: &str = "rta.xboxlive.com.V2";

/// One protected upgrade tied to an exact XSTS issuance and caller account generation.
/// No Debug or serialization: headers contain credentials and the upgrade destination is private.
pub struct ConnectionRequest {
    url: Url,
    headers: HeaderMap,
    authorization: Arc<Authorization>,
    scope: Scope,
    used: bool,
}

impl Account {
    /// Acquires and signs one fixed-service RTA upgrade without opening a socket.
    /// Supply the complete final WebSocket headers, including the transport's generated key.
    /// The caller must transmit the returned headers unchanged over verified TLS, validate
    /// the upgrade response/subprotocol and follow no redirects. Reacquire for each socket.
    ///
    /// # Errors
    /// Rejects invalid upgrade fields before authentication, or returns redacted acquisition errors.
    pub async fn rta_connection(
        &mut self,
        generation: Generation,
        upgrade_headers: HeaderMap,
    ) -> Result<ConnectionRequest, Error> {
        validate_upgrade(&upgrade_headers)?;
        let url = Url::parse(ENDPOINT).map_err(|_| Error::Invalid("upgrade endpoint"))?;
        let identity = self.authorize(XBOX_RELYING_PARTY).await?;
        super::super::social::validate_xuid(identity.xuid())?;
        let authorization = self.authorize_service(&url).await?;
        if !authorization.xuid().is_empty() && identity.xuid() != authorization.xuid() {
            return Err(Error::WrongAccount);
        }
        let (party, policy) = self
            .service_policy(&url)
            .ok_or(Error::Invalid("upgrade policy"))?;
        if party != authorization.relying_party() {
            return Err(Error::Invalid("upgrade relying party"));
        }
        let mut request = self
            .http
            .request(Method::GET, ENDPOINT)
            .headers(upgrade_headers)
            .header("authorization", authorization.header_value()?)
            .build()
            .map_err(crate::Error::from)?;
        self.http.prepare_signature(&mut request)?;
        policy.sign(&mut request, &self.key, self.http.now())?;
        bounded_headers(request.headers())?;
        let mut url = url;
        url.set_scheme("wss")
            .map_err(|_| Error::Invalid("upgrade endpoint"))?;
        Ok(ConnectionRequest {
            url,
            headers: request.headers().clone(),
            authorization,
            scope: Scope {
                xuid: identity.xuid().into(),
                proof: *self.key.verifying_key(),
                generation,
                epoch: Epoch(Uuid::new_v4()),
            },
            used: false,
        })
    }

    /// Invalidates only this exact issuance after an explicit rejected upgrade.
    /// Wrong-account and delayed failures cannot evict a replacement credential.
    pub fn reject_rta(&mut self, request: &ConnectionRequest) -> bool {
        request.scope.proof == *self.key.verifying_key() && self.reject(&request.authorization)
    }
}

impl ConnectionRequest {
    /// Explicitly exposes the fixed protected WSS destination for this upgrade only.
    pub fn url(&self) -> &Url {
        &self.url
    }
    /// Explicitly exposes all signed final upgrade headers; do not log or mutate them.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    /// Returns the required negotiated WebSocket subprotocol.
    pub fn subprotocol(&self) -> &'static str {
        SUBPROTOCOL
    }
    /// Identifies the socket whose complete incoming/outgoing messages the state may accept.
    pub fn epoch(&self) -> Epoch {
        self.scope.epoch
    }

    /// Starts one pure owner after this exact protected upgrade succeeds.
    /// Keep this request for exact-issuance rejection; it cannot start another owner.
    pub fn start(&mut self) -> Result<Connection, Error> {
        if self.used {
            return Err(Error::State);
        }
        self.used = true;
        Ok(Connection::new(self.scope.clone()))
    }
}

impl Connection {
    /// Rebinds to one freshly acquired same-account socket and fails old pending requests.
    /// First close the old socket and discard its queued frames/events. Desired subscription
    /// handles survive; call resubscribe explicitly for each returned subscriptions() entry,
    /// apply new initial snapshots, then explicitly rebind/refresh affected MPSD sessions.
    pub fn reconnect(&mut self, request: &mut ConnectionRequest) -> Result<Vec<Event>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if !self.scope.same_account(&request.scope) {
            return Err(Error::WrongAccount);
        }
        if request.used || self.scope.epoch == request.scope.epoch {
            return Err(Error::State);
        }
        let events = self.disconnect();
        self.scope = request.scope.clone();
        self.connected = true;
        request.used = true;
        Ok(events)
    }
}

/// Validates final mandatory upgrade fields before any account acquisition or signing.
fn validate_upgrade(headers: &HeaderMap) -> Result<(), Error> {
    bounded_headers(headers)?;
    let endpoint = Url::parse(ENDPOINT).map_err(|_| Error::Invalid("upgrade endpoint"))?;
    let authority = &endpoint[url::Position::BeforeHost..url::Position::AfterPort];
    for (name, expected) in [
        ("host", authority),
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-protocol", SUBPROTOCOL),
    ] {
        if headers.get_all(name).iter().count() != 1
            || !headers.get(name).is_some_and(|v| {
                if name == "sec-websocket-protocol" {
                    v.as_bytes() == expected.as_bytes()
                } else {
                    v.as_bytes().eq_ignore_ascii_case(expected.as_bytes())
                }
            })
        {
            return Err(Error::Invalid("upgrade headers"));
        }
    }
    let key = headers
        .get("sec-websocket-key")
        .ok_or(Error::Invalid("upgrade key"))?;
    if headers.get_all("sec-websocket-key").iter().count() != 1
        || !STANDARD.decode(key.as_bytes()).is_ok_and(|bytes| {
            bytes.len() == 16 && STANDARD.encode(bytes).as_bytes() == key.as_bytes()
        })
    {
        return Err(Error::Invalid("upgrade key"));
    }
    if headers.contains_key("authorization") || headers.contains_key("signature") {
        return Err(Error::Invalid("preauthenticated upgrade"));
    }
    if headers.contains_key("transfer-encoding")
        || headers
            .get_all("content-length")
            .iter()
            .any(|value| value.as_bytes() != b"0")
    {
        return Err(Error::Invalid("upgrade body framing"));
    }
    Ok(())
}

/// Bounds caller upgrade metadata and the complete credential-bearing signed result.
fn bounded_headers(headers: &HeaderMap) -> Result<(), Error> {
    if headers.len() > 64
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err(Error::Limit);
    }
    Ok(())
}

#[cfg(test)]
#[path = "connection_tests.rs"]
mod tests;
