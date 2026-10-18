//! Proof-key-bound Xbox accounts and immutable per-relying-party authorizations.

use crate::{Error, http::Http, nsal::TitleData, oauth::Credentials, signature::SignaturePolicy};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use rand::rngs::SysRng;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

pub(crate) const XBOX_RELYING_PARTY: &str = "http://xboxlive.com";
const MAX_RELYING_PARTIES: usize = 64;

mod checkpoint;
pub use checkpoint::{Checkpoint, MAX_CHECKPOINT_BYTES};

pub mod mpsd;
mod service;
pub mod social;

/// Authentication policy, distinct from the Bedrock session's platform metadata.
#[derive(Clone, Debug)]
pub struct Config {
    /// Microsoft application that acquires this account's OAuth credentials.
    pub client_id: String,
    /// User agent attached to acquisition requests.
    pub user_agent: String,
    /// XASD device platform.
    pub device: Device,
    /// XASD operating-system version.
    pub device_version: String,
    /// Xbox environment, usually RETAIL.
    pub sandbox: String,
}

/// Device identity rules supported by the inspected Xbox authentication baseline.
#[derive(Clone, Copy, Debug)]
pub enum Device {
    /// Android OS major version.
    Android,
    /// iOS/iPadOS version.
    Ios,
    /// Nintendo console OS version.
    Nintendo,
    /// PlayStation OS version.
    PlayStation,
    /// Windows NT version.
    Win32,
    /// Xbox system version.
    Xbox,
}

impl Default for Config {
    /// Uses Cinnabar's current Android Minecraft authentication policy.
    fn default() -> Self {
        Self {
            client_id: "0000000048183522".into(),
            user_agent: "XAL Android 2025.04.20250326.000".into(),
            device: Device::Android,
            device_version: "13".into(),
            sandbox: "RETAIL".into(),
        }
    }
}

impl Config {
    /// Validates policy strings before creating a network owner.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.client_id.is_empty()
            || self.user_agent.is_empty()
            || self.device_version.is_empty()
            || self.sandbox.is_empty()
        {
            return Err(Error::Invalid("empty authentication policy"));
        }
        Ok(())
    }
}

impl Device {
    /// Returns the wire name and UUID formatting for a fresh device token request.
    fn identity(self) -> (&'static str, String, Option<String>) {
        let id = uuid::Uuid::new_v4().to_string();
        match self {
            Self::Android => ("Android", format!("{{{id}}}"), None),
            Self::Nintendo => ("Nintendo", format!("{{{id}}}"), None),
            Self::Ios => ("iOS", id.to_uppercase(), None),
            Self::PlayStation => ("PlayStation", id, None),
            Self::Win32 | Self::Xbox => {
                let id = format!("{{{}}}", id.to_uppercase());
                (
                    if matches!(self, Self::Win32) {
                        "Win32"
                    } else {
                        "Xbox"
                    },
                    id.clone(),
                    Some(id),
                )
            }
        }
    }
}

/// An immutable Xbox authorization, tied to one relying party and account owner.
/// Tokens and user hashes have no Debug or automatic serialization implementation.
pub struct Authorization {
    relying_party: String,
    token: Token,
    user: User,
}

impl Authorization {
    /// Returns the party for which this credential was issued.
    pub fn relying_party(&self) -> &str {
        &self.relying_party
    }
    /// Returns the account's stable numeric Xbox identifier when this party supplies it.
    pub fn xuid(&self) -> &str {
        &self.user.xuid
    }
    /// Returns the display name when this relying party supplies one.
    pub fn gamertag(&self) -> &str {
        &self.user.gamertag
    }
    /// Exposes a sensitive HTTP header for a service that accepts this relying party.
    pub fn header_value(&self) -> Result<HeaderValue, Error> {
        let value = Zeroizing::new(format!(
            "XBL3.0 x={};{}",
            self.user.hash,
            self.token.value.as_str()
        ));
        let mut header = HeaderValue::from_str(&value)
            .map_err(|_| Error::Invalid("Xbox authorization header"))?;
        header.set_sensitive(true);
        Ok(header)
    }
}

/// Owns one account's acquisition client, OAuth state, proof key and token caches.
/// Mutable methods serialize acquisition through Rust ownership; service traffic
/// can share the returned immutable authorizations independently.
pub struct Account {
    http: Http,
    config: Config,
    credentials: Credentials,
    key: SigningKey,
    device: Option<Token>,
    session: Option<Session>,
    title_data: Option<TitleData>,
    current_title_data: Option<TitleData>,
    authorizations: HashMap<String, Arc<Authorization>>,
}

struct Session {
    title: Token,
    user: Token,
}

impl Account {
    /// Establishes one proof-key owner without issuing any network request.
    pub(crate) fn new(http: Http, config: Config, credentials: Credentials) -> Result<Self, Error> {
        let key = SigningKey::try_generate_from_rng(&mut SysRng)
            .map_err(|_| Error::Invalid("proof-key entropy unavailable"))?;
        Ok(Self::with_key(http, config, credentials, key))
    }

    /// Initializes empty derived state around one fresh or restored proof-key owner.
    fn with_key(http: Http, config: Config, credentials: Credentials, key: SigningKey) -> Self {
        Self {
            http,
            config,
            credentials,
            key,
            device: None,
            session: None,
            title_data: None,
            current_title_data: None,
            authorizations: HashMap::new(),
        }
    }

    /// Borrows the account's current Microsoft credentials for secure persistence.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Adopts a same-account credential rotation without replacing its proof key.
    ///
    /// The caller must check its account generation and serialize this operation
    /// with refresh and protected storage. Client-ID equality does not establish
    /// account identity. Derived authorizations are discarded before their next use.
    ///
    /// # Errors
    /// Rejects a different client ID without changing the current account state.
    pub fn replace_credentials(&mut self, credentials: Credentials) -> Result<(), Error> {
        if credentials.client_id != self.config.client_id {
            return Err(Error::Invalid("credential client ID"));
        }
        self.credentials = credentials;
        self.device = None;
        self.session = None;
        self.title_data = None;
        self.current_title_data = None;
        self.authorizations.clear();
        Ok(())
    }

    /// Resolves concrete service traffic against the authenticated title before generic policy.
    pub(crate) async fn authorize_service(
        &mut self,
        url: &url::Url,
    ) -> Result<Arc<Authorization>, Error> {
        if self.current_title_data.is_none() {
            let token = self.authorize(XBOX_RELYING_PARTY).await?;
            let mut request = self
                .http
                .request(reqwest::Method::GET, &self.http.endpoints.nsal_current)
                .header("x-xbl-contract-version", "1")
                .header("authorization", token.header_value()?)
                .build()?;
            SignaturePolicy::default().sign(&mut request, &self.key, self.http.now())?;
            let response = self.http.send(request).await?;
            if response.status == reqwest::StatusCode::UNAUTHORIZED {
                self.reject(&token);
            }
            response.success()?;
            self.current_title_data = Some(response.json()?);
        }
        self.ensure_title_data().await?;
        let party = self
            .service_policy(url)
            .map(|(party, _)| party.to_owned())
            .ok_or(Error::Invalid("unmatched service endpoint"))?;
        self.authorize(&party).await
    }

    /// Resolves the loaded title tables in the same order for acquisition and signing.
    fn service_policy(&self, url: &url::Url) -> Option<(&str, SignaturePolicy)> {
        self.current_title_data
            .as_ref()
            .and_then(|data| data.resolve(url))
            .or_else(|| self.title_data.as_ref().and_then(|data| data.resolve(url)))
    }

    /// Acquires or reuses a credential for one relying party. Cancellation drops
    /// the current HTTP operation; successfully installed earlier stages remain reusable.
    pub async fn authorize(&mut self, relying_party: &str) -> Result<Arc<Authorization>, Error> {
        if relying_party.is_empty() || relying_party.len() > 4096 {
            return Err(Error::Invalid("relying party"));
        }
        let now = self.http.now();
        if let Some(token) = self
            .authorizations
            .get(relying_party)
            .filter(|token| token.token.valid(now))
        {
            return Ok(Arc::clone(token));
        }
        self.authorizations
            .retain(|_, token| token.token.valid(now));
        if self.authorizations.len() >= MAX_RELYING_PARTIES {
            return Err(Error::Invalid("too many relying parties"));
        }
        self.ensure_device().await?;
        self.ensure_session().await?;
        if let Some(token) = self.authorizations.get(relying_party) {
            return Ok(Arc::clone(token));
        }
        if self.authorizations.len() >= MAX_RELYING_PARTIES {
            return Err(Error::Invalid("too many relying parties"));
        }
        let device = self
            .device
            .as_ref()
            .ok_or(Error::Invalid("missing device state"))?;
        let session = self
            .session
            .as_ref()
            .ok_or(Error::Invalid("missing SISU state"))?;
        let body = json!({
            "RelyingParty": relying_party, "TokenType": "JWT",
            "Properties": {"SandboxId": self.config.sandbox, "DeviceToken": device.value.as_str(),
                "TitleToken": session.title.value.as_str(), "UserTokens": [session.user.value.as_str()]},
        });
        let mut request = self.http.post_json(&self.http.endpoints.xsts, &body)?;
        request
            .headers_mut()
            .insert("x-xbl-contract-version", HeaderValue::from_static("1"));
        SignaturePolicy::default().sign(&mut request, &self.key, self.http.now())?;
        let response = self.http.send(request).await?;
        response.success()?;
        let wire: TokenResponse = response.json()?;
        let token = Arc::new(wire.authorization(relying_party, self.http.now())?);
        self.authorizations
            .insert(relying_party.into(), Arc::clone(&token));
        Ok(token)
    }

    /// Rejects only the exact cached issuance; a delayed failure cannot evict its replacement.
    pub fn reject(&mut self, rejected: &Arc<Authorization>) -> bool {
        if !self
            .authorizations
            .get(&rejected.relying_party)
            .is_some_and(|current| Arc::ptr_eq(current, rejected))
        {
            return false;
        }
        self.authorizations.remove(&rejected.relying_party);
        if rejected.relying_party == XBOX_RELYING_PARTY {
            self.session = None;
        }
        true
    }

    /// Caches public default title policy for this account's lifetime.
    async fn ensure_title_data(&mut self) -> Result<(), Error> {
        if self.title_data.is_none() {
            self.title_data = Some(TitleData::load(&mut self.http).await?);
        }
        Ok(())
    }

    /// Renews device state using the same proof key as later SISU and service signatures.
    async fn ensure_device(&mut self) -> Result<(), Error> {
        if self
            .device
            .as_ref()
            .is_some_and(|token| token.valid(self.http.now()))
        {
            return Ok(());
        }
        let (device_type, id, serial) = self.config.device.identity();
        let mut properties = json!({"AuthMethod": "ProofOfPossession", "Id": id,
            "DeviceType": device_type, "Version": self.config.device_version, "ProofKey": self.proof_key()});
        if let Some(serial) = serial {
            properties["SerialNumber"] = json!(serial);
        }
        let body = json!({"RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT", "Properties": properties});
        let mut request = self
            .http
            .post_json(&self.http.endpoints.device_token, &body)?;
        request
            .headers_mut()
            .insert("x-xbl-contract-version", HeaderValue::from_static("1"));
        SignaturePolicy::default().sign(&mut request, &self.key, self.http.now())?;
        let response = self.http.send(request).await?;
        response.success()?;
        let token = response.json::<TokenResponse>()?.token(self.http.now())?;
        self.device = Some(token);
        self.session = None;
        Ok(())
    }

    /// Acquires title/user/default authorization together and publishes only a valid response.
    async fn ensure_session(&mut self) -> Result<(), Error> {
        if self.session.as_ref().is_some_and(|session| {
            session.title.valid(self.http.now()) && session.user.valid(self.http.now())
        }) {
            return Ok(());
        }
        self.credentials.renew(&mut self.http).await?;
        self.ensure_title_data().await?;
        let device = self
            .device
            .as_ref()
            .ok_or(Error::Invalid("missing device state"))?;
        let access = Zeroizing::new(format!("t={}", self.credentials.access.as_str()));
        let body = json!({"AccessToken": access.as_str(), "AppId": self.config.client_id,
            "DeviceToken": device.value.as_str(), "ProofKey": self.proof_key(),
            "RelyingParty": XBOX_RELYING_PARTY, "Sandbox": self.config.sandbox,
            "SiteName": "user.auth.xboxlive.com", "UseModernGamertag": true});
        let mut request = self.http.post_json(&self.http.endpoints.sisu, &body)?;
        let (_, policy) = self
            .title_data
            .as_ref()
            .and_then(|data| data.resolve(request.url()))
            .ok_or(Error::Invalid("unmatched SISU endpoint"))?;
        policy.sign(&mut request, &self.key, self.http.now())?;
        let response = self.http.send(request).await?;
        response.success()?;
        let response: SisuResponse = response.json()?;
        let now = self.http.now();
        let title = response.title_token.token(now)?;
        let user = response.user_token.token(now)?;
        let authorization = Arc::new(
            response
                .authorization_token
                .authorization(XBOX_RELYING_PARTY, now)?,
        );
        self.session = Some(Session { title, user });
        self.authorizations
            .insert(XBOX_RELYING_PARTY.into(), authorization);
        Ok(())
    }

    /// Encodes only the public coordinates of the account's ES256 proof key.
    fn proof_key(&self) -> serde_json::Value {
        let point = self.key.verifying_key().to_sec1_point(false);
        json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..65])})
    }
}

struct Token {
    value: Zeroizing<String>,
    expires: SystemTime,
}

impl Token {
    /// Applies the acquisition baseline's one-minute renewal margin.
    fn valid(&self, now: SystemTime) -> bool {
        !self.value.is_empty()
            && self
                .expires
                .duration_since(now)
                .is_ok_and(|remaining| remaining > Duration::from_secs(60))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TokenResponse {
    token: String,
    not_after: String,
    #[serde(default)]
    display_claims: Claims,
}

#[derive(Default, Deserialize)]
struct Claims {
    #[serde(default, rename = "xui")]
    users: Vec<User>,
}

#[derive(Deserialize)]
struct User {
    #[serde(rename = "uhs")]
    hash: String,
    #[serde(default, rename = "xid")]
    xuid: String,
    #[serde(default, rename = "gtg")]
    gamertag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SisuResponse {
    title_token: TokenResponse,
    user_token: TokenResponse,
    authorization_token: TokenResponse,
}

impl TokenResponse {
    /// Rejects empty, expired and malformed service credentials before caching.
    fn token(self, now: SystemTime) -> Result<Token, Error> {
        let expires = OffsetDateTime::parse(&self.not_after, &Rfc3339)
            .map_err(|_| Error::Invalid("Xbox token expiry"))?;
        let offset = expires - OffsetDateTime::UNIX_EPOCH;
        let expires = if offset.is_negative() {
            SystemTime::UNIX_EPOCH.checked_sub(offset.unsigned_abs())
        } else {
            SystemTime::UNIX_EPOCH.checked_add(offset.unsigned_abs())
        }
        .ok_or(Error::TimeRange)?;
        let token = Token {
            value: Zeroizing::new(self.token),
            expires,
        };
        if !token.valid(now) {
            return Err(Error::Invalid("Xbox token lifetime"));
        }
        Ok(token)
    }

    /// Requires a nonempty user hash before a credential can form an HTTP header.
    fn authorization(
        mut self,
        relying_party: &str,
        now: SystemTime,
    ) -> Result<Authorization, Error> {
        if self.display_claims.users.is_empty() {
            return Err(Error::Invalid("missing Xbox user claims"));
        }
        let user = self.display_claims.users.remove(0);
        if user.hash.is_empty() {
            return Err(Error::Invalid("empty Xbox user hash"));
        }
        let token = self.token(now)?;
        Ok(Authorization {
            relying_party: relying_party.into(),
            token,
            user,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
