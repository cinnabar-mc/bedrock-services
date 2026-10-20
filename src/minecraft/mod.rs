//! Discovery, PlayFab login and Minecraft credentials owned by one account session.

mod config;
mod entity;
pub mod gatherings;
pub mod player_messaging;
pub mod profile;
mod signaling;
#[cfg(test)]
mod test_support;
mod token;

pub use config::{Config, DeviceId};
pub use token::{Authorization, Configuration, MultiplayerToken};

use crate::{Error, http::Http, playfab, realms, xbox};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p384::{ecdsa::VerifyingKey, pkcs8::EncodePublicKey};
use reqwest::{Method, header::HeaderValue};
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use url::Url;

/// Minecraft service and public authorization-provider metadata request policy.
pub const USER_AGENT: &str = "libhttpclient/1.0.0.0";

/// Release Minecraft service identity for multiplayer activity and session queries.
pub const SERVICE_CONFIG_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x4fc1_0100_5f7a_4470_899b_2808_3576_0c07);

/// Owns the concrete service chain without background tasks or shared mutable locks.
/// Async methods use the caller's runtime. Successfully acquired stages survive
/// cancellation; dropping this owner releases its account and service credentials.
pub struct Minecraft {
    xbox: xbox::Account,
    http: Http,
    config: Config,
    session_id: uuid::Uuid,
    environment: Option<Environment>,
    signaling_environment: Option<serde_json::Value>,
    legacy_signaling_environment: Option<serde_json::Value>,
    realms_environment: Option<serde_json::Value>,
    persona_environment: Option<serde_json::Value>,
    messaging_environment: Option<serde_json::Value>,
    gatherings_environment: Option<serde_json::Value>,
    gatherings_state: gatherings::State,
    messaging_state: player_messaging::State,
    realms_state: realms::State,
    playfab: Option<Arc<playfab::Session>>,
    entities: HashMap<playfab::EntityKind, Arc<playfab::Entity>>,
    authorization: Option<Arc<Authorization>>,
}

#[derive(Deserialize)]
struct ResultBody<T> {
    result: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Discovery {
    service_environments: Environments,
}

#[derive(Deserialize)]
struct Environments {
    auth: Retail,
    #[serde(default, rename = "signaling-afd")]
    signaling_afd: Option<serde_json::Value>,
    #[serde(default)]
    signaling: Option<serde_json::Value>,
    #[serde(default)]
    realms_frontend_bedrock_legacy: Option<serde_json::Value>,
    #[serde(default)]
    persona: Option<serde_json::Value>,
    #[serde(default)]
    messaging: Option<serde_json::Value>,
    #[serde(default)]
    gatherings: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Retail {
    prod: Environment,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Environment {
    service_uri: String,
    #[serde(alias = "playfabTitleId")]
    play_fab_title_id: String,
    #[serde(default)]
    issuer: String,
}

impl Minecraft {
    /// Keeps real service acquisition on the finite fixture's same verified loopback transport owner.
    #[cfg(feature = "test-support")]
    pub(crate) fn hosted_activation_http(
        &mut self,
        transport: std::sync::Arc<crate::test_support::activation::transport::Transport>,
    ) {
        self.http = transport.account_http(USER_AGENT);
        self.xbox.inherit_hosted_clock(&mut self.http);
    }

    /// Confines only the nondefault hosted fixture's discovery owner to its finite HTTP peer.
    #[cfg(feature = "test-support")]
    pub(crate) fn hosted_fixture_http(&mut self, address: std::net::SocketAddr) {
        assert!(address.ip().is_loopback());
        self.http = Http::fixture_agent(address, USER_AGENT);
    }

    /// Binds one Xbox account to stable Minecraft device/version policy without network I/O.
    pub fn new(xbox: xbox::Account, config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            xbox,
            http: Http::new(USER_AGENT)?,
            config,
            environment: None,
            signaling_environment: None,
            legacy_signaling_environment: None,
            realms_environment: None,
            persona_environment: None,
            messaging_environment: None,
            gatherings_environment: None,
            gatherings_state: gatherings::State::default(),
            messaging_state: player_messaging::State::new(),
            realms_state: realms::State::default(),
            session_id: uuid::Uuid::new_v4(),
            playfab: None,
            entities: HashMap::new(),
            authorization: None,
        })
    }

    /// Borrows current Microsoft credentials for the caller's secure persistence layer.
    pub fn credentials(&self) -> &crate::oauth::Credentials {
        self.xbox.credentials()
    }

    /// Acquires this account's Xbox identity without replacing its proof or game-session owner.
    /// Callers must verify the returned XUID before associating rotated credentials
    /// with a saved account. A matching OAuth client ID does not establish identity.
    pub async fn xbox_authorization(&mut self) -> Result<Arc<xbox::Authorization>, Error> {
        self.xbox.authorize(xbox::XBOX_RELYING_PARTY).await
    }

    /// Captures the current refresh credential and proof key without consuming this session.
    /// Protected storage, account generation and refresh serialization remain caller-owned.
    ///
    /// # Errors
    /// Returns the account checkpoint's bounded encoding or missing-refresh error.
    pub fn checkpoint(&self) -> Result<xbox::Checkpoint, Error> {
        self.xbox.checkpoint()
    }

    /// Adopts a same-account OAuth rotation while retaining proof and game-session identity.
    ///
    /// The caller must enforce account generation and serialize refresh/persistence.
    /// Derived Xbox, PlayFab and Minecraft credentials are reacquired on demand;
    /// immutable credentials already borrowed by callers are not revoked remotely.
    ///
    /// # Errors
    /// Rejects a different client ID without changing any retained credentials.
    pub fn replace_credentials(
        &mut self,
        credentials: crate::oauth::Credentials,
    ) -> Result<(), Error> {
        self.xbox.replace_credentials(credentials)?;
        self.playfab = None;
        self.entities.clear();
        self.authorization = None;
        Ok(())
    }

    /// Releases the service wrapper and returns its account, including rotated OAuth state.
    pub fn into_account(self) -> xbox::Account {
        self.xbox
    }

    /// Borrows Xbox social services using the same account, proof and XSTS cache.
    pub fn social(&mut self) -> xbox::social::Social<'_> {
        self.xbox.social()
    }

    /// Borrows explicit Xbox invitation inbox reads on the same account and proof.
    pub fn notifications(&mut self) -> xbox::notifications::Notifications<'_> {
        self.xbox.notifications()
    }

    /// Borrows explicit statistics reads on the same Xbox account and proof.
    pub fn statistics(&mut self) -> xbox::statistics::Statistics<'_> {
        self.xbox.statistics()
    }

    /// Borrows title achievements on the same authenticated account and proof.
    pub fn achievements(&mut self) -> xbox::achievements::Achievements<'_> {
        self.xbox.achievements()
    }

    /// Borrows discovered persona/gallery reads without starting acquisition or background work.
    pub fn profile(&mut self) -> profile::Profile<'_> {
        profile::Profile { minecraft: self }
    }

    /// Borrows the marketing message/inbox session without refreshing or reporting an interaction.
    /// This service is distinct from Xbox game invitations and NetherNet signaling.
    pub fn player_messaging(&mut self) -> player_messaging::PlayerMessaging<'_> {
        player_messaging::PlayerMessaging { minecraft: self }
    }

    /// Borrows one-shot title presence writes using the same account, proof and XSTS cache.
    pub fn title_presence(&mut self) -> xbox::presence::TitlePresence<'_> {
        self.xbox.title_presence()
    }

    /// Borrows session-directory operations on this account without starting RTA or hosting tasks.
    pub fn mpsd(&mut self) -> xbox::mpsd::Directory<'_> {
        self.xbox.mpsd()
    }

    /// Prepares one protected RTA upgrade using this account's proof and XSTS cache.
    /// The caller owns its account generation, WebSocket, deadlines and reconnect policy.
    pub async fn rta_connection(
        &mut self,
        generation: xbox::rta::Generation,
        upgrade_headers: reqwest::header::HeaderMap,
    ) -> Result<xbox::rta::ConnectionRequest, xbox::rta::Error> {
        self.xbox.rta_connection(generation, upgrade_headers).await
    }

    /// Rejects only the exact RTA upgrade credential; delayed failures cannot evict replacements.
    pub fn reject_rta(&mut self, request: &xbox::rta::ConnectionRequest) -> bool {
        self.xbox.reject_rta(request)
    }

    /// Checks whether this account retains the proof owner of an existing RTA connection.
    /// Applications must also fence their selected XUID and sign-in generation.
    pub fn owns_rta(&self, connection: &xbox::rta::Connection) -> bool {
        connection.owns_account_proof(&self.xbox)
    }

    /// Recovers this account's disconnected RTA socket within the caller's original deadline.
    /// Apply returned subscription snapshots in order and rebind affected MPSD memberships.
    /// Cancellation retains desired handles and retry backoff while dropping partial transport work.
    ///
    /// # Errors
    /// Returns account/lifecycle mismatch, subscription rejection or deadline expiry.
    #[cfg(feature = "rta-tokio")]
    pub async fn recover_rta(
        &mut self,
        socket: &mut xbox::rta::websocket::RtaSocket,
        deadline: std::time::Instant,
    ) -> Result<Vec<xbox::rta::Event>, xbox::rta::websocket::RecoveryError> {
        socket.recover(&mut self.xbox, deadline).await
    }

    /// Returns the game-session identifier shared by credential exchange and every mint.
    pub fn session_id(&self) -> uuid::Uuid {
        self.session_id
    }

    /// Borrows the discovered authorization issuer for caller-owned multiplayer verification.
    /// Discovery must already have completed; the returned value is not derived from token claims.
    pub fn authorization_issuer(&self) -> Result<&str, Error> {
        let issuer = &self
            .environment
            .as_ref()
            .ok_or(Error::Invalid("missing authorization discovery"))?
            .issuer;
        validate_service_url(issuer)?;
        Ok(issuer)
    }

    /// Samples the last HTTPS service Date advanced by monotonic elapsed time.
    /// The caller captures its monotonic observation before this call and retains that
    /// pair across transport work rather than starting a fresh credential lifetime later.
    pub fn service_time(&self) -> std::time::SystemTime {
        self.http.now()
    }

    /// Borrows Realms services on the discovered retail endpoint using this account's XSTS cache.
    /// Missing or malformed Realms discovery fails here without affecting auth-only calls.
    pub async fn realms(&mut self) -> Result<realms::Realms<'_>, realms::Error> {
        self.discover().await?;
        let uri = self
            .realms_environment
            .as_ref()
            .and_then(|environment| environment.get("prod"))
            .and_then(|environment| environment.get("serviceUri"))
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Invalid("missing Realms service discovery"))?;
        validate_service_url(uri)?;
        let base = Url::parse(uri).map_err(|_| Error::Invalid("Realms service URL"))?;
        Ok(realms::Realms {
            xbox: &mut self.xbox,
            http: &mut self.http,
            config: &self.config,
            state: &mut self.realms_state,
            base,
        })
    }

    /// Acquires or reuses the PlayFab session for the discovered retail title.
    pub async fn playfab(&mut self) -> Result<Arc<playfab::Session>, Error> {
        self.discover().await?;
        if let Some(session) = self
            .playfab
            .as_ref()
            .filter(|session| session.reusable(self.http.now()))
        {
            return Ok(Arc::clone(session));
        }
        let title = &self
            .environment
            .as_ref()
            .ok_or(Error::Invalid("missing discovery"))?
            .play_fab_title_id;
        let session = Arc::new(playfab::login(&mut self.http, &mut self.xbox, title).await?);
        self.entities.clear();
        self.entities.insert(
            playfab::EntityKind::TitlePlayerAccount,
            Arc::clone(&session.entity),
        );
        self.playfab = Some(Arc::clone(&session));
        Ok(session)
    }

    /// Reuses a current service credential or replaces it with a fresh session.
    pub async fn authorize(&mut self) -> Result<Arc<Authorization>, Error> {
        if let Some(token) = self
            .authorization
            .as_ref()
            .filter(|token| token.reusable(self.http.now()))
        {
            return Ok(Arc::clone(token));
        }
        let playfab = self.playfab().await?;
        let environment = self
            .environment
            .as_ref()
            .ok_or(Error::Invalid("missing discovery"))?;
        let url = append(
            &environment.service_uri,
            &["api", "v1.0", "session", "start"],
        )?;
        let request = self.json(
            &url,
            &self
                .config
                .start(&environment.play_fab_title_id, &playfab.ticket),
        )?;
        let response = self
            .http
            .send_retrying(request, crate::http::retry::Policy::Credential)
            .await?;
        response.success()?;
        let token = Arc::new(
            response
                .json::<ResultBody<token::TokenResponse>>()?
                .result
                .authorization(self.http.now())?,
        );
        self.authorization = Some(Arc::clone(&token));
        Ok(token)
    }

    /// Evicts only the credential still cached from this exact issuance.
    pub fn reject(&mut self, rejected: &Arc<Authorization>) -> bool {
        if self
            .authorization
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, rejected))
        {
            self.authorization = None;
            true
        } else {
            false
        }
    }

    /// Mints for the borrowed connection key; it never generates or replaces that key.
    pub async fn multiplayer_token(
        &mut self,
        key: &VerifyingKey,
    ) -> Result<MultiplayerToken, Error> {
        let der = key
            .to_public_key_der()
            .map_err(|_| Error::Invalid("connection public key"))?;
        let public_key = der.as_bytes().to_vec();
        let mut retried = false;
        loop {
            let authorization = self.authorize().await?;
            let environment = self
                .environment
                .as_ref()
                .ok_or(Error::Invalid("missing discovery"))?;
            let url = append(
                &environment.service_uri,
                &["api", "v1.0", "multiplayer", "session", "start"],
            )?;
            let mut request = self.json(
                &url,
                &serde_json::json!({"publicKey": STANDARD.encode(&public_key)}),
            )?;
            request
                .headers_mut()
                .insert("authorization", authorization.header_value()?);
            let response = self
                .http
                .send_retrying(request, crate::http::retry::Policy::Credential)
                .await?;
            if response.status == reqwest::StatusCode::UNAUTHORIZED {
                self.reject(&authorization);
                if !retried {
                    retried = true;
                    continue;
                }
            }
            response.success()?;
            return response
                .json::<ResultBody<token::MintResponse>>()?
                .result
                .token(public_key, self.http.now());
        }
    }

    /// Loads one version-specific environment and validates it before sending credentials.
    /// Acquires public version-matched service discovery without authorizing or minting credentials.
    ///
    /// Reuses this account session's successfully acquired environment. A failed
    /// or canceled request leaves discovery retryable on the same owner. Optional
    /// service metadata is validated by its eventual consumer; use
    /// [`Self::authorization_issuer`] afterward for a validated provider issuer.
    /// This method performs no Xbox/PlayFab authorization or multiplayer mint.
    ///
    /// # Errors
    /// Returns bounded HTTP/status/JSON or required service-route/title validation errors.
    pub async fn discover(&mut self) -> Result<(), Error> {
        if self.environment.is_some() {
            return Ok(());
        }
        let url = append(
            &self.http.endpoints.discovery,
            &[
                "api",
                "v1.0",
                "discovery",
                "MinecraftPE",
                "builds",
                &self.config.game_version,
            ],
        )?;
        let request = self
            .http
            .request(Method::GET, url.as_str())
            .header("content-type", "application/json")
            .build()?;
        let response = self
            .http
            .send_retrying(request, crate::http::retry::Policy::Discovery)
            .await?;
        response.success()?;
        let discovery = response.json::<ResultBody<Discovery>>()?.result;
        let environment = discovery.service_environments.auth.prod;
        validate_service_url(&environment.service_uri)?;
        playfab::login_url(&environment.play_fab_title_id)?;
        self.signaling_environment = discovery.service_environments.signaling_afd;
        self.legacy_signaling_environment = discovery.service_environments.signaling;
        self.realms_environment = discovery
            .service_environments
            .realms_frontend_bedrock_legacy;
        self.persona_environment = discovery.service_environments.persona;
        self.messaging_environment = discovery.service_environments.messaging;
        self.gatherings_environment = discovery.service_environments.gatherings;
        self.environment = Some(environment);
        Ok(())
    }

    /// Materializes the Minecraft headers before HTTP execution.
    fn json(&self, url: &Url, value: &impl serde::Serialize) -> Result<reqwest::Request, Error> {
        let mut request = self.http.post_json(url.as_str(), value)?;
        request
            .headers_mut()
            .insert("accept", HeaderValue::from_static("application/json"));
        request.headers_mut().insert(
            "session-id",
            HeaderValue::from_str(&self.session_id.to_string())
                .map_err(|_| Error::Invalid("game session identifier"))?,
        );
        Ok(request)
    }
}

/// Appends path segments while preserving a service URI's advertised path prefix.
fn append(base: &str, segments: &[&str]) -> Result<Url, Error> {
    let mut url = Url::parse(base).map_err(|_| Error::Invalid("service URL"))?;
    url.path_segments_mut()
        .map_err(|_| Error::Invalid("service URL path"))?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// Prevents discovery from directing credentials to plaintext or URL user information.
fn validate_service_url(value: &str) -> Result<(), Error> {
    let url = Url::parse(value).map_err(|_| Error::Invalid("authorization service URL"))?;
    let secure = url.scheme() == "https";
    #[cfg(test)]
    let secure = secure || (url.scheme() == "http" && url.host_str() == Some("127.0.0.1"));
    if !secure
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("authorization service URL policy"));
    }
    Ok(())
}

#[cfg(test)]
mod realms_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod trace_tests;
