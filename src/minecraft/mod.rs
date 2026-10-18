//! Discovery, PlayFab login and Minecraft credentials owned by one account session.

mod config;
mod token;

pub use config::Config;
pub use token::{Authorization, Configuration, MultiplayerToken};

use crate::{Error, http::Http, playfab, xbox};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p384::{ecdsa::VerifyingKey, pkcs8::EncodePublicKey};
use reqwest::{Method, header::HeaderValue};
use serde::Deserialize;
use std::sync::Arc;
use url::Url;

const USER_AGENT: &str = "libhttpclient/1.0.0.0";

/// Owns the concrete service chain without background tasks or shared mutable locks.
/// Async methods use the caller's runtime. Successfully acquired stages survive
/// cancellation; dropping this owner releases its account and service credentials.
pub struct Minecraft {
    xbox: xbox::Account,
    http: Http,
    config: Config,
    session_id: uuid::Uuid,
    environment: Option<Environment>,
    playfab: Option<Arc<playfab::Session>>,
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
}

#[derive(Deserialize)]
struct Retail {
    prod: Environment,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Environment {
    service_uri: String,
    play_fab_title_id: String,
}

impl Minecraft {
    /// Binds one Xbox account to stable Minecraft device/version policy without network I/O.
    pub fn new(xbox: xbox::Account, config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            xbox,
            http: Http::new(USER_AGENT)?,
            config,
            environment: None,
            session_id: uuid::Uuid::new_v4(),
            playfab: None,
            authorization: None,
        })
    }

    /// Borrows current Microsoft credentials for the caller's secure persistence layer.
    pub fn credentials(&self) -> &crate::oauth::Credentials {
        self.xbox.credentials()
    }

    /// Releases the service wrapper and returns its account, including rotated OAuth state.
    pub fn into_account(self) -> xbox::Account {
        self.xbox
    }

    /// Returns the game-session identifier shared by credential exchange and every mint.
    pub fn session_id(&self) -> uuid::Uuid {
        self.session_id
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
        let response = self.http.send(request).await?;
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
            let response = self.http.send(request).await?;
            if response.status == reqwest::StatusCode::UNAUTHORIZED {
                self.reject(&authorization);
                if !retried {
                    retried = true;
                    continue;
                }
            }
            response.success()?;
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Mint {
                signed_token: String,
            }
            let minted = response.json::<ResultBody<Mint>>()?.result;
            if minted.signed_token.is_empty() {
                return Err(Error::Invalid("empty multiplayer credential"));
            }
            return Ok(MultiplayerToken {
                token: zeroize::Zeroizing::new(minted.signed_token),
                public_key,
            });
        }
    }

    /// Loads one version-specific environment and validates it before sending credentials.
    async fn discover(&mut self) -> Result<(), Error> {
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
        let response = self.http.send(request).await?;
        response.success()?;
        let discovery = response.json::<ResultBody<Discovery>>()?.result;
        let environment = discovery.service_environments.auth.prod;
        validate_service_url(&environment.service_uri)?;
        playfab::login_url(&environment.play_fab_title_id)?;
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
mod tests;
