//! Shared private synthetic service issuances and real loopback HTTP owners.

use super::{Config, Minecraft, USER_AGENT, token::TokenResponse};
use crate::{http::Http, oauth::Credentials, xbox};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use uuid::Uuid;

/// Creates an already acquired immutable service issuance without any real account material.
pub(super) fn authorization(label: &str) -> Arc<crate::minecraft::Authorization> {
    let claims = URL_SAFE_NO_PAD.encode(json!({"pmid":Uuid::from_u128(7)}).to_string());
    Arc::new(
        serde_json::from_value::<TokenResponse>(json!({
            "authorizationHeader":format!("MCToken {label}.{claims}.synthetic"),
            "validUntil":"2099-01-01T00:00:00Z"
        }))
        .unwrap()
        .authorization(UNIX_EPOCH)
        .unwrap(),
    )
}

/// Uses only the ordinary account/session constructors and private fixture HTTP at the edge.
pub(super) fn services(address: std::net::SocketAddr) -> Minecraft {
    let config = xbox::Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "synthetic-access".into(),
        "synthetic-refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let account = xbox::Account::new(Http::fixture(address), config, credentials).unwrap();
    let mut services = Minecraft::new(
        account,
        Config::desktop("1.26.50", 2193, Uuid::from_u128(1)),
    )
    .unwrap();
    services.http = Http::fixture_agent(address, USER_AGENT);
    services.authorization = Some(authorization("original"));
    services
}
