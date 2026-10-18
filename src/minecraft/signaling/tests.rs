use super::*;
use crate::{
    http::Http,
    minecraft::{Authorization, Config, Environment, USER_AGENT, token::TokenResponse},
    oauth::Credentials,
    xbox::{self, tests::fixture},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use uuid::Uuid;

/// Creates original service metadata without accessing a real account or signing service.
fn authorization(label: &str) -> Arc<Authorization> {
    let claims = URL_SAFE_NO_PAD.encode(json!({"pmid":Uuid::from_u128(7)}).to_string());
    serde_json::from_value::<TokenResponse>(json!({
        "authorizationHeader":format!("MCToken {label}.{claims}.synthetic"),
        "validUntil":"2099-01-01T00:00:00Z"
    }))
    .unwrap()
    .authorization(UNIX_EPOCH)
    .map(Arc::new)
    .unwrap()
}

/// Supplies already acquired account state while exercising the concrete configuration HTTP edge.
fn services(address: std::net::SocketAddr) -> Minecraft {
    let config = xbox::Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "fixture-access".into(),
        "fixture-refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let xbox = xbox::Account::new(Http::fixture(address), config, credentials).unwrap();
    let mut minecraft =
        Minecraft::new(xbox, Config::desktop("1.26.60", 1014, Uuid::from_u128(1))).unwrap();
    minecraft.http = Http::fixture_agent(address, USER_AGENT);
    minecraft.environment = Some(Environment {
        service_uri: format!("http://{address}/auth"),
        play_fab_title_id: "AB12".into(),
        issuer: String::new(),
    });
    minecraft.signaling_environment =
        Some(json!({"prod":{"serviceUri":format!("http://{address}/prefix")}}));
    minecraft.authorization = Some(authorization("original"));
    minecraft
}

/// Checks MCToken reuse, advertised paths, protected upgrade metadata and exact-issuance rejection.
#[tokio::test]
async fn configuration_reuses_service_identity_and_rejects_only_the_failed_issuance() {
    let mut step = 0;
    let (address, server) = fixture(
        move |target, headers, _| {
            step += 1;
            assert_eq!(target, "/prefix/api/v1.0/configuration");
            let headers = headers.to_ascii_lowercase();
            assert!(headers.starts_with("get "));
            assert!(headers.contains(&format!("user-agent: {USER_AGENT}")));
            assert!(headers.contains(if step == 4 {
                "authorization: mctoken replacement."
            } else {
                "authorization: mctoken original."
            }));
            if step == 3 {
                (401, json!({"diagnostic":"SECRET"}))
            } else {
                (
                    200,
                    json!({"result":{"signalingUri":"wss://example.invalid/region/",
            "pingFrequency":"00:00:31","unrecognized":"ignored"}}),
                )
            }
        },
        4,
    )
    .await;
    let mut minecraft = services(address);
    let first = minecraft.messaging_connection().await.unwrap();
    assert_eq!(
        first.url().as_str(),
        "wss://example.invalid/region/ws/v1.0/messaging/connect"
    );
    assert_eq!(first.ping_interval(), Duration::from_secs(31));
    assert_eq!(first.player_messaging_id(), Uuid::from_u128(7));
    assert!(first.authorization().unwrap().is_sensitive());
    let second = minecraft.messaging_connection().await.unwrap();
    assert!(Arc::ptr_eq(&first.authorization, &second.authorization));
    let error = minecraft.messaging_connection().await.err().unwrap();
    assert!(!format!("{error:?} {error}").contains("SECRET"));
    assert!(minecraft.authorization.is_none());
    minecraft.authorization = Some(authorization("replacement"));
    assert!(!minecraft.reject_messaging(&first));
    let replacement = minecraft.messaging_connection().await.unwrap();
    assert!(minecraft.reject_messaging(&replacement));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Optional discovery failures do not poison auth discovery or trigger credential acquisition.
#[tokio::test]
async fn invalid_optional_discovery_and_upgrade_destinations_remain_redacted() {
    let environments = [
        Value::Null,
        json!(false),
        json!({"staging":{}}),
        json!({"prod":{"serviceUri":"http://example.invalid"}}),
        json!({"prod":{"serviceUri":"https://user:SECRET@example.invalid"}}),
        json!({"prod":{"serviceUri":"https://example.invalid?SECRET"}}),
    ];
    for environment in environments {
        let (address, server) = fixture(move |_, headers, _| {
            let host = headers.lines().find_map(|line| line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("host")).map(|(_, value)| value.trim())).unwrap();
            (200, json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
                "signaling-afd":environment}}}))
        }, 1).await;
        let mut minecraft = services(address);
        minecraft.environment = None;
        minecraft.authorization = None;
        let error = minecraft.messaging_connection().await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
        assert!(minecraft.environment.is_some());
        assert!(minecraft.authorization.is_none());
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
    for uri in [
        "ws://example.invalid",
        "https://example.invalid",
        "wss://user:SECRET@example.invalid",
        "wss://example.invalid?SECRET",
        "wss://example.invalid#SECRET",
    ] {
        let (address, server) = fixture(
            move |_, _, _| {
                (
                    200,
                    json!({"result":{"signalingUri":uri,"pingFrequency":"00:00:15"}}),
                )
            },
            1,
        )
        .await;
        let error = services(address)
            .messaging_connection()
            .await
            .err()
            .unwrap();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
    for interval in [
        "00:00:00",
        "-1:00:00",
        "18446744073709551615:00:00",
        "SECRET",
        "00:00:01:00",
    ] {
        let error = connection::ping_interval(Some(interval)).err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
}
