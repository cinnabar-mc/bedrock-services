use super::*;
use crate::{
    http::Http,
    minecraft::{Config, USER_AGENT, token::TokenResponse},
    oauth::Credentials,
    xbox::{self, tests::fixture_bytes},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use uuid::Uuid;

/// Creates an already acquired immutable service issuance without any real account material.
fn authorization(label: &str) -> Arc<crate::minecraft::Authorization> {
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
fn services(address: std::net::SocketAddr) -> Minecraft {
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

/// A source-bounded persona image must survive the public owner above acquisition's smaller cap.
#[tokio::test]
async fn profile_service_body_above_default_limit_preserves_persona_image() {
    // A one-pixel GIF padded with legal comment sub-blocks.
    let mut image = b"GIF89a".to_vec();
    image.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0, 0, 0, 0, 255, 255, 255]);
    image.extend_from_slice(&[0x21, 0xfe]);
    let comment = vec![b'a'; crate::http::RESPONSE_LIMIT + 1024];
    for block in comment.chunks(255) {
        image.push(u8::try_from(block.len()).unwrap());
        image.extend_from_slice(block);
    }
    image.push(0);
    image.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 1, 0, 0x3b]);
    assert!(image.len() > crate::http::RESPONSE_LIMIT);
    assert!(image.len() < 2 * crate::http::RESPONSE_LIMIT);
    let served_image = image.clone();
    let mut step = 0;
    let (address, server) = fixture_bytes(move |path, headers, body| {
        step += 1;
        assert!(headers.starts_with("GET "));
        assert!(body.is_empty());
        let headers = headers.to_ascii_lowercase();
        if step == 1 {
            assert_eq!(path, "/api/v1.0/discovery/MinecraftPE/builds/1.26.50");
            assert!(!headers.contains("authorization:"));
            let host = headers.lines().find_map(|line| line.strip_prefix("host: ")).unwrap();
            return (200, vec![], json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
                "persona":{"prod":{"serviceUri":format!("http://{host}/persona")}}
            }}}).to_string().into_bytes());
        }
        assert_eq!(path, "/persona/api/v1.0/profile/xuid/123/image/head");
        assert!(headers.contains("authorization: mctoken original."));
        assert!(headers.contains("accept: image/*"));
        assert!(!headers.contains("signature:"));
        (200, vec![("Content-Type", "image/gif"), ("ETag", "\"original-image\"")], served_image.clone())
    }, 2).await;
    let mut services = services(address);
    let original = Arc::clone(services.authorization.as_ref().unwrap());
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        services.profile().image("123", ImageKind::Head),
    )
    .await
    .unwrap();
    if result.is_err() {
        server.abort();
    }
    let served = server.await;
    let response = result
        .unwrap_or_else(|error| panic!("valid in-bound persona response rejected: {error:?}"));
    served.unwrap();
    assert_eq!(response.bytes.as_slice(), image.as_slice());
    assert_eq!(response.content_type.as_deref(), Some("image/gif"));
    assert_eq!(response.etag.as_deref(), Some("\"original-image\""));
    assert!(Arc::ptr_eq(
        &original,
        services.authorization.as_ref().unwrap()
    ));
}

/// Verifies discovered path prefixes, real authorized binary/JSON GETs and exact-issuance rejection.
#[tokio::test]
async fn persona_and_gallery_share_discovery_and_service_issuance_without_following_metadata() {
    let image = b"original-synthetic-image-bytes";
    let mut step = 0;
    let (address, server) = fixture_bytes(move |path, headers, body| {
        step += 1;
        assert!(headers.starts_with("GET "));
        assert!(body.is_empty());
        let headers = headers.to_ascii_lowercase();
        assert!(headers.contains(&format!("user-agent: {USER_AGENT}")));
        if step == 1 {
            assert_eq!(path, "/api/v1.0/discovery/MinecraftPE/builds/1.26.50");
            assert!(!headers.contains("authorization:"));
            let host = headers.lines().find_map(|line| line.strip_prefix("host: ")).unwrap();
            return (200, vec![], json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
                "persona":{"prod":{"serviceUri":format!("http://{host}/persona-prefix")}}
            }}}).to_string().into_bytes());
        }
        assert!(!headers.contains("signature:"));
        assert!(headers.contains(if step <= 4 { "authorization: mctoken original." } else { "authorization: mctoken replacement." }));
        if step == 2 {
            assert_eq!(path, "/persona-prefix/api/v1.0/profile/xuid/123/image/avatar");
            assert!(headers.contains("accept: image/*"));
            return (200, vec![("Content-Type","image/png"),("ETag","\"synthetic\"")], image.to_vec());
        }
        assert_eq!(path, "/persona-prefix/api/v1.0/gallery/xuid/123");
        assert!(headers.contains("accept: application/json"));
        let (status, value) = match step {
            3 => (200, json!({"result":{"showcasedImages":[
                {"id":"unfeatured","url":"https://art.example/one","isFeatured":false},
                {"id":"featured","url":"https://art.example/two","isFeatured":true,"takenTime":"future-format"},
                {"id":"unknown-state","url":"https://art.example/three"},
                {"url":"https://user:SENSITIVE@art.example/bad"},null]}})),
            4 => (401, json!({"diagnostic":"SENSITIVE-service-body"})),
            5 => (200, json!({"result":{"showcasedImages":null}})),
            6 => (200, json!({"result":null})),
            _ => unreachable!(),
        };
        (status, vec![], value.to_string().into_bytes())
    }, 6).await;
    let mut services = services(address);
    assert!(
        services
            .profile()
            .image("../invalid", ImageKind::Avatar)
            .await
            .is_err()
    );
    let original = Arc::clone(services.authorization.as_ref().unwrap());
    let response = services
        .profile()
        .image("123", ImageKind::Avatar)
        .await
        .unwrap();
    assert_eq!(response.bytes.as_slice(), image);
    assert_eq!(response.content_type.as_deref(), Some("image/png"));
    assert_eq!(response.etag.as_deref(), Some("\"synthetic\""));
    assert!(Arc::ptr_eq(
        &original,
        services.authorization.as_ref().unwrap()
    ));
    let gallery = services.profile().gallery("123").await.unwrap();
    assert_eq!(gallery.images.len(), 3);
    assert_eq!(gallery.malformed_items, 2);
    assert_eq!(gallery.images[0].is_featured, Some(false));
    assert_eq!(gallery.images[1].is_featured, Some(true));
    assert_eq!(gallery.images[2].is_featured, None);
    let error = services.profile().gallery("123").await.err().unwrap();
    assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    assert!(services.authorization.is_none());
    services.authorization = Some(authorization("replacement"));
    assert!(!services.reject(&original));
    assert!(
        services
            .profile()
            .gallery("123")
            .await
            .unwrap()
            .images
            .is_empty()
    );
    assert!(services.profile().gallery("123").await.is_err());
    server.await.unwrap();
}

/// Optional malformed persona discovery cannot poison auth or evict an unrelated service issuance.
#[tokio::test]
async fn optional_persona_discovery_fails_before_credentials_without_poisoning_auth() {
    for persona in [
        Value::Null,
        json!(false),
        json!({"staging":{}}),
        json!({"prod":{"serviceUri":"http://unsafe.example"}}),
        json!({"prod":{"serviceUri":"https://user:SENSITIVE@unsafe.example"}}),
    ] {
        let (address, server) = fixture_bytes(move |_, headers, _| {
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
            let host = headers.lines().filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("host")).unwrap().1.trim();
            (200, vec![], json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
                "persona":persona}}}).to_string().into_bytes())
        }, 1).await;
        let mut services = services(address);
        let original = Arc::clone(services.authorization.as_ref().unwrap());
        let error = services.profile().gallery("123").await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
        assert!(services.environment.is_some());
        assert!(Arc::ptr_eq(&original, &services.authorize().await.unwrap()));
        server.await.unwrap();
    }
}
