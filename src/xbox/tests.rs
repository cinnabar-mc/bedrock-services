use super::test_support::{fixture, token, verify_signature};
use super::*;
use crate::oauth::{MicrosoftAuth, Poll};
use serde_json::Value;
use std::time::UNIX_EPOCH;

/// Rejects expired dates even when they precede the platform's SystemTime range.
#[test]
fn ancient_token_expiry_returns_an_error() {
    for expiry in ["0001-01-01T00:00:00Z", "1600-12-31T23:59:59.999999999Z"] {
        let mut response = token("synthetic", false);
        response["NotAfter"] = json!(expiry);
        let response: TokenResponse = serde_json::from_value(response).unwrap();
        assert!(response.token(UNIX_EPOCH).is_err());
    }
}

/// Checks proof-key continuity, request signatures and the whole local authentication chain.
#[tokio::test]
async fn device_flow_caches_credentials_and_fences_stale_rejections() {
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture(move |target, header, body| {
        step += 1;
        if target == "/oauth-token" {
            let form = url::form_urlencoded::parse(body).collect::<HashMap<_, _>>();
            assert_eq!(form.get("scope").map(|value| value.as_ref()), Some(crate::oauth::SCOPE));
        }
        match step {
            1 => {
                assert_eq!(target, "/device-code");
                assert!(header.to_lowercase().contains("accept: application/json"));
                assert!(std::str::from_utf8(body).unwrap().contains("response_type=device_code"));
                (200, json!({"device_code": "private-device", "user_code": "PUBLIC", "verification_uri": "https://login.live.com/device",
                    "expires_in": 900, "interval": 0}))
            }
            2 => { assert_eq!(target, "/oauth-token"); (400, json!({"error": "slow_down"})) }
            3 => { assert_eq!(target, "/oauth-token"); (200, json!({"access_token": "access", "refresh_token": "refresh", "expires_in": 3600})) }
            4 => {
                assert_eq!(target, "/device-token");
                let value: Value = serde_json::from_slice(body).unwrap();
                let key = value["Properties"]["ProofKey"].clone();
                verify_signature(target, header, body, &key, &[]);
                assert_eq!(value["Properties"]["DeviceType"], "Android");
                proof = Some(key);
                (200, token("device", false))
            }
            5 => {
                assert_eq!(target, "/nsal");
                assert!(!header.to_lowercase().contains("authorization:"));
                (200, json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                    "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}], "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]}))
            }
            6 | 9 => {
                assert_eq!(target, "/sisu");
                verify_signature(target, header, body, proof.as_ref().unwrap(), &["User-Agent"]);
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(&value["ProofKey"], proof.as_ref().unwrap());
                assert_eq!(value["AccessToken"], "t=access");
                (200, json!({"TitleToken": token("title", false), "UserToken": token("user", true),
                    "AuthorizationToken": token(if step == 6 { "default1" } else { "default2" }, true)}))
            }
            7 | 8 => {
                assert_eq!(target, "/xsts");
                verify_signature(target, header, body, proof.as_ref().unwrap(), &[]);
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value["RelyingParty"], "rp://fixture");
                assert_eq!(value["Properties"]["UserTokens"], json!(["user"]));
                (200, token(if step == 7 { "service1" } else { "service2" }, true))
            }
            _ => panic!("unexpected authentication request"),
        }
    }, 9).await;
    let mut auth = MicrosoftAuth {
        http: Http::fixture(address),
        config: Config::default(),
    };
    let now = SystemTime::now();
    let mut attempt = auth.start(now).await.unwrap();
    assert_eq!(
        attempt.next_poll().duration_since(now).unwrap(),
        Duration::from_secs(5)
    );
    assert_eq!(attempt.user_code(), "PUBLIC");
    assert!(matches!(
        auth.poll(&mut attempt, now).await.unwrap(),
        Poll::Pending
    ));
    let due = attempt.next_poll();
    assert!(matches!(
        auth.poll(&mut attempt, due).await.unwrap(),
        Poll::Pending
    ));
    let due = attempt.next_poll();
    assert_eq!(due.duration_since(now).unwrap(), Duration::from_secs(15));
    assert!(matches!(
        auth.poll(&mut attempt, due - Duration::from_secs(1))
            .await
            .unwrap(),
        Poll::Pending
    ));
    let Poll::Authorized(credentials) = auth.poll(&mut attempt, due).await.unwrap() else {
        panic!("not authorized")
    };
    assert!(matches!(
        auth.poll(&mut attempt, due).await,
        Err(Error::DeviceCodeExpired)
    ));
    let mut account = auth.into_account(credentials).unwrap();
    let first = account.authorize("rp://fixture").await.unwrap();
    let cached = account.authorize("rp://fixture").await.unwrap();
    assert!(Arc::ptr_eq(&first, &cached));
    assert!(first.header_value().unwrap().is_sensitive());
    assert!(account.reject(&first));
    let replacement = account.authorize("rp://fixture").await.unwrap();
    assert!(!account.reject(&first));
    assert!(Arc::ptr_eq(
        &replacement,
        &account.authorize("rp://fixture").await.unwrap()
    ));
    let default = account.authorize(XBOX_RELYING_PARTY).await.unwrap();
    assert!(account.reject(&default));
    let renewed = account.authorize(XBOX_RELYING_PARTY).await.unwrap();
    assert!(!Arc::ptr_eq(&default, &renewed));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Proves an expired Microsoft token refreshes once and installs its rotated refresh token.
#[tokio::test]
async fn oauth_refresh_and_response_rejection_are_bounded_and_redacted() {
    let mut step = 0;
    let (address, server) = fixture(move |target, _, body| {
        step += 1;
        match step {
            1 => { assert_eq!(target, "/device-token"); (200, token("device", false)) }
            2 => {
                assert_eq!(target, "/oauth-token");
                let form = url::form_urlencoded::parse(body).collect::<HashMap<_, _>>();
                assert_eq!(form["grant_type"], "refresh_token");
                assert_eq!(form["refresh_token"], "old-refresh");
                (200, json!({"access_token": "renewed-access", "refresh_token": "rotated-refresh", "expires_in": "3600"}))
            }
            3 => (200, json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn", "RelyingParty": XBOX_RELYING_PARTY}], "SignaturePolicies": []})),
            4 => {
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value["AccessToken"], "t=renewed-access");
                (200, json!({"TitleToken": token("title", false), "UserToken": token("user", true), "AuthorizationToken": token("default", true)}))
            }
            5 => (200, json!({"Token": "SENSITIVE", "NotAfter": "malformed", "DisplayClaims": {"xui": [{"uhs": "SENSITIVE"}]}})),
            _ => panic!("unexpected refresh request"),
        }
    }, 5).await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "expired".into(),
        "old-refresh".into(),
        UNIX_EPOCH,
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    account.authorize(XBOX_RELYING_PARTY).await.unwrap();
    assert_eq!(account.credentials().refresh_token(), "rotated-refresh");
    let error = account.authorize("rp://fixture").await.err().unwrap();
    assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    assert!(!account.authorizations.contains_key("rp://fixture"));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
