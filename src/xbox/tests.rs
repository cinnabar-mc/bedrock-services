use super::*;
use crate::oauth::{MicrosoftAuth, Poll};
use serde_json::Value;
use std::time::UNIX_EPOCH;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// Serves a bounded sequence of synthetic HTTP exchanges on an ephemeral loopback port.
async fn fixture(
    mut handler: impl FnMut(&str, &str, &[u8]) -> (u16, Value) + Send + 'static,
    count: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let (header_end, length) = loop {
                assert!(bytes.len() <= 1024 * 1024);
                assert_ne!(stream.read_buf(&mut bytes).await.unwrap(), 0);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let header = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length = header
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
                    break (end + 4, length);
                }
            };
            while bytes.len() < header_end + length {
                assert_ne!(stream.read_buf(&mut bytes).await.unwrap(), 0);
            }
            let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let target = header
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let (status, body) = handler(target, header, &bytes[header_end..header_end + length]);
            let body = serde_json::to_vec(&body).unwrap();
            let header = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    (address, task)
}

/// Produces original credentials with deliberately distant expiry and no account data.
fn token(value: &str, user: bool) -> Value {
    json!({"Token": value, "NotAfter": "2099-01-01T00:00:00Z",
        "DisplayClaims": if user { json!({"xui": [{"uhs": "synthetic", "xid": "123", "gtg": "Fixture"}]}) }
            else { json!({}) }})
}

/// Checks proof-key continuity, request signatures and the whole local authentication chain.
#[tokio::test]
async fn device_flow_caches_credentials_and_fences_stale_rejections() {
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture(move |target, header, body| {
        step += 1;
        match step {
            1 => {
                assert_eq!(target, "/device-code");
                assert!(std::str::from_utf8(body).unwrap().contains("response_type=device_code"));
                (200, json!({"device_code": "private-device", "user_code": "PUBLIC", "verification_uri": "https://login.live.com/device",
                    "expires_in": 900, "interval": 5}))
            }
            2 => { assert_eq!(target, "/oauth-token"); (400, json!({"error": "slow_down"})) }
            3 => { assert_eq!(target, "/oauth-token"); (200, json!({"access_token": "access", "refresh_token": "refresh", "expires_in": 3600})) }
            4 => {
                assert_eq!(target, "/device-token");
                let value: Value = serde_json::from_slice(body).unwrap();
                let key = value["Properties"]["ProofKey"].clone();
                verify_signature(target, header, body, &key);
                assert_eq!(value["Properties"]["DeviceType"], "Android");
                proof = Some(key);
                (200, token("device", false))
            }
            5 => {
                assert_eq!(target, "/nsal");
                assert!(!header.to_lowercase().contains("authorization:"));
                (200, json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                    "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}], "SignaturePolicies": [{"Version": 1}]}))
            }
            6 | 9 => {
                assert_eq!(target, "/sisu");
                verify_signature(target, header, body, proof.as_ref().unwrap());
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(&value["ProofKey"], proof.as_ref().unwrap());
                assert_eq!(value["AccessToken"], "t=access");
                (200, json!({"TitleToken": token("title", false), "UserToken": token("user", true),
                    "AuthorizationToken": token(if step == 6 { "default1" } else { "default2" }, true)}))
            }
            7 | 8 => {
                assert_eq!(target, "/xsts");
                verify_signature(target, header, body, proof.as_ref().unwrap());
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

/// Validates a signature independently from the production request/digest helpers.
fn verify_signature(target: &str, header: &str, body: &[u8], key: &Value) {
    use base64::engine::general_purpose::STANDARD;
    use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    use sha2::{Digest, Sha256};
    let value = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("signature"))
        .unwrap()
        .1
        .trim();
    let signature = STANDARD.decode(value).unwrap();
    assert_eq!(signature.len(), 76);
    assert_eq!(&signature[..4], &1_u32.to_be_bytes());
    let mut hash = Sha256::new();
    for field in [
        &signature[..4],
        &signature[4..12],
        b"POST",
        target.as_bytes(),
        b"",
        body,
    ] {
        hash.update(field);
        hash.update([0]);
    }
    let mut point = vec![4];
    point.extend(URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(key["y"].as_str().unwrap()).unwrap());
    let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
    key.verify_prehash(
        &hash.finalize(),
        &Signature::from_slice(&signature[12..]).unwrap(),
    )
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
