use super::*;
use crate::{
    oauth::MicrosoftAuth,
    xbox::{
        XBOX_RELYING_PARTY,
        test_support::{fixture, token, verify_signature},
    },
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc, time::Duration};

/// Exercises a restart after warm caches, retaining proof ownership through refresh rotation.
#[tokio::test]
async fn restart_reuses_proof_and_refreshes_credentials_before_rebuilding_caches() {
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture(
        move |target, header, body| {
            step += 1;
            match step {
                1 | 5 | 10 => {
                    assert_eq!(target, "/device-token");
                    let value: Value = serde_json::from_slice(body).unwrap();
                    let received = value["Properties"]["ProofKey"].clone();
                    if let Some(proof) = &proof {
                        assert_eq!(&received, proof);
                    } else {
                        proof = Some(received.clone());
                    }
                    verify_signature(target, header, body, &received, &[]);
                    (200, token("device", false))
                }
                2 | 7 => {
                    assert_eq!(target, "/nsal");
                    (
                        200,
                        json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                            "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}],
                            "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]}),
                    )
                }
                3 | 8 => {
                    assert_eq!(target, "/sisu");
                    let value: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(&value["ProofKey"], proof.as_ref().unwrap());
                    assert_eq!(
                        value["AccessToken"],
                        if step == 3 {
                            "t=access-before"
                        } else {
                            "t=access-after"
                        }
                    );
                    verify_signature(target, header, body, proof.as_ref().unwrap(), &["User-Agent"]);
                    (
                        200,
                        json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                            "AuthorizationToken": token("default", true)}),
                    )
                }
                4 | 9 => {
                    assert_eq!(target, "/xsts");
                    verify_signature(target, header, body, proof.as_ref().unwrap(), &[]);
                    let value: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(value["RelyingParty"], "rp://fixture");
                    (200, token(if step == 4 { "before" } else { "after" }, true))
                }
                6 | 11 => {
                    assert_eq!(target, "/oauth-token");
                    let form = url::form_urlencoded::parse(body).collect::<HashMap<_, _>>();
                    assert_eq!(form["grant_type"], "refresh_token");
                    assert_eq!(
                        form["refresh_token"],
                        if step == 6 {
                            "refresh-before"
                        } else {
                            "refresh-after"
                        }
                    );
                    assert_eq!(form["scope"], crate::oauth::SCOPE);
                    if step == 11 {
                        return (
                            400,
                            json!({"error": "invalid_grant", "error_description": "SENSITIVE-account"}),
                        );
                    }
                    (
                        200,
                        json!({"access_token": "access-after", "refresh_token": "refresh-after", "expires_in": 3600}),
                    )
                }
                _ => panic!("unexpected restart request"),
            }
        },
        11,
    )
    .await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access-before".into(),
        "refresh-before".into(),
        std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config.clone(), credentials).unwrap();
    let before = account.authorize("rp://fixture").await.unwrap();
    let checkpoint = account.checkpoint().unwrap();
    let saved = Zeroizing::new(checkpoint.as_bytes().to_vec());
    drop(checkpoint);
    drop(account);

    let auth = MicrosoftAuth {
        http: Http::fixture(address),
        config,
    };
    let mut restored = auth
        .restore_account(Checkpoint::from_bytes(saved).unwrap())
        .unwrap();
    let after = restored.authorize("rp://fixture").await.unwrap();
    assert!(!Arc::ptr_eq(&before, &after));
    assert_eq!(restored.credentials().refresh_token(), "refresh-after");
    assert!(!restored.reject(&before));
    assert!(Arc::ptr_eq(
        &after,
        &restored.authorize("rp://fixture").await.unwrap()
    ));
    let checkpoint = restored.checkpoint().unwrap();
    let auth = MicrosoftAuth {
        http: Http::fixture(address),
        config: Config::default(),
    };
    let mut next = auth.restore_account(checkpoint).unwrap();
    assert_eq!(next.credentials().refresh_token(), "refresh-after");
    assert_eq!(
        next.key.verifying_key().to_sec1_point(false),
        restored.key.verifying_key().to_sec1_point(false)
    );
    let error = next.authorize("rp://fixture").await.err().unwrap();
    assert!(matches!(error, Error::SignInRequired));
    assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Rejects policy substitution, malformed encoding and unusable proof/refresh ownership.
#[test]
fn checkpoint_import_is_bounded_and_policy_bound() {
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        String::new(),
        "SENSITIVE-refresh".into(),
        std::time::UNIX_EPOCH,
    )
    .unwrap();
    let account = MicrosoftAuth::new(config.clone())
        .unwrap()
        .into_account(credentials)
        .unwrap();
    let checkpoint = account.checkpoint().unwrap();
    let bytes = checkpoint.as_bytes();
    for end in 0..bytes.len() {
        assert!(Checkpoint::from_bytes(Zeroizing::new(bytes[..end].to_vec())).is_err());
    }
    let changes: [fn(&mut Config); 5] = [
        |config| config.client_id.push('x'),
        |config| config.user_agent.push('x'),
        |config| config.device_version.push('x'),
        |config| config.sandbox.push('x'),
        |config| config.device = Device::Win32,
    ];
    for change in changes {
        let mut changed = config.clone();
        change(&mut changed);
        let auth = MicrosoftAuth::new(changed).unwrap();
        let checkpoint = Checkpoint::from_bytes(Zeroizing::new(bytes.to_vec())).unwrap();
        let error = auth.restore_account(checkpoint).err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    let mut changed_scope = Zeroizing::new(bytes.to_vec());
    let scope = changed_scope
        .windows(crate::oauth::SCOPE.len())
        .position(|value| value == crate::oauth::SCOPE.as_bytes())
        .unwrap();
    changed_scope[scope] = b'x';
    let auth = MicrosoftAuth::new(config.clone()).unwrap();
    assert!(
        auth.restore_account(Checkpoint::from_bytes(changed_scope).unwrap())
            .is_err()
    );
    let mut malformed = Zeroizing::new(bytes.to_vec());
    malformed.push(0);
    assert!(Checkpoint::from_bytes(malformed).is_err());
    let mut malformed = Zeroizing::new(bytes.to_vec());
    malformed[PREFIX.len() - 1] = 0xff;
    assert!(Checkpoint::from_bytes(malformed).is_err());
    let mut malformed = Zeroizing::new(bytes.to_vec());
    malformed[PREFIX.len() + 1..PREFIX.len() + 5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Checkpoint::from_bytes(malformed).is_err());
    let mut malformed = Zeroizing::new(bytes.to_vec());
    *malformed.last_mut().unwrap() = 0xff;
    assert!(Checkpoint::from_bytes(malformed).is_err());
    assert!(Checkpoint::from_bytes(Zeroizing::new(vec![0; MAX_CHECKPOINT_BYTES + 1])).is_err());

    let mut empty_refresh = Zeroizing::new(bytes.to_vec());
    let refresh_start = bytes.len() - account.credentials().refresh_token().len();
    empty_refresh[refresh_start - 4..refresh_start].copy_from_slice(&0_u32.to_le_bytes());
    empty_refresh.truncate(refresh_start);
    assert!(Checkpoint::from_bytes(empty_refresh).is_err());

    let mut invalid_key = Zeroizing::new(bytes.to_vec());
    let proof_start = bytes.len() - (4 + account.credentials().refresh_token().len() + PROOF_BYTES);
    invalid_key[proof_start..proof_start + PROOF_BYTES].fill(0);
    let auth = MicrosoftAuth::new(config.clone()).unwrap();
    assert!(
        auth.restore_account(Checkpoint::from_bytes(invalid_key).unwrap())
            .is_err()
    );
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access-only".into(),
        String::new(),
        std::time::UNIX_EPOCH,
    )
    .unwrap();
    let account = MicrosoftAuth::new(config.clone())
        .unwrap()
        .into_account(credentials)
        .unwrap();
    assert!(matches!(account.checkpoint(), Err(Error::SignInRequired)));

    let mut large = config.clone();
    large.device_version = "x".repeat(MAX_CHECKPOINT_BYTES);
    let credentials = Credentials::from_tokens(
        large.client_id.clone(),
        String::new(),
        "refresh".into(),
        std::time::UNIX_EPOCH,
    )
    .unwrap();
    let account = MicrosoftAuth::new(large)
        .unwrap()
        .into_account(credentials)
        .unwrap();
    assert!(account.checkpoint().is_err());
}

const CACHE_DATE: &str = "Tue, 14 Nov 2023 22:13:20 GMT";

/// Supplies the same concrete public policy used by the account acquisition fixtures.
fn cache_policy() -> Value {
    json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
        "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}],
        "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]})
}

/// Acquires original synthetic cache entries through signed HTTP with an explicit service Date.
async fn calibrated_account(value: String) -> (Account, Arc<super::super::Authorization>) {
    use crate::xbox::test_support::fixture_headers;
    let mut proof = None;
    let (address, server) = fixture_headers(
        move |target, header, body| {
            let response = match target {
                "/device-token" => {
                    let request: Value = serde_json::from_slice(body).unwrap();
                    proof = Some(request["Properties"]["ProofKey"].clone());
                    verify_signature(target, header, body, proof.as_ref().unwrap(), &[]);
                    token("device", false)
                }
                "/nsal" => cache_policy(),
                "/sisu" => {
                    let request: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(request["ProofKey"], *proof.as_ref().unwrap());
                    verify_signature(
                        target,
                        header,
                        body,
                        proof.as_ref().unwrap(),
                        &["User-Agent"],
                    );
                    json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                        "AuthorizationToken": token("default", true)})
                }
                "/xsts" => {
                    verify_signature(target, header, body, proof.as_ref().unwrap(), &[]);
                    token(&value, true)
                }
                _ => panic!("unexpected calibrated-cache request"),
            };
            (200, vec![("Date", CACHE_DATE)], response)
        },
        4,
    )
    .await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let issued = account.authorize("rp://fixture").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    (account, issued)
}

/// Reuses proof-bound issuances after fresh policy/time, persists eviction and keeps hard expiry.
#[tokio::test]
async fn calibrated_restart_reuses_issuances_without_resurrecting_rejection_or_expiry() {
    use crate::xbox::test_support::fixture_headers;
    let (account, issued) = calibrated_account("original".into()).await;
    let proof = account.key.verifying_key().to_sec1_point(false);
    let checkpoint = account.checkpoint().unwrap();
    assert!(checkpoint.as_bytes().starts_with(CACHED_PREFIX));
    for end in 0..checkpoint.as_bytes().len() {
        assert!(
            Checkpoint::from_bytes(Zeroizing::new(checkpoint.as_bytes()[..end].to_vec())).is_err()
        );
    }
    let original_expiry = issued.token.expires;
    let original_access_expiry = account.credentials().expires_at();
    let mut step = 0;
    let (address, server) = fixture_headers(
        move |target, _, body| {
            step += 1;
            match step {
                1 | 3 => {
                    assert_eq!(target, "/nsal");
                    (200, vec![("Date", CACHE_DATE)], cache_policy())
                }
                2 => {
                    assert_eq!(target, "/sisu");
                    let request: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(request["AccessToken"], "t=access");
                    (
                        200,
                        vec![("Date", CACHE_DATE)],
                        json!({
                            "TitleToken": token("title", false), "UserToken": token("user", false),
                            "AuthorizationToken": token("renewed-default", true)
                        }),
                    )
                }
                4 => {
                    assert_eq!(target, "/xsts");
                    let request: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(request["Properties"]["DeviceToken"], "device");
                    assert_eq!(request["Properties"]["TitleToken"], "title");
                    assert_eq!(request["Properties"]["UserTokens"], json!(["user"]));
                    (200, vec![("Date", CACHE_DATE)], token("replacement", true))
                }
                5 => {
                    assert_eq!(target, "/nsal");
                    (
                        200,
                        vec![("Date", "Fri, 02 Jan 2099 00:00:00 GMT")],
                        cache_policy(),
                    )
                }
                6 => {
                    assert_eq!(target, "/device-token");
                    (401, vec![], json!({}))
                }
                _ => panic!("unexpected restart or eviction request"),
            }
        },
        6,
    )
    .await;
    let restore = |checkpoint| {
        Account::restore(Http::fixture(address), Config::default(), checkpoint).unwrap()
    };
    let mut restored = restore(checkpoint);
    restored
        .replace_credentials(
            Credentials::from_tokens(
                Config::default().client_id,
                "access".into(),
                "refresh".into(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
            )
            .unwrap(),
        )
        .unwrap();
    let reused = restored.authorize("rp://fixture").await.unwrap();
    assert_eq!(
        reused.header_value().unwrap(),
        issued.header_value().unwrap()
    );
    assert_eq!(reused.token.expires, original_expiry);
    assert_eq!(restored.credentials().expires_at(), original_access_expiry);
    let default = restored.authorize(XBOX_RELYING_PARTY).await.unwrap();
    assert!(restored.reject(&default));
    // Rebuilding SISU may use admitted access, preserving its original deadline without OAuth refresh.
    restored.authorize(XBOX_RELYING_PARTY).await.unwrap();
    assert_eq!(restored.credentials().expires_at(), original_access_expiry);
    assert_eq!(restored.key.verifying_key().to_sec1_point(false), proof);
    assert!(!restored.reject(&issued));
    assert!(restored.reject(&reused));
    let mut next = restore(restored.checkpoint().unwrap());
    let replacement = next.authorize("rp://fixture").await.unwrap();
    assert_ne!(
        replacement.header_value().unwrap(),
        reused.header_value().unwrap()
    );
    assert!(!next.reject(&reused));
    assert!(Arc::ptr_eq(
        &replacement,
        &next.authorize("rp://fixture").await.unwrap()
    ));
    let mut expired = restore(next.checkpoint().unwrap());
    assert!(matches!(
        expired.authorize("rp://fixture").await,
        Err(Error::Status { .. })
    ));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Rejected, malformed, absent and rolled-back clocks also keep saved OAuth access dormant.
#[tokio::test]
async fn restored_cache_requires_date_on_the_successful_decoded_policy_response() {
    use crate::xbox::test_support::fixture_headers;
    let (account, issued) = calibrated_account("original".into()).await;
    let checkpoint = account.checkpoint().unwrap();
    for case in 0..5 {
        let proof = account.proof_key();
        let mut step = 0;
        let (address, server) = fixture_headers(
            move |target, header, body| {
                step += 1;
                if step == 1 {
                    assert_eq!(target, "/nsal");
                    return match case {
                        0 => (401, vec![("Date", CACHE_DATE)], cache_policy()),
                        1 => (200, vec![("Date", CACHE_DATE)], json!({"EndPoints": 42})),
                        2 => (200, vec![], cache_policy()),
                        3 => (200, vec![("Date", "invalid")], cache_policy()),
                        4 => (
                            200,
                            vec![("Date", "Tue, 14 Nov 2023 22:13:19 GMT")],
                            cache_policy(),
                        ),
                        _ => unreachable!(),
                    };
                }
                if case < 2 {
                    assert_eq!(target, "/nsal");
                    return (200, vec![("Date", CACHE_DATE)], cache_policy());
                }
                match step {
                    2 => {
                        assert_eq!(target, "/device-token");
                        let request: Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(request["Properties"]["ProofKey"], proof);
                        verify_signature(target, header, body, &proof, &[]);
                        // No fresh Date here can accidentally qualify the saved access.
                        (200, vec![], token("fresh-device", false))
                    }
                    3 => {
                        assert_eq!(target, "/oauth-token", "saved access must refresh after failed time admission");
                        let form = url::form_urlencoded::parse(body).collect::<HashMap<_, _>>();
                        assert_eq!(form["grant_type"], "refresh_token");
                        assert_eq!(form["refresh_token"], "refresh");
                        (200, vec![("Date", CACHE_DATE)], json!({
                            "access_token": "fresh-access", "refresh_token": "rotated-refresh", "expires_in": 3600
                        }))
                    }
                    4 => {
                        assert_eq!(target, "/sisu");
                        let request: Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(request["AccessToken"], "t=fresh-access");
                        assert_eq!(request["ProofKey"], proof);
                        assert_eq!(request["DeviceToken"], "fresh-device");
                        verify_signature(target, header, body, &proof, &["User-Agent"]);
                        (200, vec![("Date", CACHE_DATE)], json!({
                            "TitleToken": token("fresh-title", false), "UserToken": token("fresh-user", false),
                            "AuthorizationToken": token("fresh-default", true)
                        }))
                    }
                    5 => {
                        assert_eq!(target, "/xsts");
                        let request: Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(request["Properties"]["TitleToken"], "fresh-title");
                        assert_eq!(request["Properties"]["UserTokens"], json!(["fresh-user"]));
                        verify_signature(target, header, body, &proof, &[]);
                        (200, vec![("Date", CACHE_DATE)], token("fresh-issuance", true))
                    }
                    _ => panic!("unexpected unqualified-access continuation"),
                }
            },
            if case < 2 { 2 } else { 5 },
        )
        .await;
        let saved = Checkpoint::from_bytes(Zeroizing::new(checkpoint.as_bytes().to_vec())).unwrap();
        let mut restored =
            Account::restore(Http::fixture(address), Config::default(), saved).unwrap();
        // Identical leased material must retain restored access dormancy.
        restored
            .replace_credentials(
                Credentials::from_tokens(
                    Config::default().client_id,
                    account.credentials().access_token().into(),
                    account.credentials().refresh_token().into(),
                    account.credentials().expires_at(),
                )
                .unwrap(),
            )
            .unwrap();
        if case < 2 {
            assert!(restored.authorize("rp://fixture").await.is_err());
            assert!(restored.authorize("rp://fixture").await.is_err());
            restored.advance_fixture_time(Duration::from_secs(16));
            assert_eq!(
                restored
                    .authorize("rp://fixture")
                    .await
                    .unwrap()
                    .header_value()
                    .unwrap(),
                issued.header_value().unwrap()
            );
        } else {
            let acquired = restored.authorize("rp://fixture").await.unwrap();
            assert_ne!(
                acquired.header_value().unwrap(),
                issued.header_value().unwrap()
            );
            assert_eq!(restored.credentials().access_token(), "fresh-access");
            assert_eq!(restored.credentials().refresh_token(), "rotated-refresh");
            assert_eq!(
                restored.key.verifying_key().to_sec1_point(false),
                account.key.verifying_key().to_sec1_point(false)
            );
        }
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}

/// Credential changes invalidate saved issuances, while cache growth cannot block refresh durability.
#[tokio::test]
async fn changed_material_and_oversized_cache_preserve_only_authoritative_restart_state() {
    let (mut account, _) = calibrated_account("original".into()).await;
    let checkpoint = account.checkpoint().unwrap();
    let (address, server) = fixture(
        |target, _, _| {
            assert_eq!(target, "/device-token");
            (401, json!({}))
        },
        1,
    )
    .await;
    account = Account::restore(Http::fixture(address), Config::default(), checkpoint).unwrap();
    account
        .replace_credentials(
            Credentials::from_tokens(
                Config::default().client_id,
                "new-access".into(),
                "rotated-refresh".into(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_001),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(account.authorize("rp://fixture").await.is_err());
    let checkpoint = account.checkpoint().unwrap();
    let contents = Contents::parse(checkpoint.as_bytes()).unwrap();
    assert_eq!(contents.refresh, "rotated-refresh");
    assert!(contents.derived.is_none());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();

    let (large, _) = calibrated_account("x".repeat(MAX_CHECKPOINT_BYTES)).await;
    let checkpoint = large.checkpoint().unwrap();
    assert!(checkpoint.as_bytes().starts_with(PREFIX));
    let restored = Account::restore(Http::fixture(address), Config::default(), checkpoint).unwrap();
    assert_eq!(
        restored.credentials().refresh_token(),
        large.credentials().refresh_token()
    );
    assert_eq!(
        restored.key.verifying_key().to_sec1_point(false),
        large.key.verifying_key().to_sec1_point(false)
    );
}

/// Cancellation before public policy completes retains dormant bytes for a later bounded attempt.
#[tokio::test]
async fn cancelled_policy_fetch_retains_the_original_dormant_checkpoint() {
    use crate::xbox::test_support::fixture_headers;
    use tokio::{io::AsyncReadExt, net::TcpListener, sync::oneshot};
    let (account, issued) = calibrated_account("original".into()).await;
    let checkpoint = account.checkpoint().unwrap();
    let saved = Zeroizing::new(checkpoint.as_bytes().to_vec());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted, received) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            assert!(request.len() < 16 * 1024);
            assert_ne!(stream.read_buf(&mut request).await.unwrap(), 0);
        }
        assert!(request.starts_with(b"GET /nsal "));
        accepted.send(()).unwrap();
        released.await.unwrap();
    });
    let mut restored =
        Account::restore(Http::fixture(address), Config::default(), checkpoint).unwrap();
    {
        let mut request = Box::pin(restored.authorize("rp://fixture"));
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut request => panic!("policy unexpectedly completed: {}", result.is_ok()),
                result = received => result.unwrap(),
            }
        }).await.unwrap();
    }
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    let checkpoint = restored.checkpoint().unwrap();
    assert_eq!(checkpoint.as_bytes(), saved.as_slice());
    let (address, server) = fixture_headers(
        |target, _, _| {
            assert_eq!(target, "/nsal");
            (200, vec![("Date", CACHE_DATE)], cache_policy())
        },
        1,
    )
    .await;
    let mut next = Account::restore(Http::fixture(address), Config::default(), checkpoint).unwrap();
    assert_eq!(
        next.authorize("rp://fixture")
            .await
            .unwrap()
            .header_value()
            .unwrap(),
        issued.header_value().unwrap()
    );
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
