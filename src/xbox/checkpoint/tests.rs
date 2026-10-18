use super::*;
use crate::{
    oauth::MicrosoftAuth,
    xbox::{
        XBOX_RELYING_PARTY,
        tests::{fixture, token, verify_signature},
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
