use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum Expected {
    Rejected,
    Challenge,
    Authorized,
}

/// Actual acquisition must not manufacture signup/device identity from positional JSON containers.
#[tokio::test]
async fn signup_consumed_metadata_requires_objects_while_optional_fields_remain_compatible() {
    let mut observed = Vec::new();
    for (name, claims, page, expected) in [
        (
            "array page",
            json!({"xdi":{"did":DEVICE}}),
            json!([PAGE]),
            Expected::Rejected,
        ),
        (
            "array device identity",
            json!({"xdi":[DEVICE]}),
            json!({"WebPage":PAGE}),
            Expected::Rejected,
        ),
        (
            "array display claims",
            json!([[DEVICE]]),
            json!({"WebPage":PAGE}),
            Expected::Rejected,
        ),
        (
            "objects with unused fields",
            json!({"xdi":{"did":DEVICE,"unused":[1,2]},"unused":{"any":true}}),
            json!({"WebPage":PAGE,"unused":[1,{"any":true}]}),
            Expected::Challenge,
        ),
        (
            "missing device identity",
            json!({"unused":[1,2]}),
            json!(null),
            Expected::Authorized,
        ),
        (
            "null optional device identity",
            json!({"xdi":null}),
            json!(null),
            Expected::Authorized,
        ),
    ] {
        let count = Arc::new(AtomicUsize::new(0));
        let requests = Arc::clone(&count);
        let mut proof = None;
        let (address, server) = fixture_headers(move |target, headers, body| {
            let step = requests.fetch_add(1, Ordering::SeqCst) + 1;
            match step {
                1 => {
                    assert_eq!(target, "/device-token");
                    let request: Value = serde_json::from_slice(body).unwrap();
                    let key = request["Properties"]["ProofKey"].clone();
                    verify_signature(target, headers, body, &key, &[]);
                    proof = Some(key);
                    let mut device = token("device", false);
                    device["DisplayClaims"] = claims.clone();
                    (200, token_headers(), device)
                }
                2 => {
                    assert_eq!(target, "/nsal");
                    (200, token_headers(), json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                        "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}],
                        "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]}))
                }
                3 => {
                    assert_eq!(target, "/sisu");
                    let request: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(&request["ProofKey"], proof.as_ref().unwrap());
                    verify_signature(target, headers, body, proof.as_ref().unwrap(), &["User-Agent"]);
                    if matches!(expected, Expected::Authorized) {
                        (200, token_headers(), json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                            "AuthorizationToken": token("default", true)}))
                    } else {
                        (401, vec![("Date", DATE), ("X-Err", "2148916233"), ("X-SessionId", SESSION)], page.clone())
                    }
                }
                _ => panic!("unexpected metadata-shape request"),
            }
        }, 3).await;
        let config = Config::default();
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            "access".into(),
            "refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .unwrap();
        let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            account.authorize(XBOX_RELYING_PARTY),
        )
        .await;
        drop(account);
        // Rejection may finish at the actual device response; retire its same finite server before verdict.
        server.abort();
        if let Err(error) = server.await {
            assert!(
                error.is_cancelled(),
                "original shape fixture failed: {error}"
            );
        }
        let correct = match expected {
            Expected::Rejected => matches!(&result, Ok(Err(Error::Invalid(_)))),
            Expected::Challenge => matches!(&result, Ok(Err(Error::AccountCreationRequired(_)))),
            Expected::Authorized => {
                matches!(&result, Ok(Ok(authorization)) if authorization.xuid() == "123")
            }
        };
        observed.push((name, correct, count.load(Ordering::SeqCst)));
    }
    assert!(
        observed.iter().all(|(_, correct, _)| *correct),
        "consumed signup metadata accepted positional containers or rejected compatible objects: {observed:?}"
    );
}
