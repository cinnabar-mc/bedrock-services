use super::*;
use crate::{
    http::Http,
    oauth::{Credentials, MicrosoftAuth},
    xbox::{
        Account, Authorization, Config, XBOX_RELYING_PARTY,
        test_support::{fixture_headers, token, verify_signature},
    },
};
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

const SESSION: &str = "fixture session+id";
const DEVICE: &str = "1234abcd";
const PAGE: &str =
    "https://sisu.xboxlive.com/signup?keep=first&keep=second&sig=old&did=old&sid=old&redirect=old";
const DATE: &str = "Wed, 01 Jan 2025 00:00:00 GMT";

/// Returns only the actual typed challenge; an unexpected authorization cannot substitute for it.
fn challenge(
    result: Result<Arc<Authorization>, Error>,
) -> Result<AccountCreationRequired, &'static str> {
    match result {
        Err(Error::AccountCreationRequired(challenge)) => Ok(challenge),
        _ => Err("SISU did not return the actual signup challenge"),
    }
}

/// Checks same-account signing, retry and restored device metadata through real bounded HTTP exchanges.
#[tokio::test]
async fn signup_keeps_the_original_proof_device_and_restored_account() {
    let proof = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&proof);
    let mut step = 0;
    let (address, server) = fixture_headers(move |target, headers, body| {
        step += 1;
        match step {
            1 => {
                assert_eq!(target, "/device-token");
                let request: Value = serde_json::from_slice(body).unwrap();
                let key = request["Properties"]["ProofKey"].clone();
                verify_signature(target, headers, body, &key, &[]);
                *observed.lock().unwrap() = Some(key);
                let mut device = token("device", false);
                device["DisplayClaims"]["xdi"] = json!({"did": DEVICE});
                (200, token_headers(), device)
            }
            2 | 5 => {
                assert_eq!(target, "/nsal");
                (200, token_headers(), json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                    "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}],
                    "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]}))
            }
            3 | 4 | 6 | 7 => {
                assert_eq!(target, "/sisu");
                let request: Value = serde_json::from_slice(body).unwrap();
                let proof = observed.lock().unwrap();
                let proof = proof.as_ref().unwrap();
                assert_eq!(&request["ProofKey"], proof);
                assert_eq!(request["DeviceToken"], "device");
                assert_eq!(request["AccessToken"], "t=access");
                verify_signature(target, headers, body, proof, &["User-Agent"]);
                if step == 7 {
                    (200, token_headers(), json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                        "AuthorizationToken": token("default", true)}))
                } else {
                    (401, vec![("Date", DATE), ("X-Err", "2148916233"), ("X-SessionId", SESSION)], json!({"WebPage": PAGE}))
                }
            }
            _ => panic!("unexpected signup acquisition request"),
        }
    }, 7).await;
    let run = async {
        let config = Config::default();
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            "access".into(),
            "refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .map_err(|_| "credentials")?;
        let mut account = Account::new(Http::fixture(address), config.clone(), credentials)
            .map_err(|_| "account")?;
        let first = challenge(account.authorize(XBOX_RELYING_PARTY).await)?;
        let second = challenge(account.authorize(XBOX_RELYING_PARTY).await)?;
        let checkpoint = account.checkpoint().map_err(|_| "checkpoint")?;
        drop(account);
        let auth = MicrosoftAuth {
            http: Http::fixture(address),
            config,
        };
        let mut restored = auth.restore_account(checkpoint).map_err(|_| "restore")?;
        let third = challenge(restored.authorize(XBOX_RELYING_PARTY).await)?;
        let authorized = restored
            .authorize(XBOX_RELYING_PARTY)
            .await
            .map_err(|_| "authorization after signup")?;
        Ok::<_, &'static str>(([first, second, third], authorized.xuid().to_owned()))
    };
    let result = tokio::time::timeout(Duration::from_secs(5), run).await;
    if !matches!(&result, Ok(Ok(_))) {
        server.abort();
    }
    let served = server.await;
    let (challenges, xuid) = result
        .expect("finite signup fixture")
        .expect("original signup owner");
    served.unwrap();
    assert_eq!(xuid, "123");
    let proof = proof.lock().unwrap();
    for value in challenges {
        let diagnostic = format!("{value:?} {value}");
        assert!(!diagnostic.contains("signup?"));
        let url = Url::parse(value.signup_url()).unwrap();
        let values = url.query_pairs().fold(
            BTreeMap::<String, Vec<String>>::new(),
            |mut values, (name, value)| {
                values
                    .entry(name.into_owned())
                    .or_default()
                    .push(value.into_owned());
                values
            },
        );
        assert_eq!(values["keep"], ["first", "second"]);
        assert_eq!(values["sid"], [SESSION]);
        assert_eq!(values["did"], [format!("0x{DEVICE}")]);
        assert_eq!(
            values["redirect"],
            [format!("{SISU_ORIGIN}/sisu_desktop.srf")]
        );
        assert_eq!(values["sig"].len(), 1);
        verify_signature(
            "/proxy?sessionid=fixture+session%2Bid",
            &format!("signature: {}", values["sig"][0]),
            b"",
            proof.as_ref().unwrap(),
            &[],
        );
    }
}

/// Supplies the same public response-clock sample for original and restored acquisition.
fn token_headers() -> Vec<(&'static str, &'static str)> {
    vec![("Date", DATE)]
}

/// Missing device/session and unusable pages never become a browser authentication capability.
#[test]
fn incomplete_or_insecure_signup_metadata_remains_a_redacted_failure() {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    for (session, device, page) in [
        (None, Some(DEVICE), PAGE),
        (Some(SESSION), None, PAGE),
        (Some(SESSION), Some(DEVICE), "http://example.test/signup"),
        (
            Some(SESSION),
            Some(DEVICE),
            "https://user:private@example.test/signup",
        ),
        (Some(SESSION), Some(DEVICE), ""),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("x-err", "2148916233".parse().unwrap());
        if let Some(session) = session {
            headers.insert("x-sessionid", session.parse().unwrap());
        }
        let response = Response {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Zeroizing::new(serde_json::to_vec(&json!({"WebPage": page})).unwrap()),
        };
        let error = check(&response, device, &key, UNIX_EPOCH).unwrap_err();
        assert!(!matches!(error, Error::AccountCreationRequired(_)));
        assert!(!format!("{error:?} {error}").contains("private"));
    }
}

/// Migrates only a recognized challenge from a real old cache, then signs its matching fresh session.
#[tokio::test]
async fn old_cached_device_migrates_once_without_replacing_the_proof_or_oauth_flow() {
    const OLD_SESSION: &str = "old fixture session";
    let proof = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&proof);
    let mut step = 0;
    let (address, server) = fixture_headers(move |target, headers, body| {
        step += 1;
        match step {
            1 | 6 => {
                assert_eq!(target, "/device-token");
                let request: Value = serde_json::from_slice(body).unwrap();
                let key = &request["Properties"]["ProofKey"];
                verify_signature(target, headers, body, key, &[]);
                let mut proof = observed.lock().unwrap();
                if let Some(original) = proof.as_ref() {
                    assert_eq!(key, original);
                } else {
                    *proof = Some(key.clone());
                }
                let mut device = token(if step == 1 { "old-device" } else { "new-device" }, false);
                if step == 6 {
                    device["DisplayClaims"]["xdi"] = json!({"did": DEVICE});
                }
                (200, token_headers(), device)
            }
            2 | 4 => {
                assert_eq!(target, "/nsal");
                (200, token_headers(), json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                    "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}],
                    "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]}))
            }
            3 | 5 | 7 | 8 => {
                assert_eq!(target, "/sisu");
                let request: Value = serde_json::from_slice(body).unwrap();
                let proof = observed.lock().unwrap();
                let proof = proof.as_ref().unwrap();
                assert_eq!(&request["ProofKey"], proof);
                assert_eq!(request["AccessToken"], "t=access");
                assert_eq!(request["DeviceToken"], if step < 6 { "old-device" } else { "new-device" });
                verify_signature(target, headers, body, proof, &["User-Agent"]);
                match step {
                    3 => (401, vec![("Date", DATE), ("X-Err", "2148916238")], json!({})),
                    5 => (401, vec![("Date", DATE), ("X-Err", "2148916233"), ("X-SessionId", OLD_SESSION)], json!({"WebPage": PAGE})),
                    7 => (401, vec![("Date", DATE), ("X-Err", "2148916233"), ("X-SessionId", SESSION)], json!({"WebPage": PAGE})),
                    8 => (200, token_headers(), json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                        "AuthorizationToken": token("default", true)})),
                    _ => unreachable!(),
                }
            }
            _ => panic!("unexpected legacy signup migration request"),
        }
    }, 8).await;
    let run = async {
        let config = Config::default();
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            "access".into(),
            "refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .map_err(|_| "credentials")?;
        let mut account = Account::new(Http::fixture(address), config.clone(), credentials)
            .map_err(|_| "account")?;
        if !matches!(
            account.authorize(XBOX_RELYING_PARTY).await,
            Err(Error::Status {
                xerr: Some(2148916238),
                ..
            })
        ) {
            return Err("ordinary SISU failure was retried or changed");
        }
        let checkpoint = account.checkpoint().map_err(|_| "checkpoint")?;
        if !checkpoint.as_bytes().starts_with(b"BSAC\x02") {
            return Err("fixture did not create the original no-device-ID cache format");
        }
        drop(account);
        let auth = MicrosoftAuth {
            http: Http::fixture(address),
            config,
        };
        let mut restored = auth.restore_account(checkpoint).map_err(|_| "restore")?;
        let signup = challenge(restored.authorize(XBOX_RELYING_PARTY).await)?;
        let authorized = restored
            .authorize(XBOX_RELYING_PARTY)
            .await
            .map_err(|_| "authorization after signup")?;
        Ok::<_, &'static str>((signup, authorized.xuid().to_owned()))
    };
    let result = tokio::time::timeout(Duration::from_secs(5), run).await;
    if !matches!(&result, Ok(Ok(_))) {
        server.abort();
    }
    let served = server.await;
    let (signup, xuid) = result
        .expect("finite legacy signup fixture")
        .expect("same-account migration");
    served.unwrap();
    assert_eq!(xuid, "123");
    let url = Url::parse(signup.signup_url()).unwrap();
    let query = url.query_pairs().collect::<BTreeMap<_, _>>();
    assert_eq!(query["sid"], SESSION);
    assert_eq!(query["did"], format!("0x{DEVICE}"));
    assert!(!signup.signup_url().contains("old+fixture+session"));
    verify_signature(
        "/proxy?sessionid=fixture+session%2Bid",
        &format!("signature: {}", query["sig"]),
        b"",
        proof.lock().unwrap().as_ref().unwrap(),
        &[],
    );
}

/// Canceling an actual SISU request keeps installed proof/device state for the caller's next attempt.
#[tokio::test]
async fn canceled_signup_request_keeps_the_original_account_and_installed_device() {
    use crate::xbox::test_support::{read_request, write_response};
    use tokio::{net::TcpListener, sync::oneshot};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen_tx, seen_rx) = oneshot::channel();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let mut seen_tx = Some(seen_tx);
    let mut cancel_rx = Some(cancel_rx);
    let proof = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&proof);
    let server = tokio::spawn(async move {
        for step in 1..=5 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (bytes, header_end, length) = read_request(&mut stream).await;
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let target = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let body = &bytes[header_end..header_end + length];
            let (status, response_headers, response) = match step {
                1 => {
                    assert_eq!(target, "/device-token");
                    let request: Value = serde_json::from_slice(body).unwrap();
                    let key = request["Properties"]["ProofKey"].clone();
                    verify_signature(target, headers, body, &key, &[]);
                    *observed.lock().unwrap() = Some(key);
                    let mut device = token("device", false);
                    device["DisplayClaims"]["xdi"] = json!({"did": DEVICE});
                    (200, token_headers(), device)
                }
                2 => {
                    assert_eq!(target, "/nsal");
                    (
                        200,
                        token_headers(),
                        json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                        "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}],
                        "SignaturePolicies": [{"Version": 1, "ExtraHeaders": ["User-Agent"]}]}),
                    )
                }
                3..=5 => {
                    assert_eq!(target, "/sisu");
                    let request: Value = serde_json::from_slice(body).unwrap();
                    {
                        let proof = observed.lock().unwrap();
                        let proof = proof.as_ref().unwrap();
                        assert_eq!(&request["ProofKey"], proof);
                        assert_eq!(request["DeviceToken"], "device");
                        assert_eq!(request["AccessToken"], "t=access");
                        verify_signature(target, headers, body, proof, &["User-Agent"]);
                    }
                    if step == 3 {
                        seen_tx.take().unwrap().send(()).unwrap();
                        cancel_rx.take().unwrap().await.unwrap();
                        // The caller canceled this original HTTP request; no response is fabricated.
                        drop(stream);
                        continue;
                    }
                    if step == 4 {
                        (
                            401,
                            vec![
                                ("Date", DATE),
                                ("X-Err", "2148916233"),
                                ("X-SessionId", SESSION),
                            ],
                            json!({"WebPage": PAGE}),
                        )
                    } else {
                        (
                            200,
                            token_headers(),
                            json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                            "AuthorizationToken": token("default", true)}),
                        )
                    }
                }
                _ => unreachable!(),
            };
            write_response(
                &mut stream,
                status,
                response_headers,
                &serde_json::to_vec(&response).unwrap(),
            )
            .await;
        }
    });
    let run = async {
        let config = Config::default();
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            "access".into(),
            "refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .map_err(|_| "credentials")?;
        let mut account =
            Account::new(Http::fixture(address), config, credentials).map_err(|_| "account")?;
        {
            let acquire = account.authorize(XBOX_RELYING_PARTY);
            tokio::pin!(acquire);
            tokio::select! {
                result = &mut acquire => { drop(result); return Err("held acquisition completed before cancellation"); }
                seen = seen_rx => { seen.map_err(|_| "original SISU request not observed")?; }
            }
        }
        cancel_tx
            .send(())
            .map_err(|_| "original server retired before cancellation")?;
        let checkpoint = account
            .checkpoint()
            .map_err(|_| "checkpoint after cancellation")?;
        if !checkpoint.as_bytes().starts_with(b"BSAC\x03") {
            return Err("cancellation discarded the installed device identity");
        }
        let signup = challenge(account.authorize(XBOX_RELYING_PARTY).await)?;
        let authorized = account
            .authorize(XBOX_RELYING_PARTY)
            .await
            .map_err(|_| "authorization after signup")?;
        Ok::<_, &'static str>((signup, authorized.xuid().to_owned()))
    };
    let result = tokio::time::timeout(Duration::from_secs(5), run).await;
    if !matches!(&result, Ok(Ok(_))) {
        server.abort();
    }
    let served = server.await;
    let (signup, xuid) = result
        .expect("finite canceled signup fixture")
        .expect("same original account");
    served.unwrap();
    assert_eq!(xuid, "123");
    let url = Url::parse(signup.signup_url()).unwrap();
    assert!(
        url.query_pairs()
            .any(|(name, value)| name == "did" && value == format!("0x{DEVICE}"))
    );
}

mod shapes;
