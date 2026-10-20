use super::*;
use crate::{
    http::Http,
    oauth::Credentials,
    xbox::{
        Config,
        test_support::{fixture_headers, token},
    },
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use reqwest::header::HeaderValue;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::UNIX_EPOCH,
};

const SIGNED_HEADERS: &[&str] = &[
    "User-Agent",
    "Accept",
    "Host",
    "Accept-Language",
    "Cache-Control",
    "Content-Type",
    "Content-Length",
    "X-Xbl-Contract-Version",
];

/// Borrows transmitted header values independently of request-building helpers.
fn header<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map_or("", |(_, value)| value.trim())
}

/// Verifies the actual method, path, authorization, headers and complete transmitted body.
fn verify(target: &str, headers: &str, body: &[u8], proof: &Value) {
    let encoded = STANDARD.decode(header(headers, "signature")).unwrap();
    assert_eq!(&encoded[..4], &1_u32.to_be_bytes());
    let path = percent_encoding::percent_decode_str(target).collect::<Vec<_>>();
    let mut hash = Sha256::new();
    for field in [
        &encoded[..4],
        &encoded[4..12],
        headers.split_whitespace().next().unwrap().as_bytes(),
        path.as_slice(),
        header(headers, "authorization").as_bytes(),
    ] {
        hash.update(field);
        hash.update([0]);
    }
    for name in SIGNED_HEADERS {
        hash.update(header(headers, name).as_bytes());
        hash.update([0]);
    }
    hash.update(body);
    hash.update([0]);
    let mut point = vec![4];
    point.extend(
        URL_SAFE_NO_PAD
            .decode(proof["x"].as_str().unwrap())
            .unwrap(),
    );
    point.extend(
        URL_SAFE_NO_PAD
            .decode(proof["y"].as_str().unwrap())
            .unwrap(),
    );
    VerifyingKey::from_sec1_bytes(&point)
        .unwrap()
        .verify_prehash(
            &hash.finalize(),
            &Signature::from_slice(&encoded[12..]).unwrap(),
        )
        .unwrap();
}

/// Exercises authenticated title selection, actual signed bytes, reuse, failure and cleanup.
#[tokio::test]
async fn title_updates_retry_without_repeating_dispatch_or_removal() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let observed_dispatches = Arc::clone(&dispatches);
    let mut updates = 0;
    let mut update_body = None;
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture_headers(
        move |target, headers, body| {
            step += 1;
            if step <= 5 || step == 10 {
                assert_eq!(observed_dispatches.load(Ordering::SeqCst), updates,
                    "acquiring credentials must not report a title POST");
            }
            let mut extra = Vec::new();
            let (status, response) = match step {
                1 => {
                    assert_eq!(target, "/device-token");
                    let value: Value = serde_json::from_slice(body).unwrap();
                    proof = Some(value["Properties"]["ProofKey"].clone());
                    (200, token("device", false))
                }
                2 => {
                    assert_eq!(target, "/nsal");
                    (200, json!({"EndPoints": [{"Protocol":"http", "Host":"127.0.0.1",
                        "HostType":"fqdn", "RelyingParty":XBOX_RELYING_PARTY}], "SignaturePolicies":[]}))
                }
                3 => {
                    assert_eq!(target, "/sisu");
                    let value: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(&value["ProofKey"], proof.as_ref().unwrap());
                    (200, json!({"TitleToken":token("title", false), "UserToken":token("user", false),
                        "AuthorizationToken":token("default", true)}))
                }
                4 => {
                    assert_eq!(target, "/nsal-current");
                    // A path-scoped policy must resolve against the complete final destination.
                    (200, json!({"EndPoints": [{"Protocol":"http", "Host":"127.0.0.1",
                        "HostType":"fqdn", "Path":"/users/xuid(123)/devices/current/titles/current",
                        "RelyingParty":"rp://presence", "SignaturePolicyIndex":0}],
                        "SignaturePolicies":[{"Version":1,"ExtraHeaders":SIGNED_HEADERS}]}))
                }
                5 | 10 => {
                    assert_eq!(target, "/xsts");
                    let value: Value = serde_json::from_slice(body).unwrap();
                    assert_eq!(value["RelyingParty"], "rp://presence");
                    (200, token(if step == 5 { "first" } else { "second" }, true))
                }
                _ => {
                    assert_eq!(target, "/users/xuid(123)/devices/current/titles/current");
                    verify(target, headers, body, proof.as_ref().unwrap());
                    if headers.starts_with("POST ") && !matches!(step, 12 | 13) {
                        updates += 1;
                    }
                    if matches!(step, 11..=13) {
                        assert_eq!(body, update_body.as_deref().unwrap());
                    }
                    assert_eq!(observed_dispatches.load(Ordering::SeqCst), updates,
                        "one logical update reports dispatch once across all its signed attempts");
                    assert_eq!(header(headers, "x-xbl-contract-version"), CONTRACT);
                    assert_eq!(header(headers, "accept"), "*/*");
                    assert_eq!(header(headers, "accept-language"), DEFAULT_LANGUAGE);
                    assert_eq!(header(headers, "cache-control"), "no-cache");
                    assert_eq!(header(headers, "content-type"), "application/json");
                    let authorization = header(headers, "authorization");
                    if step <= 9 {
                        assert_eq!(authorization, "XBL3.0 x=synthetic;first");
                    } else {
                        assert_eq!(authorization, "XBL3.0 x=synthetic;second");
                    }
                    match step {
                        6 | 7 => {
                            assert!(headers.starts_with("POST "));
                            assert!(body.ends_with(b"\n"));
                            assert_eq!(header(headers, "content-length"), body.len().to_string());
                            let request: Value = serde_json::from_slice(body).unwrap();
                            assert_eq!(request, json!({"state":"active","placement":"background",
                                "activity":{"richPresence":{"id":"FixtureActivity",
                                    "scid":uuid::Uuid::from_u128(1),"params":["alpha", ""]}}}));
                            assert!(request.get("id").is_none());
                            if step == 6 {
                                update_body = Some(body.to_vec());
                                extra.push(("X-Heartbeat-After", "79"));
                            }
                            (if step == 6 { 201 } else { 200 }, json!({"ignored":"data"}))
                        }
                        8 | 9 => {
                            if step == 9 {
                                extra.push(("WWW-Authenticate", "Token error=\"token_expired\""));
                            }
                            (401, json!({"error":"SENSITIVE-response"}))
                        }
                        11 | 12 => {
                            extra.push(("Retry-After", "1"));
                            (if step == 11 { 429 } else { 503 }, json!({"error":"SENSITIVE-response"}))
                        }
                        13 => (200, Value::Null),
                        14 | 15 | 18 | 19 => {
                            assert!(headers.starts_with("DELETE "));
                            assert!(body.is_empty());
                            assert_eq!(header(headers, "content-length"), "0");
                            if step == 19 {
                                extra.push(("Retry-After", "1"));
                            }
                            (match step { 14 => 200, 15 => 201, 18 => 202, _ => 503 }, Value::Null)
                        }
                        16 => (202, Value::Null),
                        17 => {
                            assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"state":"inactive"}));
                            extra.extend([("X-Heartbeat-After", "5"), ("X-Heartbeat-After", "6")]);
                            (200, Value::Null)
                        }
                        _ => panic!("unexpected presence request"),
                    }
                }
            };
            (status, extra, response)
        },
        19,
    )
    .await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let mut presence = account.title_presence();
    presence.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let update = TitleUpdate::new(State::Active)
        .with_placement(Placement::Background)
        .with_rich_presence(
            RichPresence::new(uuid::Uuid::from_u128(1), "FixtureActivity")
                .unwrap()
                .with_parameters(&["alpha", ""])
                .unwrap(),
        );
    let dispatched = || {
        dispatches.fetch_add(1, Ordering::SeqCst);
    };
    assert_eq!(
        presence
            .update_with_dispatch(&update, dispatched)
            .await
            .unwrap()
            .heartbeat_after,
        Some(Duration::from_secs(79))
    );
    assert_eq!(
        presence
            .update_with_dispatch(&update, dispatched)
            .await
            .unwrap()
            .heartbeat_after,
        None
    );
    for expected in [401, 401] {
        let error = presence
            .update_with_dispatch(&update, dispatched)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Status { status, .. } if status.as_u16() == expected));
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    assert_eq!(
        presence
            .update_with_dispatch(&update, dispatched)
            .await
            .unwrap()
            .heartbeat_after,
        None
    );
    // Cleanup remains explicit even after an update error; no success flag suppresses it.
    presence.remove().await.unwrap();
    presence.remove().await.unwrap();
    assert!(matches!(
        presence.update_with_dispatch(&update, dispatched).await,
        Err(Error::Status {
            status: StatusCode::ACCEPTED,
            ..
        })
    ));
    assert_eq!(
        presence
            .update_with_dispatch(&TitleUpdate::new(State::Inactive), dispatched)
            .await
            .unwrap()
            .heartbeat_after,
        None
    );
    assert!(matches!(
        presence.remove().await,
        Err(Error::Status {
            status: StatusCode::ACCEPTED,
            ..
        })
    ));
    assert!(matches!(
        presence.remove().await,
        Err(Error::Status {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    ));
    assert_eq!(dispatches.load(Ordering::SeqCst), 7);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Refuses a changed service XUID and still permits cleanup after canceling an observed POST.
#[tokio::test]
async fn title_identity_and_canceled_update_do_not_suppress_explicit_cleanup() {
    let (observed, mut observation) = tokio::sync::oneshot::channel();
    let mut observed = Some(observed);
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture_headers(
        move |target, headers, body| {
            step += 1;
            let response = match step {
                1 => {
                    assert_eq!(target, "/device-token");
                    proof = Some(
                        serde_json::from_slice::<Value>(body).unwrap()["Properties"]["ProofKey"]
                            .clone(),
                    );
                    token("device", false)
                }
                2 => {
                    assert_eq!(target, "/nsal");
                    json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn",
                        "RelyingParty":XBOX_RELYING_PARTY}],"SignaturePolicies":[]})
                }
                3 => {
                    assert_eq!(target, "/sisu");
                    assert_eq!(
                        &serde_json::from_slice::<Value>(body).unwrap()["ProofKey"],
                        proof.as_ref().unwrap()
                    );
                    json!({"TitleToken":token("title", false),"UserToken":token("user", false),
                        "AuthorizationToken":token("default", true)})
                }
                4 => {
                    assert_eq!(target, "/nsal-current");
                    json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn",
                        "RelyingParty":"rp://presence","SignaturePolicyIndex":0}],
                        "SignaturePolicies":[{"Version":1,"ExtraHeaders":SIGNED_HEADERS}]})
                }
                5 | 6 => {
                    assert_eq!(target, "/xsts");
                    let mut value = token("service", true);
                    if step == 5 {
                        value["DisplayClaims"]["xui"][0]["xid"] = json!("321");
                    }
                    value
                }
                7 | 8 => {
                    assert_eq!(target, "/users/xuid(123)/devices/current/titles/current");
                    verify(target, headers, body, proof.as_ref().unwrap());
                    if step == 7 {
                        assert!(headers.starts_with("POST "));
                        observed.take().unwrap().send(()).unwrap();
                    } else {
                        assert!(headers.starts_with("DELETE "));
                        assert!(body.is_empty());
                    }
                    Value::Null
                }
                _ => panic!("unexpected presence request"),
            };
            (200, Vec::new(), response)
        },
        8,
    )
    .await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let base = Url::parse(&format!("http://{address}")).unwrap();
    let update = TitleUpdate::new(State::Active);
    let mut dispatched = false;
    {
        let mut presence = account.title_presence();
        presence.fixture_base = Some(base.clone());
        assert!(matches!(
            presence
                .update_with_dispatch(&update, || dispatched = true)
                .await,
            Err(Error::Invalid("presence account identity"))
        ));
    }
    assert!(!dispatched, "a rejected service XUID cannot dispatch");
    let mismatched = account.authorize("rp://presence").await.unwrap();
    assert!(account.reject(&mismatched));
    let mut presence = account.title_presence();
    presence.fixture_base = Some(base);
    {
        drop(presence.update_with_dispatch(&update, || dispatched = true));
        assert!(!dispatched, "an unpolled future cannot dispatch");
        let pending = presence.update_with_dispatch(&update, || dispatched = true);
        tokio::pin!(pending);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = &mut observation => result.unwrap(),
                result = &mut pending => panic!("update completed before cancellation: {result:?}"),
            }
        })
        .await
        .unwrap();
        // Drop the in-flight future after the service observed its write, before accepting its reply.
    }
    assert!(
        dispatched,
        "observed POST cancellation retains caller-owned dispatch state"
    );
    presence.remove().await.unwrap();
    assert!(
        dispatched,
        "successful cleanup does not erase the earlier POST evidence"
    );
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Keeps dispatch absent through cold acquisition, identity rejection and final signing failure.
#[tokio::test]
async fn title_update_dispatch_observer_stays_clear_on_pre_dispatch_errors() {
    #[derive(Clone, Copy)]
    enum Failure {
        Acquisition,
        Identity,
        Signing,
    }
    for failure in [Failure::Acquisition, Failure::Identity, Failure::Signing] {
        let dispatches = Arc::new(AtomicUsize::new(0));
        let observed_dispatches = Arc::clone(&dispatches);
        let mut step = 0;
        let count = if matches!(failure, Failure::Acquisition) {
            1
        } else {
            5
        };
        let (address, server) = fixture_headers(
            move |target, _, _| {
                step += 1;
                assert_eq!(
                    observed_dispatches.load(Ordering::SeqCst),
                    0,
                    "acquisition traffic is not presence dispatch"
                );
                let response = match step {
                    1 => {
                        assert_eq!(target, "/device-token");
                        if matches!(failure, Failure::Acquisition) {
                            return (503, Vec::new(), Value::Null);
                        }
                        token("device", false)
                    }
                    2 => {
                        assert_eq!(target, "/nsal");
                        json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1",
                        "HostType":"fqdn","RelyingParty":XBOX_RELYING_PARTY}],
                        "SignaturePolicies":[]})
                    }
                    3 => {
                        assert_eq!(target, "/sisu");
                        json!({"TitleToken":token("title", false),"UserToken":token("user", false),
                        "AuthorizationToken":token("default", true)})
                    }
                    4 => {
                        assert_eq!(target, "/nsal-current");
                        let signed = if matches!(failure, Failure::Signing) {
                            &["invalid header name"][..]
                        } else {
                            SIGNED_HEADERS
                        };
                        json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1",
                        "HostType":"fqdn","RelyingParty":"rp://presence","SignaturePolicyIndex":0}],
                        "SignaturePolicies":[{"Version":1,"ExtraHeaders":signed}]})
                    }
                    5 => {
                        assert_eq!(target, "/xsts");
                        let mut value = token("service", true);
                        if matches!(failure, Failure::Identity) {
                            value["DisplayClaims"]["xui"][0]["xid"] = json!("321");
                        }
                        value
                    }
                    _ => panic!("a pre-dispatch failure reached the presence service"),
                };
                (200, Vec::new(), response)
            },
            count,
        )
        .await;
        let config = Config::default();
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            "access".into(),
            "refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .unwrap();
        let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
        let mut presence = account.title_presence();
        presence.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            presence.update_with_dispatch(&TitleUpdate::new(State::Active), || {
                dispatches.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        match failure {
            Failure::Acquisition => assert!(matches!(
                error,
                Error::Status {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    ..
                }
            )),
            Failure::Identity => {
                assert!(matches!(error, Error::Invalid("presence account identity")))
            }
            Failure::Signing => assert!(matches!(
                error,
                Error::Invalid("signature policy header name")
            )),
        }
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}

/// Does not turn malformed scheduling metadata into a zero-delay retry or overflow.
#[test]
fn heartbeat_metadata_requires_one_positive_representable_integer() {
    let mut response = Response {
        status: StatusCode::OK,
        headers: reqwest::header::HeaderMap::new(),
        body: zeroize::Zeroizing::new(Vec::new()),
    };
    assert_eq!(heartbeat_after(&response), None);
    for value in ["", "0", "-1", "+1", "1.5", "NaN", "18446744073709551616"] {
        response
            .headers
            .insert("x-heartbeat-after", HeaderValue::from_str(value).unwrap());
        assert_eq!(heartbeat_after(&response), None, "{value}");
    }
    response
        .headers
        .insert("x-heartbeat-after", HeaderValue::from_static("79"));
    assert_eq!(heartbeat_after(&response), Some(Duration::from_secs(79)));
    response
        .headers
        .append("x-heartbeat-after", HeaderValue::from_static("80"));
    assert_eq!(heartbeat_after(&response), None);
}

/// Rejects invalid caller data before network work and bounds worst-case JSON escaping.
#[test]
fn rich_presence_bounds_apply_before_encoding() {
    let scid = uuid::Uuid::from_u128(1);
    assert!(RichPresence::new(uuid::Uuid::nil(), "activity").is_err());
    for value in [
        "",
        "line\nbreak",
        "nul\0value",
        &"x".repeat(MAX_TEXT_BYTES + 1),
    ] {
        assert!(RichPresence::new(scid, value).is_err());
    }
    let activity = RichPresence::new(scid, "activity").unwrap();
    assert!(
        activity
            .with_parameters(&["value"; MAX_PARAMETERS + 1])
            .is_err()
    );
    assert!(activity.with_parameters(&["bad\rvalue"]).is_err());
    let text = "\\".repeat(MAX_TEXT_BYTES);
    let parameters = vec![text.as_str(); MAX_PARAMETERS];
    let update = TitleUpdate::new(State::Active).with_rich_presence(
        RichPresence::new(scid, &text)
            .unwrap()
            .with_parameters(&parameters)
            .unwrap(),
    );
    assert!(update.encode().unwrap().len() < crate::http::RESPONSE_LIMIT);
}
