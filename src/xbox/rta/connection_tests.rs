use super::*;
use crate::{
    http::Http,
    oauth::Credentials,
    xbox::{
        Config,
        test_support::{fixture, token},
    },
};
use p256::ecdsa::{Signature, signature::hazmat::PrehashVerifier};
use reqwest::header::HeaderValue;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, UNIX_EPOCH};

const SIGNED: &[&str] = &[
    "host",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "user-agent",
    "accept",
];

/// Builds complete original synthetic transport upgrade headers before account signing.
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("host", "rta.xboxlive.com"),
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-protocol", SUBPROTOCOL),
        ("sec-websocket-key", "MDEyMzQ1Njc4OWFiY2RlZg=="),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers
}

/// Independently hashes the final upgrade wire fields; no production signing helper is called.
fn verify(request: &ConnectionRequest, account: &Account) {
    let headers = request.headers();
    assert!(headers["authorization"].is_sensitive());
    assert!(headers["signature"].is_sensitive());
    let signature = STANDARD.decode(headers["signature"].as_bytes()).unwrap();
    let mut hash = Sha256::new();
    for field in [
        &signature[..4],
        &signature[4..12],
        b"GET",
        b"/connect",
        headers["authorization"].as_bytes(),
    ] {
        hash.update(field);
        hash.update([0]);
    }
    for name in SIGNED {
        hash.update(headers[*name].as_bytes());
        hash.update([0]);
    }
    hash.update([0]);
    account
        .key
        .verifying_key()
        .verify_prehash(
            &hash.finalize(),
            &Signature::from_slice(&signature[12..]).unwrap(),
        )
        .unwrap();
}

#[tokio::test]
async fn protected_upgrade_reuses_account_policy_signs_final_headers_and_fences_reconnect() {
    let mut step = 0;
    let (address, server) = fixture(move |path, _, _| {
        step += 1;
        let body = match step {
            1 => { assert_eq!(path,"/device-token"); token("device",false) }
            2 => { assert_eq!(path,"/nsal"); json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn","RelyingParty":XBOX_RELYING_PARTY,"SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1}]}) }
            3 => { assert_eq!(path,"/sisu"); json!({"TitleToken":token("title",false),"UserToken":token("user",false),"AuthorizationToken":token("xbox",true)}) }
            4 => { assert_eq!(path,"/nsal-current"); json!({"EndPoints":[{"Protocol":"https","Host":"rta.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rta","SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1,"ExtraHeaders":SIGNED}]}) }
            5 | 6 => { assert_eq!(path,"/xsts"); token(&format!("rta-{step}"),true) }
            _ => panic!("unexpected account request"),
        }; (200,body)
    },6).await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let generation = Generation::new(7).unwrap();
    let mut first = account.rta_connection(generation, headers()).await.unwrap();
    assert_eq!(first.url().as_str(), "wss://rta.xboxlive.com/connect");
    assert_eq!(first.subprotocol(), SUBPROTOCOL);
    verify(&first, &account);
    let mut state = first.start().unwrap();
    assert!(state.owns_account_proof(&account));
    let original_proof = state.scope.proof;
    state.scope.proof = *p256::ecdsa::SigningKey::from_slice(&[11; 32])
        .unwrap()
        .verifying_key();
    assert!(!state.owns_account_proof(&account));
    state.scope.proof = original_proof;
    assert!(matches!(first.start(), Err(Error::State)));
    let now = Instant::now();
    let (id, frame) = state
        .subscribe(
            super::super::Resource::session_directory(),
            now,
            now + Duration::from_secs(10),
        )
        .unwrap();
    state
        .receive(
            first.epoch(),
            format!(
                "[1,{},0,5,{{\"ConnectionId\":\"00000000-0000-0000-0000-000000000001\"}}]",
                frame.request_id().sequence
            )
            .as_bytes(),
            now,
        )
        .unwrap();

    let mut second = account.rta_connection(generation, headers()).await.unwrap();
    assert_ne!(first.epoch(), second.epoch());
    assert!(Arc::ptr_eq(&first.authorization, &second.authorization));
    let epoch = state.epoch();
    second.scope.generation = Generation::new(8).unwrap();
    assert!(matches!(
        state.reconnect(&mut second),
        Err(Error::WrongAccount)
    ));
    assert_eq!(state.epoch(), epoch);
    assert!(!second.used);
    second.scope.generation = generation;
    let original_xuid = second.scope.xuid.clone();
    second.scope.xuid = "456".into();
    assert!(matches!(
        state.reconnect(&mut second),
        Err(Error::WrongAccount)
    ));
    second.scope.xuid = original_xuid;
    let proof = second.scope.proof;
    second.scope.proof = *p256::ecdsa::SigningKey::from_slice(&[11; 32])
        .unwrap()
        .verifying_key();
    assert!(matches!(
        state.reconnect(&mut second),
        Err(Error::WrongAccount)
    ));
    second.scope.proof = proof;
    state.disconnect();
    state.reconnect(&mut second).unwrap();
    assert!(matches!(
        state.directory_binding(id, Uuid::from_u128(3)),
        Err(Error::State)
    ));
    assert!(matches!(
        state.receive(epoch, b"[3,5,{}]", now),
        Err(Error::WrongHandle)
    ));
    let replacement = state
        .resubscribe(id, now, now + Duration::from_secs(10))
        .unwrap();
    state
        .receive(
            second.epoch(),
            format!(
                "[1,{},0,9,{{\"ConnectionId\":\"00000000-0000-0000-0000-000000000002\"}}]",
                replacement.request_id().sequence
            )
            .as_bytes(),
            now,
        )
        .unwrap();
    assert!(state.directory_binding(id, Uuid::from_u128(3)).is_ok());
    assert!(state.cancel(frame.request_id()).is_empty());

    assert!(account.reject_rta(&first));
    let replacement = account.rta_connection(generation, headers()).await.unwrap();
    verify(&replacement, &account);
    assert!(!account.reject_rta(&first));
    assert!(!account.reject_rta(&second));
    assert!(Arc::ptr_eq(
        account.authorizations.get("rp://rta").unwrap(),
        &replacement.authorization
    ));
    server.await.unwrap();
}

#[test]
fn invalid_or_ambiguous_upgrade_headers_fail_before_credential_acquisition() {
    validate_upgrade(&headers()).unwrap();
    for name in [
        "host",
        "connection",
        "upgrade",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-key",
    ] {
        let mut input = headers();
        input.remove(name);
        assert!(matches!(validate_upgrade(&input), Err(Error::Invalid(_))));
    }
    let mut input = headers();
    input.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("rta.xboxlive.com.v2"),
    );
    assert!(matches!(validate_upgrade(&input), Err(Error::Invalid(_))));
    input = headers();
    input.append(
        "sec-websocket-key",
        HeaderValue::from_static("MDEyMzQ1Njc4OWFiY2RlZg=="),
    );
    assert!(matches!(validate_upgrade(&input), Err(Error::Invalid(_))));
    input = headers();
    input.insert("content-length", HeaderValue::from_static("1"));
    assert!(matches!(validate_upgrade(&input), Err(Error::Invalid(_))));
    input = headers();
    input.insert(
        "authorization",
        HeaderValue::from_static("private-caller-token"),
    );
    let error = validate_upgrade(&input).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-caller-token"));
}
