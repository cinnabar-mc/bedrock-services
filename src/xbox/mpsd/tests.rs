use super::*;
use crate::{
    http::Http,
    oauth::Credentials,
    xbox::{
        Config,
        tests::{fixture_headers, token},
    },
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256};
use std::time::{Duration, UNIX_EPOCH};
use uuid::Uuid;

const SIGNED_HEADERS: &[&str] = &[
    "User-Agent",
    "Accept",
    "Host",
    "Content-Type",
    "Content-Length",
    "X-Xbl-Contract-Version",
    "If-Match",
    "If-None-Match",
];

/// Borrows one transmitted header value without depending on header case or order.
fn header<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map_or("", |(_, value)| value.trim())
}

/// Independently verifies the actual method, authorization, conditional headers and JSON bytes.
fn verify(target: &str, headers: &str, body: &[u8], point: &Value, signed_headers: &[&str]) {
    let encoded = STANDARD.decode(header(headers, "signature")).unwrap();
    let method = headers.split_whitespace().next().unwrap();
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let mut canonical = percent_encoding::percent_decode_str(path).collect::<Vec<_>>();
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        canonical.push(b'?');
        canonical.extend_from_slice(query.as_bytes());
    }
    let mut hash = Sha256::new();
    for field in [
        &encoded[..4],
        &encoded[4..12],
        method.as_bytes(),
        canonical.as_slice(),
        header(headers, "authorization").as_bytes(),
    ] {
        hash.update(field);
        hash.update([0]);
    }
    for name in signed_headers {
        hash.update(header(headers, name).as_bytes());
        hash.update([0]);
    }
    hash.update(body);
    hash.update([0]);
    let mut key = vec![4];
    key.extend(
        URL_SAFE_NO_PAD
            .decode(point["x"].as_str().unwrap())
            .unwrap(),
    );
    key.extend(
        URL_SAFE_NO_PAD
            .decode(point["y"].as_str().unwrap())
            .unwrap(),
    );
    VerifyingKey::from_sec1_bytes(&key)
        .unwrap()
        .verify_prehash(
            &hash.finalize(),
            &Signature::from_slice(&encoded[12..]).unwrap(),
        )
        .unwrap();
}

/// Supplies five original authentication exchanges, then verifies each concrete directory request.
async fn script(
    sign_transport_defaults: bool,
    mut service: impl FnMut(usize, &str, &str, &[u8]) -> (u16, Vec<(&'static str, &'static str)>, Value)
    + Send
    + 'static,
    count: usize,
) -> (Account, std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    // Validator regressions isolate ETag behavior; the other chains also sign late transport defaults.
    let signed_headers: Vec<_> = SIGNED_HEADERS
        .iter()
        .copied()
        .filter(|name| sign_transport_defaults || !matches!(*name, "Accept" | "Host"))
        .collect();
    let mut step = 0;
    let mut proof = None;
    let (address, task) = fixture_headers(move |target, headers, body| {
        step += 1;
        let value = match step {
            1 => { assert_eq!(target,"/device-token"); let value: Value=serde_json::from_slice(body).unwrap(); proof=Some(value["Properties"]["ProofKey"].clone()); token("device",false) }
            2 => { assert_eq!(target,"/nsal"); json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn","RelyingParty":super::super::XBOX_RELYING_PARTY,"SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1}]}) }
            3 => { assert_eq!(target,"/sisu"); json!({"TitleToken":token("title",false),"UserToken":token("user",false),"AuthorizationToken":token("xbox",true)}) }
            4 => { assert_eq!(target,"/nsal-current"); json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn","RelyingParty":"rp://mpsd","SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1,"ExtraHeaders":signed_headers}]}) }
            5 => { assert_eq!(target,"/xsts"); token("directory",true) }
            _ => {
                verify(target,headers,body,proof.as_ref().unwrap(),&signed_headers);
                assert_eq!(header(headers,"authorization"),"XBL3.0 x=synthetic;directory");
                assert_eq!(header(headers,"x-xbl-contract-version"), CONTRACT);
                if !body.is_empty() { assert_eq!(body.last(),Some(&b'\n')); }
                return service(step-5,target,headers,body);
            }
        };
        (200,Vec::new(),value)
    }, count+5).await;
    (account(address), address, task)
}

/// Creates an account with synthetic OAuth tokens and a fresh proof key, without I/O.
fn account(address: std::net::SocketAddr) -> Account {
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    Account::new(Http::fixture(address), config, credentials).unwrap()
}

/// Builds a complete response with one actual caller membership and optional revision metadata.
fn snapshot(change: u64) -> Value {
    json!({"branch":Uuid::from_u128(1),"changeNumber":change,"members":{"me":{"constants":{"system":{"xuid":"123"}},"properties":{"system":{"active":true}}}},
        "properties":{"system":{"joinRestriction":"FutureRestriction"},"custom":{"nonces":{"321":"synthetic-admission"}}}})
}

#[test]
fn binding_requires_the_local_active_member_and_exact_connection_and_subscription() {
    let account = account("127.0.0.1:1".parse().unwrap());
    let connection = Uuid::from_u128(41);
    let subscription = Uuid::from_u128(42);
    let binding = Binding::new(connection, subscription).unwrap();
    let mut description = snapshot(1);
    description["members"]["me"]["properties"]["system"] = json!({
        "active":true, "connection":connection,
        "subscription":{"id":subscription.to_string().to_uppercase()}
    });
    let mut session = Session {
        reference: Reference::new(Uuid::from_u128(7), "MinecraftLobby".into(), "world".into())
            .unwrap(),
        owner: "123".into(),
        proof: *account.key.verifying_key(),
        description: serde_json::from_value(description).unwrap(),
        etag: None,
        closed: false,
        uncertain: false,
    };
    assert!(session.is_bound(binding));
    assert!(!session.is_bound(Binding::new(Uuid::from_u128(43), subscription).unwrap()));
    assert!(!session.is_bound(Binding::new(connection, Uuid::from_u128(44)).unwrap()));
    session.uncertain = true;
    assert!(!session.is_bound(binding));
    session.uncertain = false;
    session
        .description
        .members
        .get_mut("me")
        .unwrap()
        .as_mut()
        .unwrap()
        .properties
        .as_mut()
        .unwrap()
        .system
        .as_mut()
        .unwrap()["active"] = json!(false);
    assert!(!session.is_bound(binding));
    session
        .description
        .members
        .get_mut("me")
        .unwrap()
        .as_mut()
        .unwrap()
        .properties
        .as_mut()
        .unwrap()
        .system
        .as_mut()
        .unwrap()["active"] = json!(true);
    session.owner = "456".into();
    assert!(!session.is_bound(binding));
}

/// Exercises actual signed lifecycle, isolated account ownership, partial writes and complete-cache refresh.
#[tokio::test]
async fn lifecycle_preserves_validators_membership_identity_and_uncertain_write_fences() {
    let scid = Uuid::from_u128(7);
    let reference = Reference::new(scid, "MinecraftLobby".into(), "Hosted World".into()).unwrap();
    let target =
        format!("/serviceconfigs/{scid}/sessionTemplates/MinecraftLobby/sessions/Hosted%20World");
    let (mut account,address,server)=script(false, move |step,path,headers,body| {
        let value:Value=if body.is_empty(){Value::Null}else{serde_json::from_slice(body).unwrap()};
        if !matches!(step,2|3) { assert_eq!(path,target); }
        match step {
            1 => { assert_eq!(header(headers,"if-none-match"),"*"); assert_eq!(value["members"]["me"]["constants"]["system"]["xuid"],"123");
                assert_eq!(value["members"]["me"]["properties"]["system"]["subscription"]["id"],Uuid::from_u128(3).to_string().to_uppercase());
                assert_eq!(value["properties"]["system"],json!({"closed":false,"joinRestriction":"followed","readRestriction":"followed"}));
                (201,vec![("ETag","\"v1\"")],snapshot(1)) }
            2 => { assert_eq!(path,"/handles"); assert_eq!(value["type"],"activity"); assert_eq!(value["sessionRef"]["scid"],scid.to_string()); (201,vec![],json!({})) }
            3 => { assert_eq!(path,"/handles"); assert_eq!(value["type"],"invite"); assert_eq!(value["invitedXuid"],"321"); assert_eq!(value["inviteAttributes"]["titleId"],"12345");
                (201,vec![],json!({"id":Uuid::from_u128(9),"invitedXuid":"321","senderXuid":"123","expiration":"2099-01-01T00:00:00Z","gameTypes":{"future-platform":{"titleId":"12345"}}})) }
            4 => { assert_eq!(header(headers,"if-match"),"\"v1\""); assert_eq!(value,json!({"properties":{"custom":{"memberCount":2}}}));
                let mut result=snapshot(2);result["members"]=Value::Null; (200,vec![("ETag","\"v2\"")],result) }
            5 => { assert_eq!(header(headers,"if-none-match"),"\"v2\""); (304,vec![],Value::Null) }
            6 => { assert_eq!(header(headers,"if-match"),"\"v2\""); assert_eq!(value,json!({"members":{"me":{"properties":{"custom":{"ready":true}}}}})); (412,vec![("ETag","\"v3\"")],json!({"secret":"SENSITIVE"})) }
            7 => { assert_eq!(header(headers,"if-none-match"),""); (200,vec![],snapshot(3)) }
            8 => { assert_eq!(header(headers,"if-match"),"*"); assert_eq!(value["members"]["me"]["properties"]["system"]["connection"],Uuid::from_u128(4).to_string()); (200,vec![("ETag","\"v4\"")],snapshot(4)) }
            9 => { assert_eq!(header(headers,"if-none-match"),"\"v4\""); (200,vec![("ETag","\"stale\"")],snapshot(2)) }
            10 => { assert_eq!(header(headers,"if-match"),"\"v4\""); assert_eq!(value,json!({"members":{"me":null}})); (204,vec![],Value::Null) }
            11 => (200,vec![("ETag","\"v10\"")],snapshot(10)),
            12 => { let mut value=snapshot(11); value["sessionRef"]=json!({"scid":scid,"templateName":"MinecraftLobby","name":"SENSITIVE-other-world"}); (200,vec![("ETag","\"wrong\"")],value) }
            13 => { assert_eq!(header(headers,"if-none-match"),"\"v10\""); let mut value=snapshot(1);value["branch"]=json!(Uuid::from_u128(2));(200,vec![],value) }
            14 => { assert_eq!(header(headers,"if-match"),"*"); let mut value=snapshot(2);value["branch"]=json!(Uuid::from_u128(2));(200,vec![("ETag","\"rotated\"")],value) }
            15 => { assert_eq!(header(headers,"if-none-match"),"\"rotated\""); let mut value=snapshot(0);value["branch"]=json!(Uuid::from_u128(2));(200,vec![("ETag","\"stale-branch\"")],value) }
            16 => { assert_eq!(header(headers,"if-match"),"\"rotated\"");(204,vec![],Value::Null) }
            _=>panic!("unexpected lifecycle request"),
        }
    },16).await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let mut session = directory
        .publish(
            &reference,
            Publish {
                binding,
                member: MemberData::default(),
                constants: None,
                properties: Some(json!({"worldName":"Fixture"})),
                join: Restriction::Followed,
                read: Restriction::Followed,
            },
        )
        .await
        .unwrap();
    let mut foreign = super::tests::account(address);
    assert!(matches!(
        foreign
            .mpsd()
            .set_properties(&mut session, &json!({}))
            .await,
        Err(Error::WrongAccount)
    ));
    directory.publish_activity(&session).await.unwrap();
    assert_eq!(
        directory.invite(&session, "321", "12345").await.unwrap().id,
        Uuid::from_u128(9)
    );
    assert_eq!(
        directory
            .set_properties(&mut session, &json!({"memberCount":2}))
            .await
            .unwrap(),
        Update::Updated
    );
    assert!(session.description().members.is_empty());
    assert_eq!(
        directory.sync(&mut session).await.unwrap(),
        Update::Unchanged
    );
    assert_eq!(
        directory
            .set_member_properties(&mut session, &json!({"ready":true}))
            .await
            .unwrap(),
        Update::PreconditionFailed
    );
    assert!(session.needs_sync());
    assert!(matches!(
        directory.leave(&mut session).await,
        Err(Error::SyncRequired)
    ));
    directory.sync(&mut session).await.unwrap();
    directory
        .bind(
            &mut session,
            Binding::new(Uuid::from_u128(4), Uuid::from_u128(3)).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        directory.sync(&mut session).await,
        Err(Error::Stale)
    ));
    assert_eq!(session.description().change_number, Some(4));
    assert_eq!(directory.leave(&mut session).await.unwrap(), Update::Closed);
    assert!(session.is_closed());
    assert!(matches!(
        directory.set_properties(&mut session, &json!({})).await,
        Err(Error::Closed)
    ));
    let mut fresh = directory.read(&reference).await.unwrap();
    let error = directory.sync(&mut fresh).await.unwrap_err();
    assert!(!format!("{error:?}").contains("SENSITIVE"));
    assert_eq!(fresh.description().change_number, Some(10));
    assert_eq!(directory.sync(&mut fresh).await.unwrap(), Update::Updated);
    assert_eq!(fresh.description().change_number, Some(1));
    assert_eq!(fresh.description().branch, Some(Uuid::from_u128(2)));
    assert_eq!(
        directory
            .set_properties(&mut fresh, &json!({"worldName":"After no validator"}))
            .await
            .unwrap(),
        Update::Updated
    );
    assert!(matches!(
        directory.sync(&mut fresh).await,
        Err(Error::Stale)
    ));
    assert_eq!(directory.leave(&mut fresh).await.unwrap(), Update::Closed);
    assert!(fresh.is_closed());
    server.await.unwrap();
}

/// Only explicit 412 replays stable join bytes, with bounded attempts and safe reference extraction.
#[tokio::test]
async fn joins_bound_retries_and_never_follow_response_credential_destinations() {
    let mut first = None;
    let (mut account,address,server)=script(true, move |step,path,headers,body| {
        assert!(path.starts_with("/handles/"));
        match step {
            1=>{assert_eq!(header(headers,"if-match"),"*");first=Some(body.to_vec());(412,vec![("ETag","\"join2\"")],json!({}))}
            2=>{assert_eq!(header(headers,"if-match"),"\"join2\"");assert_eq!(body,first.as_ref().unwrap());(412,vec![("ETag","\"join3\"")],json!({}))}
            3=>{assert_eq!(header(headers,"if-match"),"\"join3\"");assert_eq!(body,first.as_ref().unwrap());(200,vec![("Content-Location","/serviceconfigs/00000000-0000-0000-0000-000000000007/sessionTemplates/MinecraftLobby/sessions/Joined%20World"),("ETag","\"joined\"")],snapshot(1))}
            4..=6=>(412,vec![("ETag","\"raced\"")],json!({})),
            7=>(200,vec![("Content-Location","https://elsewhere.invalid/serviceconfigs/00000000-0000-0000-0000-000000000007/sessionTemplates/MinecraftLobby/sessions/SENSITIVE")],snapshot(1)),
            8=>(500,vec![],json!({"secret":"SENSITIVE"})),
            _=>panic!("unexpected join request"),
        }
    },8).await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let mut attempt = directory
        .join_attempt(Uuid::from_u128(5), binding, MemberData::default())
        .unwrap();
    assert!(!attempt.needs_reconciliation());
    drop(directory.join(&mut attempt));
    assert!(!attempt.needs_reconciliation());
    assert!(matches!(
        directory.join(&mut attempt).await.unwrap(),
        JoinOutcome::Precondition { remaining: 2, .. }
    ));
    assert!(!attempt.needs_reconciliation());
    assert!(matches!(
        directory.join(&mut attempt).await.unwrap(),
        JoinOutcome::Precondition { remaining: 1, .. }
    ));
    let JoinOutcome::Joined(session) = directory.join(&mut attempt).await.unwrap() else {
        panic!("join not completed")
    };
    assert_eq!(session.reference().name(), "Joined World");
    assert!(matches!(
        directory.join(&mut attempt).await,
        Err(Error::JoinFinished)
    ));
    let mut raced = directory
        .join_attempt(Uuid::from_u128(6), binding, MemberData::default())
        .unwrap();
    for _ in 1..MAX_JOIN_ATTEMPTS {
        assert!(matches!(
            directory.join(&mut raced).await.unwrap(),
            JoinOutcome::Precondition { .. }
        ));
    }
    assert!(matches!(
        directory.join(&mut raced).await.unwrap(),
        JoinOutcome::Exhausted
    ));
    assert!(
        !raced.needs_reconciliation(),
        "explicitly exhausted 412 writes did not create membership"
    );
    assert!(matches!(
        directory.join(&mut raced).await,
        Err(Error::JoinFinished)
    ));
    for handle in [7, 8] {
        let mut rejected = directory
            .join_attempt(Uuid::from_u128(handle), binding, MemberData::default())
            .unwrap();
        let error = match directory.join(&mut rejected).await {
            Err(error) => error,
            Ok(_) => panic!("invalid join accepted"),
        };
        assert!(!format!("{error:?}").contains("SENSITIVE"));
        assert!(matches!(
            directory.join(&mut rejected).await,
            Err(Error::JoinFinished)
        ));
    }
    assert!(
        directory
            .join_attempt(
                Uuid::from_u128(9),
                binding,
                MemberData {
                    constants: None,
                    properties: Some(json!("x".repeat(MAX_REQUEST_BYTES)))
                }
            )
            .is_err()
    );
    assert!(Reference::new(Uuid::from_u128(1), "../credentials".into(), "world".into()).is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_rejected_join_metadata_does_not_make_the_write_ambiguous() {
    let (mut account, address, server) = script(
        true,
        |_, _, _, _| (412, vec![("ETag", "unquoted")], json!({})),
        1,
    )
    .await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let mut attempt = directory
        .join_attempt(
            Uuid::from_u128(5),
            Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap(),
            MemberData::default(),
        )
        .unwrap();
    assert!(matches!(
        directory.join(&mut attempt).await,
        Err(Error::Invalid("session ETag"))
    ));
    assert!(
        !attempt.needs_reconciliation(),
        "the observed 412 rejected membership before metadata decoding"
    );
    assert!(matches!(
        directory.join(&mut attempt).await,
        Err(Error::JoinFinished)
    ));
    server.await.unwrap();
}

/// Exercises real reads/refresh/conditional leave without needing the original RTA socket to be live.
async fn bound_cleanup_scenario(scenario: &'static str) {
    let connection = Uuid::from_u128(41);
    let subscription = Uuid::from_u128(42);
    let binding = Binding::new(connection, subscription).unwrap();
    let (mut account, address, server) = script(true, move |step, _, headers, body| {
            let mut value = snapshot(step as u64);
            value["members"]["me"]["properties"]["system"] = json!({
                "active":true, "connection":connection,
                "subscription":{"id":if scenario == "replacement" && step == 2 { Uuid::from_u128(43) } else { subscription }}
            });
            match step {
                1 => (200, vec![("ETag", "\"v1\"")], value),
                2 => {
                    assert_eq!(header(headers, "if-none-match"), "\"v1\"");
                    (200, if scenario == "missing-validator" { vec![] } else { vec![("ETag", "\"v2\"")] }, value)
                }
                3 => {
                    assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"members":{"me":null}}));
                    assert_eq!(header(headers, "if-match"), if scenario == "missing-validator" { "*" } else { "\"v2\"" });
                    (204, vec![], Value::Null)
                }
                _ => panic!("unexpected bound cleanup request"),
            }
        }, 3).await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let reference =
        Reference::new(Uuid::from_u128(7), "MinecraftLobby".into(), "Hosted".into()).unwrap();
    let mut session = directory.read(&reference).await.unwrap();
    assert!(session.is_bound(binding));
    assert_eq!(directory.sync(&mut session).await.unwrap(), Update::Updated);
    let result = directory.leave_bound(&mut session, binding).await;
    match scenario {
        "original" => {
            assert_eq!(result.unwrap(), Update::Closed);
            server.await.unwrap();
        }
        "replacement" => {
            assert!(
                matches!(result, Err(Error::Invalid("session cleanup binding"))),
                "cleanup must never delete an observed replacement membership"
            );
            assert!(!session.is_closed());
            assert!(!session.needs_sync());
            server.abort();
            let _ = server.await;
        }
        _ => {
            assert!(
                matches!(result, Err(Error::Invalid("session cleanup validator"))),
                "wildcard cleanup cannot protect an unobserved replacement"
            );
            assert!(!session.is_closed());
            assert!(!session.needs_sync());
            server.abort();
            let _ = server.await;
        }
    }
}

#[tokio::test]
async fn bound_cleanup_leaves_original_membership_without_a_live_socket() {
    bound_cleanup_scenario("original").await;
}

#[tokio::test]
async fn bound_cleanup_preserves_an_observed_replacement_membership() {
    bound_cleanup_scenario("replacement").await;
}

#[tokio::test]
async fn bound_cleanup_rejects_a_missing_validator_before_destructive_io() {
    bound_cleanup_scenario("missing-validator").await;
}

/// Drops a live HTTP future once the fixture has applied its request but before consuming its reply.
async fn cancel_after_application<F: std::future::Future>(
    future: F,
    seen: &std::sync::atomic::AtomicUsize,
    expected: usize,
) {
    use std::{future::poll_fn, sync::atomic::Ordering, task::Poll};
    let mut future = Box::pin(future);
    poll_fn(|cx| {
        if seen.load(Ordering::SeqCst) >= expected {
            return Poll::Ready(());
        }
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "response consumed before cancellation witness"
        );
        Poll::Pending
    })
    .await;
}

/// Actual canceled HTTP writes may apply remotely; sync clears ambiguity, while a canceled join remains sealed.
#[tokio::test]
async fn canceled_writes_require_reconciliation_and_canceled_joins_cannot_replay() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let applied = Arc::new(AtomicUsize::new(0));
    let signal = Arc::clone(&applied);
    let (mut account,address,server)=script(true, move |step,_path,headers,body| {
        match step {
            1=>(200,vec![("ETag","\"v1\"")],snapshot(1)),
            2=>{assert_eq!(header(headers,"if-match"),"\"v1\"");signal.store(2,Ordering::SeqCst);(200,vec![("ETag","\"v2\"")],snapshot(2))}
            3=>{assert_eq!(header(headers,"if-none-match"),"");(200,vec![("ETag","\"v2\"")],snapshot(2))}
            4|5=>(412,vec![("ETag","\"raced\"")],json!({})),
            6=>{let value:Value=serde_json::from_slice(body).unwrap();assert_eq!(value["members"]["me"]["constants"]["system"]["xuid"],"123");signal.store(6,Ordering::SeqCst);
                (200,vec![("Content-Location","/serviceconfigs/00000000-0000-0000-0000-000000000007/sessionTemplates/MinecraftLobby/sessions/Joined")],snapshot(1))}
            7=>(200,vec![("ETag","\"joined\"")],snapshot(1)),
            8|9=>{assert_eq!(serde_json::from_slice::<Value>(body).unwrap(),json!({"members":{"me":null}}));(204,vec![],Value::Null)}
            _=>panic!("unexpected cancellation request"),
        }
    },9).await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let reference =
        Reference::new(Uuid::from_u128(7), "MinecraftLobby".into(), "Hosted".into()).unwrap();
    let mut session = directory.read(&reference).await.unwrap();
    let custom = json!({"worldName":"Changed"});
    cancel_after_application(directory.set_properties(&mut session, &custom), &applied, 2).await;
    assert!(session.needs_sync());
    assert!(matches!(
        directory.set_properties(&mut session, &custom).await,
        Err(Error::SyncRequired)
    ));
    assert_eq!(directory.sync(&mut session).await.unwrap(), Update::Updated);
    assert_eq!(session.description().change_number, Some(2));
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let mut attempt = directory
        .join_attempt(Uuid::from_u128(5), binding, MemberData::default())
        .unwrap();
    for _ in 1..MAX_JOIN_ATTEMPTS {
        assert!(matches!(
            directory.join(&mut attempt).await.unwrap(),
            JoinOutcome::Precondition { .. }
        ));
        assert!(!attempt.needs_reconciliation());
    }
    cancel_after_application(directory.join(&mut attempt), &applied, 6).await;
    assert!(attempt.needs_reconciliation());
    assert!(matches!(
        directory.join(&mut attempt).await,
        Err(Error::JoinFinished)
    ));
    // The application already knows the referenced world and explicitly reconciles it.
    let joined =
        Reference::new(Uuid::from_u128(7), "MinecraftLobby".into(), "Joined".into()).unwrap();
    let mut joined = directory.read(&joined).await.unwrap();
    directory.leave(&mut joined).await.unwrap();
    directory.leave(&mut session).await.unwrap();
    server.await.unwrap();
}

/// Untrusted validators cannot turn conditional writes into wildcards, and URL normalization cannot hide dot segments.
#[test]
fn metadata_rejects_unsafe_validators_locations_and_escaped_body_overflow() {
    for value in ["*", "unquoted", "\"one\", \"two\"", "W/\"unterminated"] {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::ETAG, HeaderValue::from_str(value).unwrap());
        assert!(types::etag(&headers).is_err());
    }
    let path = "/serviceconfigs/00000000-0000-0000-0000-000000000007/sessionTemplates/MinecraftLobby/sessions/World";
    assert!(join::location_reference(path).is_ok());
    for location in [
        format!("https://elsewhere.invalid{path}"),
        format!("https://user:secret@sessiondirectory.xboxlive.com{path}"),
        format!("{path}?secret=value"),
        format!("{path}/%2e%2e/Other"),
        path.replace("World", "slash%2Fname"),
    ] {
        assert!(join::location_reference(&location).is_err());
    }
    assert!(matches!(
        encode(&json!("\"".repeat(MAX_REQUEST_BYTES / 2))),
        Err(Error::Limit)
    ));
}
