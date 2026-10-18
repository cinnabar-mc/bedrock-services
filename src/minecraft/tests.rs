use super::*;
use crate::{
    oauth::Credentials,
    xbox::tests::{fixture, token},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use std::time::{Duration, UNIX_EPOCH};
use uuid::Uuid;

/// Generates original service metadata without a real account or private signing key.
fn service_token(label: &str) -> Value {
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "pmid":"25c7d2d9-dfff-4e3f-877c-3f1c3ab9cfac","exp":4102444800_i64,
        }))
        .unwrap(),
    );
    json!({"result":{"authorizationHeader":format!("MCToken {label}.{claims}.synthetic"),
        "validUntil":"2099-01-01T00:00:00Z", "treatments":["fixture"],
        "configurations":{"fixture":{"id":"Minecraft","parameters":{"enabled":"true"}}},
        "treatmentContext":"fixture"}})
}

/// Drives discovery and actual HTTP through Xbox, title NSAL, PlayFab and key-bound mint.
#[tokio::test]
async fn service_chain_reuses_state_and_retries_only_the_rejected_issuance() {
    let key = p384::ecdsa::SigningKey::from_slice(&[1; 48]).unwrap();
    let der = key.verifying_key().to_public_key_der().unwrap();
    let expected_der = der.as_bytes().to_vec();
    let device_id = Uuid::from_u128(1);
    let version = "1.26.50";
    let protocol = 2193;
    let mut step = 0;
    let mut session_id = None;
    let (address, server) = fixture(move |target, header, body| {
        step += 1;
        let headers = header.to_ascii_lowercase();
        let host = header.lines().filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("host")).unwrap().1.trim();
        match step {
            1 => {
                assert_eq!(target, format!("/api/v1.0/discovery/MinecraftPE/builds/{version}"));
                assert!(headers.contains(&format!("user-agent: {USER_AGENT}")));
                (200,json!({"result":{"serviceEnvironments":{
                    "auth":{"prod":{"serviceUri":format!("http://{host}/prefix"),"playFabTitleId":"AB12"},
                        "unrelated":{"unrecognized":"ignored"}},
                    "unrelated":{"prod":{"unrecognized":"ignored"}}
                }}}))
            }
            2 => { assert_eq!(target,"/device-token"); (200,token("device",false)) }
            3 => { assert_eq!(target,"/nsal"); (200,json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1",
                "HostType":"fqdn","RelyingParty":"http://xboxlive.com"}]})) }
            4 => { assert_eq!(target,"/sisu"); (200,json!({"TitleToken":token("title",false),
                "UserToken":token("user",true),"AuthorizationToken":token("xbox",true)})) }
            5 => {
                assert_eq!(target,"/nsal-current");
                assert!(headers.contains("authorization: xbl3.0 x=synthetic;xbox"));
                assert!(headers.contains("signature: "));
                (200,json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn",
                    "Path":"/Client/LoginWithXbox","RelyingParty":"rp://title-playfab"}]}))
            }
            6 => {
                assert_eq!(target,"/xsts");
                let body: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(body["RelyingParty"],"rp://title-playfab");
                (200,token("playfab",true))
            }
            7 => {
                assert_eq!(target,"/Client/LoginWithXbox");
                assert!(!headers.contains("authorization:"));
                let body: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(body["TitleId"],"AB12");
                assert_eq!(body["CreateAccount"],true);
                assert_eq!(body["XboxToken"],"XBL3.0 x=synthetic;playfab");
                (200,json!({"data":{"SessionTicket":"ticket","PlayFabId":"player",
                    "EntityToken":{"EntityToken":"entity","TokenExpiration":"2030-01-01T01:00:00Z",
                    "Entity":{"Id":"title-player","Type":"title_player_account"}}}}))
            }
            8 | 10 => {
                assert_eq!(target,"/prefix/api/v1.0/session/start");
                let id = headers.lines().find_map(|line| line.strip_prefix("session-id: ")).unwrap();
                let parsed = Uuid::parse_str(id).unwrap();
                assert!(!parsed.is_nil());
                if let Some(expected) = session_id { assert_eq!(parsed,expected); } else { session_id=Some(parsed); }
                assert!(headers.contains(&format!("user-agent: {USER_AGENT}")));
                assert!(headers.contains("accept: application/json"));
                let body: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(body["user"]["token"],"ticket");
                assert_eq!(body["user"]["tokenType"],"PlayFab");
                assert_eq!(body["device"]["id"],device_id.to_string());
                assert_eq!(body["device"]["networkProtocolVersion"],protocol);
                assert_eq!(body["device"]["hardwareMemoryTier"],5);
                assert_eq!(body["device"]["platform"],"Windows10");
                assert_eq!(body["device"]["capabilities"],json!([]));
                (200,service_token(if step == 8 {"original"} else {"replacement"}))
            }
            9 | 11 => {
                assert_eq!(target,"/prefix/api/v1.0/multiplayer/session/start");
                let id = headers.lines().find_map(|line| line.strip_prefix("session-id: ")).unwrap();
                assert_eq!(Uuid::parse_str(id).unwrap(),session_id.unwrap());
                let body: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(STANDARD.decode(body["publicKey"].as_str().unwrap()).unwrap(),expected_der);
                if step == 9 {
                    assert!(headers.contains("authorization: mctoken original."));
                    (401,json!({"diagnostic":"SECRET"}))
                } else {
                    assert!(headers.contains("authorization: mctoken replacement."));
                    (200,json!({"result":{"signedToken":"synthetic-multiplayer","validUntil":"2099-01-01T00:00:00Z"}}))
                }
            }
            12..=14 => {
                assert_eq!(target,"/prefix/api/v1.0/multiplayer/session/start");
                let mut result=json!({"signedToken":"SECRET"});
                if step == 12 { result["validUntil"]=json!("0001-01-01T00:00:00Z"); }
                if step == 13 { result["validUntil"]=json!("malformed"); }
                (200,json!({"result":result}))
            }
            15 | 16 | 19 | 20..=24 => {
                assert_eq!(target,"/Authentication/GetEntityToken");
                assert!(!headers.contains("authorization:"));
                let source = match step { 15 => "entity",16 => "master",19 => "entity2",_ => "master2" };
                assert!(headers.contains(&format!("x-entitytoken: {source}")));
                let body: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(body,json!({"Entity":{"Id":"player","Type":"master_player_account"}}));
                let mut result=json!({"EntityToken":if step == 15 {"master"} else {"master2"},
                    "TokenExpiration":match step {15 => "2030-01-01T01:00:00Z",19 => "2030-01-01T03:00:00Z",_ => "2030-01-01T02:00:00Z"},
                    "Entity":{"Id":"player","Type":"master_player_account"}});
                if step >= 20 { result["EntityToken"]=json!("SECRET"); }
                match step {
                    20 => result["Entity"]["Id"]=json!("different-player"),
                    21 => result["Entity"]["Type"]=json!("title_player_account"),
                    22 => result["TokenExpiration"]=json!("2030-01-01T00:00:00Z"),
                    23 => { result.as_object_mut().unwrap().remove("TokenExpiration"); },
                    24 => result["TokenExpiration"]=json!("malformed"),
                    _ => {},
                }
                (200,json!({"data":result}))
            }
            17 => {
                assert_eq!(target,"/Authentication/GetEntityToken");
                assert!(headers.contains("x-entitytoken: master2"));
                (401,json!({"diagnostic":"SECRET"}))
            }
            18 => {
                assert_eq!(target,"/Client/LoginWithXbox");
                (200,json!({"data":{"SessionTicket":"ticket2","PlayFabId":"player",
                    "EntityToken":{"EntityToken":"entity2","TokenExpiration":"2030-01-02T00:00:00Z",
                    "Entity":{"Id":"title-player","Type":"title_player_account"}}}}))
            }
            25 | 26 => {
                assert_eq!(target,"/Authentication/GetEntityToken");
                let (source, id, kind, credential) = if step == 25 {
                    ("entity2","title-player","title_player_account","entity3")
                } else {
                    ("entity3","player","master_player_account","master3")
                };
                assert!(headers.contains(&format!("x-entitytoken: {source}")));
                let body: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(body,json!({"Entity":{"Id":id,"Type":kind}}));
                (200,json!({"data":{"EntityToken":credential,"TokenExpiration":"2030-01-03T00:00:00Z",
                    "Entity":{"Id":id,"Type":kind}}}))
            }
            _ => panic!("unexpected service request {step}: {target}"),
        }
    },26).await;
    let xbox_config = xbox::Config::default();
    let credentials = Credentials::from_tokens(
        xbox_config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4102444800),
    )
    .unwrap();
    let account = xbox::Account::new(Http::fixture(address), xbox_config, credentials).unwrap();
    let mut minecraft =
        Minecraft::new(account, Config::desktop(version, protocol, device_id)).unwrap();
    minecraft.http = Http::fixture_agent(address, USER_AGENT);
    let start = UNIX_EPOCH + Duration::from_secs(1_893_456_000);
    minecraft.http.set_fixture_time(start);
    let original = minecraft.authorize().await.unwrap();
    assert!(Arc::ptr_eq(
        &original,
        &minecraft.authorize().await.unwrap()
    ));
    assert_eq!(original.treatments(), ["fixture"]);
    assert_eq!(
        original.configurations()["fixture"].parameters["enabled"],
        "true"
    );
    let playfab = minecraft.playfab().await.unwrap();
    assert_eq!(playfab.player_id(), "player");
    assert_eq!(playfab.entity().id(), "title-player");
    assert!(playfab.entity().header_value().unwrap().is_sensitive());
    let minted = minecraft
        .multiplayer_token(key.verifying_key())
        .await
        .unwrap();
    assert_eq!(minted.as_str(), "synthetic-multiplayer");
    assert_eq!(minted.public_key_der(), der.as_bytes());
    let replacement = minecraft.authorize().await.unwrap();
    assert!(!Arc::ptr_eq(&original, &replacement));
    assert!(!minecraft.reject(&original));
    assert!(Arc::ptr_eq(&playfab, &minecraft.playfab().await.unwrap()));
    for _ in 0..3 {
        let error = minecraft
            .multiplayer_token(key.verifying_key())
            .await
            .err()
            .expect("invalid multiplayer expiry must be rejected");
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    let title = minecraft
        .entity(playfab::EntityKind::TitlePlayerAccount)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&title, &playfab.entity));
    let master = minecraft
        .entity(playfab::EntityKind::MasterPlayerAccount)
        .await
        .unwrap();
    assert_eq!(master.id(), "player");
    assert!(master.header_value().unwrap().is_sensitive());
    assert!(Arc::ptr_eq(
        &master,
        &minecraft
            .entity(playfab::EntityKind::MasterPlayerAccount)
            .await
            .unwrap()
    ));
    minecraft
        .http
        .set_fixture_time(start + Duration::from_secs(50 * 60));
    let renewed = minecraft
        .entity(playfab::EntityKind::MasterPlayerAccount)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&master, &renewed));
    // Simulate a service rejecting the current exchange source before its hard expiry.
    minecraft
        .http
        .set_fixture_time(start + Duration::from_secs(110 * 60));
    let recovered = minecraft
        .entity(playfab::EntityKind::MasterPlayerAccount)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&renewed, &recovered));
    assert!(Arc::ptr_eq(
        &replacement,
        &minecraft.authorize().await.unwrap()
    ));
    minecraft
        .http
        .set_fixture_time(start + Duration::from_secs(170 * 60));
    for _ in 0..5 {
        let error = minecraft
            .entity(playfab::EntityKind::MasterPlayerAccount)
            .await
            .err()
            .expect("mismatched or invalid entity credential must be rejected");
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    let title2 = minecraft
        .entity(playfab::EntityKind::TitlePlayerAccount)
        .await
        .unwrap();
    minecraft
        .http
        .set_fixture_time(start + Duration::from_secs(23 * 3600 + 50 * 60));
    let title3 = minecraft
        .entity(playfab::EntityKind::TitlePlayerAccount)
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&title2, &title3));
    minecraft
        .http
        .set_fixture_time(start + Duration::from_secs(24 * 3600 + 10 * 60));
    let master3 = minecraft
        .entity(playfab::EntityKind::MasterPlayerAccount)
        .await
        .unwrap();
    assert_eq!(master3.id(), "player");
    assert_eq!(master3.header_value().unwrap(), "master3");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Checks malformed or expired credential metadata without disclosing its secret bytes.
#[test]
fn malformed_service_credentials_fail_without_panicking_or_leaking() {
    let now = UNIX_EPOCH + Duration::from_secs(3600);
    for (field, value) in [
        ("validUntil", json!("0001-01-01T00:00:00Z")),
        ("authorizationHeader", json!("SECRET.malformed.credential")),
    ] {
        let mut response = service_token("SECRET")["result"].clone();
        response[field] = value;
        let token: token::TokenResponse = serde_json::from_value(response).unwrap();
        let error = token.authorization(now).err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
}
