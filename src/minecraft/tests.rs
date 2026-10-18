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
                    "EntityToken":{"EntityToken":"entity","TokenExpiration":"2099-01-01T00:00:00Z",
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
            _ => panic!("unexpected service request {step}: {target}"),
        }
    },14).await;
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
