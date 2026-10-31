use super::*;
use crate::xbox::test_support::{fixture_headers, token};
use crate::{http::Http, oauth::Credentials, xbox::Config};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256};
use std::time::{Duration, UNIX_EPOCH};

const SIGNED_HEADERS: &[&str] = &[
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Cache-Control",
    "Content-Type",
    "Content-Length",
    "X-Xbl-Contract-Version",
];

/// Verifies transmitted service requests independently of the production digest builder.
fn verify(header: &str, target: &str, body: &[u8], point: &Value) {
    let value = |name: &str| {
        header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map_or("", |(_, value)| value.trim())
    };
    let encoded = STANDARD.decode(value("signature")).unwrap();
    let mut hash = Sha256::new();
    let method = header
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    for field in [
        &encoded[..4],
        &encoded[4..12],
        method.as_bytes(),
        target.as_bytes(),
        value("authorization").as_bytes(),
    ] {
        hash.update(field);
        hash.update([0]);
    }
    for extra in SIGNED_HEADERS {
        hash.update(value(extra).as_bytes());
        hash.update([0]);
    }
    hash.update(body);
    hash.update([0]);
    let mut bytes = vec![4];
    bytes.extend(
        URL_SAFE_NO_PAD
            .decode(point["x"].as_str().unwrap())
            .unwrap(),
    );
    bytes.extend(
        URL_SAFE_NO_PAD
            .decode(point["y"].as_str().unwrap())
            .unwrap(),
    );
    VerifyingKey::from_sec1_bytes(&bytes)
        .unwrap()
        .verify_prehash(
            &hash.finalize(),
            &Signature::from_slice(&encoded[12..]).unwrap(),
        )
        .unwrap();
}

/// Exercises one real HTTP service chain, unknown state, identity binding and exact rejection reuse.
#[tokio::test]
async fn social_reads_share_account_policy_and_preserve_unknown_presence_and_session_data() {
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture_headers(move |target, header, body| {
        step += 1;
        let mut response_headers = Vec::new();
        let (status, value) = match step {
            1 => {
                assert_eq!(target, "/device-token");
                let value: Value = serde_json::from_slice(body).unwrap();
                proof = Some(value["Properties"]["ProofKey"].clone());
                (200, token("device", false))
            }
            2 => {
                assert_eq!(target, "/nsal");
                (200, json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                    "RelyingParty": XBOX_RELYING_PARTY, "SignaturePolicyIndex": 0}], "SignaturePolicies": [{"Version": 1}]}))
            }
            3 => {
                assert_eq!(target, "/sisu");
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(&value["ProofKey"], proof.as_ref().unwrap());
                (200, json!({"TitleToken": token("title", false), "UserToken": token("user", false),
                    "AuthorizationToken": token("default", true)}))
            }
            4 => {
                assert_eq!(target, "/nsal-current");
                assert!(header.to_lowercase().contains("authorization: xbl3.0 x=synthetic;default"));
                (200, json!({"EndPoints": [{"Protocol": "http", "Host": "127.0.0.1", "HostType": "fqdn",
                    "RelyingParty": "rp://social", "SignaturePolicyIndex": 0}], "SignaturePolicies": [{"Version": 1,
                    "ExtraHeaders": SIGNED_HEADERS}]}))
            }
            5 | 11 => {
                assert_eq!(target, "/xsts");
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value["RelyingParty"], "rp://social");
                (200, token(if step == 5 { "social-before" } else { "social-after" }, true))
            }
            _ => {
                verify(header, target, body, proof.as_ref().unwrap());
                let expected = if step < 11 { "social-before" } else { "social-after" };
                assert!(header.to_lowercase().contains(&format!("authorization: xbl3.0 x=synthetic;{expected}")));
                match step {
                    6 => {
                        assert_eq!(target, format!("/users/me/people/friends/decoration/{DECORATIONS}"));
                        assert!(header.to_lowercase().contains("accept: application/json\r\n"));
                        assert!(header.to_lowercase().contains(&format!("accept-language: fr-FR, {DEFAULT_LANGUAGE}").to_lowercase()));
                        assert!(header.to_lowercase().contains(&format!("x-xbl-contract-version: {}", Service::People.contract())));
                        (200, json!({"futureField": {}, "people": [{"xuid": "321", "gamertag": "Fixture", "presenceState": "FutureState",
                            "gamerScore": "17", "presenceDetails": [{"State": "FutureActivity", "TitleId": "123", "Device": "FutureDevice"}],
                            "multiplayerSummary": {"futureRestriction": "unknown"}}, {"displayName": "Partial", "gamerScore": {"unknown": true}, "presenceDetails": null}]}))
                    }
                    7 => {
                        assert_eq!(target, "/users/me/people/followers");
                        (200, json!({"people": [{"xuid": "456"}]}))
                    }
                    8 => {
                        assert_eq!(target, format!("/users/me/people/xuids(321)/decoration/{DECORATIONS}"));
                        (200, json!({"people": [{"xuid": "999", "gamertag": "wrong-account"}]}))
                    }
                    9 => {
                        assert_eq!(target, "/users/xuid(321)?level=all");
                        assert!(header.to_lowercase().contains("accept: */*\r\n"));
                        assert!(header.to_lowercase().contains("cache-control: no-cache"));
                        assert!(header.to_lowercase().contains(&format!("x-xbl-contract-version: {}", Service::Presence.contract())));
                        // An ordinary authorization failure must not evict the cached issuance.
                        (401, json!({"error": "SENSITIVE-body"}))
                    }
                    10 => {
                        response_headers.push(("WWW-Authenticate", "Token error=\"token_expired\""));
                        (401, json!({"error": "SENSITIVE-body"}))
                    }
                    12 => {
                        assert_eq!(target, "/users/xuid(321)?level=all");
                        (200, json!({"xuid": "321", "state": "FuturePresence", "devices": [{"type": "FutureConsole", "titles": [{"id": 123,
                            "name": "Fixture", "activity": {"richPresence": "Playing", "future": true}}]}], "unknown": true}))
                    }
                    13 | 14 => {
                        assert_eq!(target, "/handles/query?include=relatedInfo,customProperties");
                        assert!(header.to_lowercase().contains(&format!("x-xbl-contract-version: {}", Service::Activities.contract())));
                        let value: Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(value["type"], "activity");
                        if step == 13 {
                            assert_eq!(value["owners"]["people"]["monikerXuid"], "123");
                            assert!(value["owners"].get("xuids").is_none());
                        } else {
                            assert_eq!(value["owners"]["xuids"], json!(["321"]));
                            assert!(value["owners"].get("people").is_none());
                        }
                        (200, json!({"results": [{"type": "futureActivity", "ownerXuid": "321", "sessionRef": {"scid": value["scid"],
                            "templateName": "Minecraft", "name": "UPPERCASE-SESSION"}, "relatedInfo": {"joinRestriction": "FutureRestriction"},
                            "customProperties": {"transport": "unknown", "device": {"network": "opaque"}}}, {"type": "partial"}]}))
                    }
                    15 => {
                        assert_eq!(target, "/users/batch");
                        assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"users": ["321"], "level": "all"}));
                        (200, json!([{"xuid": "321", "state": "Away", "devices": null}]))
                    }
                    16 => {
                        assert_eq!(target, format!("/users/me/people/batch/decoration/{DECORATIONS}"));
                        assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"xuids": ["321"]}));
                        (200, json!({"people": [{"xuid": "321", "presenceState": "Online", "isFriend":true, "isFriendRequestSent":false, "isFriendRequestReceived":true}]}))
                    }
                    17 => {
                        assert_eq!(target, format!("/users/me/people/xuids(123)/decoration/{DECORATIONS}"));
                        (200, json!({"people": [{"xuid": "123", "gamertag": "Self"}]}))
                    }
                    18 => {
                        assert_eq!(target, "/users/me?level=all");
                        (200, json!({"xuid": "123", "state": "Offline", "devices": null}))
                    }
                    19..=21 => {
                        assert_eq!(target, "/users/me/profile/settings/batch");
                        let lower = header.to_ascii_lowercase();
                        assert!(lower.starts_with("post "));
                        assert!(lower.contains("x-xbl-contract-version: 3"));
                        assert!(lower.contains("content-type: application/json"));
                        assert!(lower.contains(&format!("accept-language: fr-FR, {DEFAULT_LANGUAGE}").to_ascii_lowercase()));
                        assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"settings":[{"userSetting":{"id":"FutureSetting","value":"opaque"}}]}));
                        (match step { 19 => 201, 20 => 503, _ => 200 }, json!({"error":"SENSITIVE-body"}))
                    }
                    _ => panic!("unexpected social request"),
                }
            }
        };
        (status, response_headers, value)
    }, 21).await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let mut social = account.social().with_language("fr-FR").unwrap();
    social.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    assert!(social.profiles(&[]).await.unwrap().is_empty());
    assert!(social.presences(&[]).await.unwrap().is_empty());
    assert!(social.profile("../credentials").await.is_err());
    assert!(social.activities(uuid::Uuid::nil(), &[]).await.is_err());
    assert!(
        social
            .presences(&vec!["321"; MAX_BATCH_USERS + 1])
            .await
            .is_err()
    );
    let users = social
        .people(PeopleList::Friends, ProfileDetail::Full)
        .await
        .unwrap();
    assert!(!users[0].is_online());
    assert_eq!(users[0].presence_state.as_deref(), Some("FutureState"));
    assert_eq!(users[0].gamerscore, Some(17));
    assert_eq!(users[0].presence_details[0].title_id, Some(123));
    assert_eq!(
        users[0].presence_details[0].device.as_deref(),
        Some("FutureDevice")
    );
    assert_eq!(users[1].gamerscore, None);
    let basic = social
        .people(PeopleList::Followers, ProfileDetail::Basic)
        .await
        .unwrap();
    assert!(basic[0].presence_state.is_none());
    assert!(social.profile("321").await.is_err());
    for _ in 0..2 {
        let error = social.presence("321").await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    let presence = social.presence("321").await.unwrap();
    assert_eq!(presence.state.as_deref(), Some("FuturePresence"));
    assert_eq!(
        presence.devices[0].device_type.as_deref(),
        Some("FutureConsole")
    );
    let scid = uuid::Uuid::from_u128(1);
    for users in [&[][..], &["321"][..]] {
        let activities = social.activities(scid, users).await.unwrap();
        assert_eq!(
            activities[0].session.as_ref().unwrap().name.as_deref(),
            Some("UPPERCASE-SESSION")
        );
        let info = activities[0].related_info.as_ref().unwrap();
        assert_eq!(info.closed, None);
        assert_eq!(info.join_restriction.as_deref(), Some("FutureRestriction"));
        assert!(activities[1].related_info.is_none());
    }
    assert_eq!(
        social.presences(&["321"]).await.unwrap()[0]
            .state
            .as_deref(),
        Some("Away")
    );
    let batch = social.profiles(&["321"]).await.unwrap();
    assert!(batch[0].is_online());
    assert_eq!(batch[0].is_friend, Some(true));
    assert_eq!(batch[0].is_friend_request_sent, Some(false));
    assert_eq!(batch[0].is_friend_request_received, Some(true));
    assert_eq!(users[0].is_friend, None);
    assert_eq!(social.current_profile().await.unwrap().xuid, "123");
    assert_eq!(
        social.current_presence().await.unwrap().state.as_deref(),
        Some("Offline")
    );
    let mut settings = ProfileSettings::default();
    settings.insert("FutureSetting".into(), "opaque".into());
    social.update_profile_settings(&settings).await.unwrap();
    for _ in 0..2 {
        let error = social
            .update_profile_settings(&settings)
            .await
            .err()
            .unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
/// The service envelope retains arbitrary setting IDs and last-write duplicate semantics.
#[test]
fn profile_settings_preserve_unknown_entries_and_wire_formats() {
    let mut settings: ProfileSettings = serde_json::from_value(json!({"settings":[
        {"userSetting":{"id":"Bio","value":"before"}},
        {"userSetting":{"id":"FutureSetting","value":"opaque"}},
        {"userSetting":{"id":"Bio","value":"after"}},
        {"userSetting":{"id":"Location","value":""}}
    ]}))
    .unwrap();
    assert_eq!(settings["Bio"], "after");
    assert_eq!(settings["FutureSetting"], "opaque");
    assert_eq!(settings["Location"], "");
    settings = settings
        .with_show_user_as_avatar(true)
        .with_preferred_platforms(&["pc", "future"]);
    assert!(settings.show_user_as_avatar());
    assert_eq!(settings["ShowUserAsAvatar"], "1");
    assert_eq!(settings.preferred_platforms(), ["pc", "future"]);
    assert_eq!(settings["PreferredPlatforms"], "pc,future");
    let decoded: ProfileSettings =
        serde_json::from_value(serde_json::to_value(&settings).unwrap()).unwrap();
    assert_eq!(decoded, settings);
    let disabled = settings.with_show_user_as_avatar(false);
    assert!(!disabled.show_user_as_avatar());
    assert_eq!(disabled["ShowUserAsAvatar"], "0");
    for value in [
        json!(null),
        json!({}),
        json!({"settings":null}),
        json!({"settings":[]}),
    ] {
        assert!(
            serde_json::from_value::<ProfileSettings>(value)
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        serde_json::to_value(ProfileSettings::default()).unwrap(),
        json!({"settings":[]})
    );
    for value in [
        json!([]),
        json!({"settings":{}}),
        json!({"settings":[[]]}),
        json!({"settings":[{"userSetting":[]}]}),
        json!({"settings":[{"userSetting":{"id":7}}]}),
    ] {
        assert!(serde_json::from_value::<ProfileSettings>(value).is_err());
    }
}
/// Presence title IDs accept decimal strings and numbers in single and batch response shapes.
#[test]
fn presence_title_ids_regression() {
    for id in [json!(123), json!("123")] {
        let record =
            json!({"xuid":"321","devices":[{"titles":[{"id":id}]}],"lastSeen":{"titleId":id}});
        let single: Presence = serde_json::from_value(record.clone()).unwrap();
        let batch: Vec<Presence> = serde_json::from_value(json!([record])).unwrap();
        for presence in std::iter::once(single).chain(batch) {
            assert_eq!(presence.devices[0].titles[0].id, Some(123));
            assert_eq!(presence.last_seen.unwrap().title_id, Some(123));
        }
    }
    for id in [json!("4294967296"), json!(-1), json!(1.5), json!("bad")] {
        let record =
            json!({"xuid":"321","devices":[{"titles":[{"id":id}]}],"lastSeen":{"titleId":id}});
        assert!(serde_json::from_value::<Presence>(record).is_err());
    }
}
