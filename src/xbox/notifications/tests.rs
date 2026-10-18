use super::*;
use crate::{
    http::Http,
    oauth::Credentials,
    xbox::{
        Config,
        mpsd::tests::signed_service_script,
        test_support::{fixture_headers, token},
    },
};
use serde_json::json;
use std::time::{Duration, UNIX_EPOCH};
use uuid::Uuid;

/// Builds original service-shaped invitation data with a distinct actor and recipient.
fn item(handle: Uuid) -> Value {
    json!({
        "SubscriptionCategory": CATEGORY, "SubscriptionType": INVITE_TYPE,
        "SubscriptionId": "notification-one", "OtherActionCount": 7,
        "MarkedRead": false, "Seen": true,
        "NotificationOptions": {
            "Location": {"Id": "12345", "Type": 3, "Name": "Fixture title", "Pfn": "fixture.family"},
            "Platforms": ["android", "FuturePlatform"]
        },
        "Actions": [{
            "Actor": {"Id": "321", "Type": 1, "ModernGamertag": "Inviter"},
            "ActionId": "action-one", "ActionTime": "2098-01-01T00:00:00Z",
            "LaunchInfo": {"mpsdHandleId": handle, "expirationTime": "2099-01-01T00:00:00Z",
                "gameTypes": "{\"FuturePlatform\":{\"titleId\":\"12345\",\"pfn\":\"fixture.family\",\"boundPfns\":[\"fixture.other\"]}}"}
        }],
        "FutureMetadata": {"anything": true}
    })
}

/// Exercises the actual signed HTTP path, recipient binding, action forms and bounded neighbors.
#[tokio::test]
async fn inbox_read_preserves_invitation_forms_without_mutating_or_accepting_them() {
    let handle = Uuid::from_u128(73);
    let (mut account, address, server) = signed_service_script(
        CONTRACT,
        true,
        move |step, target, headers, body| {
            assert!(headers.starts_with("GET "));
            assert!(
                body.is_empty(),
                "inbox refresh must not mark or accept notifications"
            );
            let url = Url::parse(&format!("http://fixture{target}")).unwrap();
            assert_eq!(url.path(), "/users/123/inbox");
            let query = url
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(query.len(), 4);
            assert_eq!(query["maxItems"], MAX_INBOX_ITEMS.to_string());
            assert_eq!(query["maxActions"], MAX_INBOX_ACTIONS.to_string());
            assert_eq!(query["subscriptionCategory"], CATEGORY);
            assert_eq!(query["subscriptionType"], INVITE_TYPE);
            let mut singleton = item(handle);
            singleton["Action"] = singleton["Actions"][0].clone();
            singleton.as_object_mut().unwrap().remove("Actions");
            let mut combined = item(handle);
            combined["Action"] = combined["Actions"][0].clone();
            combined["Action"]["ActionId"] = json!("singleton-last");
            let mut malformed = item(handle);
            malformed["Actions"][0]["LaunchInfo"]["gameTypes"] = json!("SENSITIVE-not-json");
            match step {
                1 => (
                    200,
                    vec![("Date", "Thu, 01 Jan 2026 00:00:00 GMT")],
                    json!({"items": [item(handle), singleton, combined,
                {"SubscriptionCategory": CATEGORY, "SubscriptionType": "FutureType"}, malformed,
                {"SubscriptionCategory": CATEGORY}, null]}),
                ),
                2 => (200, vec![], json!({"items": null})),
                3 => (
                    200,
                    vec![],
                    json!({"items": vec![json!({}); MAX_INBOX_ITEMS + 1]}),
                ),
                4 => (403, vec![], json!({"error": "SENSITIVE-service-body"})),
                _ => unreachable!(),
            }
        },
        4,
    )
    .await;
    let mut notifications = account.notifications();
    notifications.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let inbox = notifications.game_invites().await.unwrap();
    assert_eq!(inbox.owner_xuid(), "123");
    assert_eq!(inbox.invites.len(), 3);
    assert_eq!(inbox.unsupported_items, 1);
    assert_eq!(inbox.malformed_items, 3);
    assert!(
        inbox.observed_time()
            >= httpdate::parse_http_date("Thu, 01 Jan 2026 00:00:00 GMT").unwrap()
    );
    assert!(inbox.observed_at() <= Instant::now());
    for invite in &inbox.invites {
        assert_eq!(invite.subscription_id, "notification-one");
        assert_eq!(invite.options.location.id, "12345");
        assert_eq!(invite.options.location.kind, 3);
        assert_eq!(invite.options.platforms, ["android", "FuturePlatform"]);
        assert_eq!(invite.other_action_count, 7);
        assert!(!invite.marked_read);
        assert!(invite.seen);
        let action = &invite.actions[0];
        assert_eq!(action.actor.id, "321");
        assert_eq!(action.actor.modern_gamertag, "Inviter");
        assert_eq!(action.launch_info.handle, handle);
        assert_eq!(
            action.launch_info.expires,
            UNIX_EPOCH + Duration::from_secs(4_070_908_800)
        );
        assert_eq!(
            action.launch_info.game_types["FuturePlatform"].title_id,
            "12345"
        );
        assert_eq!(
            action.launch_info.game_types["FuturePlatform"].bound_package_family_names,
            ["fixture.other"]
        );
    }
    assert_eq!(inbox.invites[2].actions.len(), 2);
    assert_eq!(inbox.invites[2].actions[1].action_id, "singleton-last");
    assert!(
        notifications
            .game_invites()
            .await
            .unwrap()
            .invites
            .is_empty()
    );
    for _ in 0..2 {
        let error = notifications.game_invites().await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    server.await.unwrap();
}

/// Resolves the complete account path's policy and rejects a cross-XUID issuance before inbox I/O.
#[tokio::test]
async fn inbox_recipient_is_checked_against_the_actual_path_scoped_authorization() {
    let mut step = 0;
    let mut proof = None;
    let (address, server) = fixture_headers(move |target, _, body| {
        step += 1;
        let value = match step {
            1 => {
                assert_eq!(target, "/device-token");
                proof = Some(serde_json::from_slice::<Value>(body).unwrap()["Properties"]["ProofKey"].clone());
                token("device", false)
            }
            2 => {
                assert_eq!(target, "/nsal");
                json!({"EndPoints": [{"Protocol":"http", "Host":"127.0.0.1", "HostType":"fqdn", "RelyingParty":XBOX_RELYING_PARTY}]})
            }
            3 => {
                assert_eq!(target, "/sisu");
                assert_eq!(&serde_json::from_slice::<Value>(body).unwrap()["ProofKey"], proof.as_ref().unwrap());
                json!({"TitleToken":token("title",false),"UserToken":token("user",false),"AuthorizationToken":token("default",true)})
            }
            4 => {
                assert_eq!(target, "/nsal-current");
                json!({"EndPoints":[{"Protocol":"http", "Host":"127.0.0.1", "HostType":"fqdn", "Path":"/users/123/inbox", "RelyingParty":"rp://inbox"}]})
            }
            5 => {
                assert_eq!(target, "/xsts");
                assert_eq!(serde_json::from_slice::<Value>(body).unwrap()["RelyingParty"], "rp://inbox");
                let mut wrong = token("wrong-recipient", true);
                wrong["DisplayClaims"]["xui"][0]["xid"] = json!("999");
                wrong
            }
            _ => panic!("cross-XUID authorization must never reach the inbox"),
        };
        (200, vec![], value)
    }, 5).await;
    let config = Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let mut account = Account::new(Http::fixture(address), config, credentials).unwrap();
    let mut notifications = account.notifications();
    notifications.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    assert!(matches!(
        notifications.game_invites().await,
        Err(Error::Invalid("notification recipient identity"))
    ));
    server.await.unwrap();
}

/// Required handle/expiry/action framing fails closed while future metadata remains uninterpreted.
#[test]
fn inbox_decoder_bounds_actions_and_rejects_unusable_launch_metadata() {
    let original = item(Uuid::from_u128(73));
    let mut too_many = original.clone();
    too_many["Actions"] = json!(vec![original["Actions"][0].clone(); MAX_INBOX_ACTIONS + 1]);
    assert!(types::decode(too_many).is_err());
    for value in [json!(Uuid::nil()), json!("not-a-handle"), Value::Null] {
        let mut malformed = original.clone();
        malformed["Actions"][0]["LaunchInfo"]["mpsdHandleId"] = value;
        assert!(types::decode(malformed).is_err());
    }
    for value in [json!("not-a-timestamp"), Value::Null] {
        let mut malformed = original.clone();
        malformed["Actions"][0]["LaunchInfo"]["expirationTime"] = value;
        assert!(types::decode(malformed).is_err());
    }
    let mut no_action = original.clone();
    no_action["Actions"] = json!([]);
    assert!(types::decode(no_action).is_err());
    let mut action_only = original.clone();
    action_only["ActionId"] = json!("not-a-notification");
    assert!(types::decode(action_only).is_err());
    let mut unknown = original.clone();
    unknown["SubscriptionType"] = json!("Unknown");
    assert!(types::decode(unknown).unwrap().is_none());
    for value in [json!(""), json!("null"), Value::Null] {
        let mut empty_types = original.clone();
        empty_types["Actions"][0]["LaunchInfo"]["gameTypes"] = value;
        assert!(
            types::decode(empty_types).unwrap().unwrap().actions[0]
                .launch_info
                .game_types
                .is_empty()
        );
    }
    let mut both = original.clone();
    both["Actions"] = json!(vec![original["Actions"][0].clone(); MAX_INBOX_ACTIONS]);
    both["Action"] = original["Actions"][0].clone();
    assert_eq!(
        types::decode(both).unwrap().unwrap().actions.len(),
        MAX_INBOX_ACTIONS + 1
    );
}
