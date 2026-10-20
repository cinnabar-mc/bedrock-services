use super::*;
use crate::minecraft::{test_support, tests::discovery_owner};
use std::time::{Duration, UNIX_EPOCH};

/// Restores through the public account and Minecraft constructors without preinstalling time.
fn restart(owner: &Minecraft, config: Config) -> Minecraft {
    let bytes = Zeroizing::new(owner.checkpoint().unwrap().as_bytes().to_vec());
    let account = crate::oauth::MicrosoftAuth::new(xbox::Config::default())
        .unwrap()
        .restore_account(xbox::Checkpoint::from_bytes(bytes).unwrap())
        .unwrap();
    Minecraft::new(account, config).unwrap()
}

/// Creates synthetic acquired state with a bounded session, entity and original service clock.
fn acquired() -> Minecraft {
    let mut owner = discovery_owner("127.0.0.1:9".parse().unwrap());
    owner
        .http
        .set_fixture_time(UNIX_EPOCH + Duration::from_secs(1_893_456_000));
    owner.environment = Some(Environment {
        service_uri: "https://service.invalid/".into(),
        play_fab_title_id: "AB12".into(),
        issuer: "https://issuer.invalid/".into(),
    });
    owner.authorization = Some(test_support::authorization("saved"));
    let snapshot = serde_json::json!({
        "ticket":"synthetic-ticket", "player_id":"player",
        "reusable_until":owner.http.now() + Duration::from_secs(85_500),
        "entity_id":"entity", "entity_kind":"title_player_account",
        "entity_token":"synthetic-entity", "entity_expires":owner.http.now() + Duration::from_secs(3600)
    });
    let bytes = Zeroizing::new(serde_json::to_vec(&snapshot).unwrap());
    let saved: playfab::checkpoint::Snapshot<'_> = serde_json::from_slice(&bytes).unwrap();
    owner.playfab = saved.restore(owner.http.now()).map(Arc::new);
    owner
}

/// Simulates the actual discovery admission boundary with an explicit server Date.
fn admit(owner: &Minecraft, restored: &mut Minecraft, by: Duration) {
    restored.environment = owner.environment.clone();
    restored.http.set_fixture_time(owner.http.now() + by);
    restored.admit_service_checkpoint(restored.http.response_time());
}

/// Repeated saves retain dormant state; fresh discovery admits the same session and credentials.
#[test]
fn checkpoint_round_trip_retains_original_service_issuances() {
    let owner = acquired();
    let restored = restart(&owner, owner.config.clone());
    assert!(restored.authorization.is_none());
    assert!(restored.playfab.is_none());
    let mut restored = restart(&restored, owner.config.clone());
    admit(&owner, &mut restored, Duration::from_secs(10));
    assert_eq!(restored.session_id(), owner.session_id());
    assert_eq!(
        restored.authorization.unwrap().header_value().unwrap(),
        owner.authorization.unwrap().header_value().unwrap()
    );
    let session = restored.playfab.unwrap();
    assert_eq!(session.player_id(), "player");
    assert_eq!(session.ticket.as_str(), "synthetic-ticket");
    assert!(restored.entities[&playfab::EntityKind::TitlePlayerAccount].valid(restored.http.now()));
}

/// Expired service and PlayFab state are discarded independently using their original deadlines.
#[test]
fn checkpoint_never_reanchors_playfab_or_minecraft_expiry() {
    let mut owner = acquired();
    // This fixture issuance is far in the future; use its exact refresh boundary.
    let expires = SystemTime::from(
        time::OffsetDateTime::parse(
            "2099-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap(),
    );
    owner
        .http
        .set_fixture_time(expires - Duration::from_secs(61));
    let mut restored = restart(&owner, owner.config.clone());
    admit(&owner, &mut restored, Duration::from_secs(2));
    assert!(restored.authorization.is_none());
    assert!(restored.playfab.is_none());

    let owner = acquired();
    let mut restored = restart(&owner, owner.config.clone());
    admit(&owner, &mut restored, Duration::from_secs(85_500));
    assert!(restored.playfab.is_none());
    assert!(restored.authorization.is_some());
}

/// Changed device/version policy, service routes and missing or older Dates cannot admit secrets.
#[test]
fn checkpoint_admission_requires_matching_policy_route_and_fresh_date() {
    let owner = acquired();
    for control in 0..5 {
        let mut config = owner.config.clone();
        if control == 0 {
            config.game_version.push('1');
        }
        if control == 1 {
            config.device_id = uuid::Uuid::from_u128(2).into();
        }
        let mut restored = restart(&owner, config);
        restored.environment = owner.environment.clone();
        if control == 2 {
            restored.environment.as_mut().unwrap().service_uri =
                "https://replacement.invalid/".into();
        }
        if control != 3 {
            let now = owner.http.now();
            restored.http.set_fixture_time(if control == 4 {
                now - Duration::from_secs(1)
            } else {
                now
            });
        }
        restored.admit_service_checkpoint(restored.http.response_time());
        assert!(restored.authorization.is_none(), "control {control}");
        assert!(restored.playfab.is_none(), "control {control}");
    }
}

/// Optional large metadata cannot prevent saving and restoring required account credentials.
#[test]
fn checkpoint_oversized_service_cache_preserves_account() {
    let mut owner = acquired();
    owner.environment.as_mut().unwrap().issuer = "x".repeat(xbox::MAX_CHECKPOINT_BYTES);
    let restored = restart(&owner, owner.config.clone());
    assert!(restored.restored.is_none());
    assert_eq!(
        restored.credentials().refresh_token(),
        owner.credentials().refresh_token()
    );
}

/// Corrupt timestamps outside the calendar range discard optional state without panicking.
#[test]
fn checkpoint_calendar_overflow_is_rejected_without_panicking() {
    let owner = acquired();
    let mut restored = restart(&owner, owner.config.clone());
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(restored.restored.as_ref().unwrap()).unwrap();
    let overflow = serde_json::json!({"secs_since_epoch":i64::MAX,"nanos_since_epoch":0});
    snapshot["authorization"]["expires"] = overflow.clone();
    snapshot["playfab"]["entity_expires"] = overflow;
    restored.restored = Some(Zeroizing::new(serde_json::to_vec(&snapshot).unwrap()));
    admit(&owner, &mut restored, Duration::ZERO);
    assert!(restored.authorization.is_none());
    assert!(restored.playfab.is_none());
}

/// An earlier rejected or malformed response cannot qualify a later undated discovery.
#[tokio::test]
async fn checkpoint_requires_date_on_successful_discovery_response() {
    for case in 0..4 {
        let owner = acquired();
        let mut hit = 0;
        let (address, server) = crate::xbox::test_support::fixture_headers(move |_, _, _| {
            hit += 1;
            if hit == 1 {
                return (if case < 2 {400} else {200}, vec![("Date","Tue, 01 Jan 2030 00:00:10 GMT")], serde_json::json!({"invalid":"SENSITIVE"}));
            }
            (200, if case % 2 == 0 {vec![]} else {vec![("Date","invalid")]}, serde_json::json!({"result":{"serviceEnvironments":{"auth":{"prod":{
                "serviceUri":"https://service.invalid/", "playFabTitleId":"AB12", "issuer":"https://issuer.invalid/"
            }}}}}))
        }, 2).await;
        let mut restored = restart(&owner, owner.config.clone());
        restored.http = Http::fixture_agent(address, USER_AGENT);
        assert!(restored.discover().await.is_err());
        assert!(restored.restored.is_some());
        restored.discover().await.unwrap();
        server.await.unwrap();
        assert!(restored.authorization.is_none(), "case {case}");
        assert!(restored.playfab.is_none(), "case {case}");
    }
}
