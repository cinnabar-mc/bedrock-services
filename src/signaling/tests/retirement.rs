use super::*;

/// Retiring one credential request preserves unrelated waits, prior cache and a later successor.
#[test]
fn credential_retirement_matches_only_its_pending_or_completed_request() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(30);
    let mut state = Messaging::new(7);
    let result = |name| {
        json!({"ExpirationInSeconds":60,"TurnAuthServers":[{
            "Username":name,"Password":"synthetic-retirement-password","Urls":["turn:fixture.invalid:3478"]
        }]})
    };
    let old = state.request_credentials(deadline).unwrap();
    let old_id = old.request_id().unwrap();
    assert!(completed(
        &state
            .receive(&accepted(&old, result("original")), now)
            .unwrap(),
        old_id,
        Ok(())
    ));
    let fresh = state.request_credentials(deadline).unwrap();
    let fresh_id = fresh.request_id().unwrap();
    let ping = state.ping(deadline).unwrap();
    let ping_id = ping.request_id().unwrap();
    assert!(!state.retire_credentials(ping_id));
    assert!(state.retire_credentials(fresh_id));
    assert!(!state.retire_credentials(fresh_id));
    assert_eq!(
        state.credentials(now).unwrap().servers()[0].username(),
        "original"
    );
    assert!(
        state
            .receive(&accepted(&fresh, result("retired")), now)
            .unwrap()
            .iter()
            .all(|event| matches!(event, Event::Ignored))
    );
    assert!(completed(
        &state.receive(&accepted(&ping, Value::Null), now).unwrap(),
        ping_id,
        Ok(())
    ));
    assert!(state.retire_credentials(old_id));
    assert!(state.credentials(now).is_none());
    let next = state.request_credentials(deadline).unwrap();
    let next_id = next.request_id().unwrap();
    let events = state
        .receive(&accepted(&next, result("successor")), now)
        .unwrap();
    assert!(completed(&events, next_id, Ok(())));
    assert!(!state.retire_credentials(old_id));
    assert_eq!(
        state.credentials(now).unwrap().servers()[0].username(),
        "successor"
    );
    let owner = state.take_credentials(now).unwrap();
    assert!(!state.retire_credentials(next_id));
    assert!(state.take_credentials(now).is_none());
    assert_eq!(owner.servers()[0].username(), "successor");
}
