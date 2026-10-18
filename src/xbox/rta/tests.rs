use super::*;
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Constructs original synthetic non-credential identity with a fixed test-only public proof.
fn connection() -> Connection {
    Connection::new(state::Scope {
        xuid: "123".into(),
        proof: *SigningKey::from_slice(&[7; 32]).unwrap().verifying_key(),
        generation: Generation::new(1).unwrap(),
        epoch: Epoch(Uuid::from_u128(1)),
    })
}

/// Feeds one original complete wire message without clocks, sleeping or network I/O.
fn receive(connection: &mut Connection, value: Value, now: Instant) -> Vec<Event> {
    connection
        .receive(
            connection.epoch(),
            &serde_json::to_vec(&value).unwrap(),
            now,
        )
        .unwrap()
}

/// Establishes one generic active resource using a real encoded request/response correlation.
fn active(connection: &mut Connection, now: Instant, server: u32) -> SubscriptionId {
    let (id, frame) = connection
        .subscribe(
            connection.social_resource(),
            now,
            now + Duration::from_secs(15),
        )
        .unwrap();
    assert!(matches!(
        receive(
            connection,
            json!([1,frame.request_id().sequence,0,server,{"version":1}]),
            now
        )
        .as_slice(),
        [Event::Subscribed { .. }]
    ));
    id
}

#[test]
fn correlation_orders_initial_snapshot_and_changes_without_replaying_responses() {
    let mut state = connection();
    let now = Instant::now();
    let (id, frame) = state
        .subscribe(state.social_resource(), now, now + Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(frame.as_str()).unwrap(),
        json!([1, 1, "https://social.xboxlive.com/users/xuid(123)/friends"])
    );
    assert!(receive(&mut state, json!([3,19,{"version":2}]), now).is_empty());
    // The same sequence on the wrong response operation cannot consume the pending subscribe.
    assert!(receive(&mut state, json!([2, 1, 0]), now).is_empty());
    let events = receive(&mut state, json!([1,1,0,19,{"version":1}]), now);
    assert!(
        matches!(events.as_slice(), [Event::Subscribed { subscription, initial, .. }] if *subscription == id && initial["version"] == 1)
    );
    assert!(receive(&mut state, json!([1,1,0,19,{"version":0}]), now).is_empty());
    assert!(!state.is_current(&frame));
    assert!(
        matches!(receive(&mut state, json!([3,19,{"version":2}]), now).as_slice(), [Event::Changed { subscription, data }] if *subscription == id && data["version"] == 2)
    );
    assert!(
        matches!(receive(&mut state, json!([4]), now).as_slice(), [Event::Resync { subscriptions }] if subscriptions == &vec![id])
    );
}

#[test]
fn explicit_unsubscribe_rejection_restores_events_then_success_removes_only_that_resource() {
    let mut state = connection();
    let now = Instant::now();
    let first = active(&mut state, now, 11);
    let second = active(&mut state, now, 12);
    let remove = state
        .unsubscribe(first, now, now + Duration::from_secs(10))
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(remove.as_str()).unwrap(),
        json!([2, 3, 11])
    );
    assert!(matches!(
        receive(&mut state, json!([3,11,{"version":2}]), now).as_slice(),
        [Event::Changed { .. }]
    ));
    let rejected = receive(
        &mut state,
        json!([2, 3, 1002, "secret remote diagnostics"]),
        now,
    );
    assert!(matches!(
        rejected.as_slice(),
        [Event::Failed {
            cause: Failure::Status(1002),
            ..
        }]
    ));
    assert!(matches!(
        receive(&mut state, json!([3, 11, {}]), now).as_slice(),
        [Event::Changed { .. }]
    ));
    let remove = state
        .unsubscribe(first, now, now + Duration::from_secs(10))
        .unwrap()
        .unwrap();
    assert!(
        matches!(receive(&mut state, json!([2,remove.request_id().sequence,0]), now).as_slice(), [Event::Unsubscribed { subscription, .. }] if *subscription == first)
    );
    assert_eq!(state.subscriptions().collect::<Vec<_>>(), vec![second]);
    assert!(receive(&mut state, json!([3, 11, {}]), now).is_empty());
    assert!(state.is_connected());
}

#[test]
fn cancellation_and_deadlines_retire_ambiguous_sockets_and_complete_requests_once() {
    let mut state = connection();
    let now = Instant::now();
    let (cancelled, first) = state
        .subscribe(state.social_resource(), now, now + Duration::from_secs(10))
        .unwrap();
    let (retained, second) = state
        .subscribe(
            Resource::session_directory(),
            now,
            now + Duration::from_secs(20),
        )
        .unwrap();
    let events = state.cancel(first.request_id());
    assert!(events.iter().any(|event| matches!(event, Event::Failed { request, cause: Failure::Cancelled, .. } if *request == first.request_id())));
    assert!(events.iter().any(|event| matches!(event, Event::Failed { request, cause: Failure::Disconnected, .. } if *request == second.request_id())));
    assert!(!state.is_current(&first) && !state.is_current(&second));
    assert_eq!(state.subscriptions().collect::<Vec<_>>(), vec![retained]);
    assert!(!state.subscriptions().any(|id| id == cancelled));
    assert!(state.cancel(first.request_id()).is_empty());
    assert!(state.disconnect().is_empty());
    assert!(matches!(
        state.receive(state.epoch(), b"[1,1,0,1,{}]", now),
        Err(Error::Disconnected)
    ));

    let mut state = connection();
    let active = active(&mut state, now, 18);
    let remove = state
        .unsubscribe(active, now, now + Duration::from_secs(5))
        .unwrap()
        .unwrap();
    let (_, pending) = state
        .subscribe(state.social_resource(), now, now + Duration::from_secs(10))
        .unwrap();
    assert_eq!(state.next_deadline(), Some(now + Duration::from_secs(5)));
    assert!(state.expire(now + Duration::from_secs(4)).is_empty());
    let events = state
        .receive(
            state.epoch(),
            format!("[2,{},0]", remove.request_id().sequence).as_bytes(),
            now + Duration::from_secs(5),
        )
        .unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Failed {
            cause: Failure::TimedOut,
            ..
        }
    )));
    assert!(!state.subscriptions().any(|id| id == active));
    assert!(!state.is_current(&pending));
    assert!(state.expire(now + Duration::from_secs(100)).is_empty());
}

#[test]
fn directory_snapshot_binding_and_shoulder_taps_reuse_validated_session_references() {
    let mut state = connection();
    let now = Instant::now();
    let (id, frame) = state
        .subscribe(
            Resource::session_directory(),
            now,
            now + Duration::from_secs(10),
        )
        .unwrap();
    assert!(matches!(
        state.directory_binding(id, Uuid::from_u128(9)),
        Err(Error::State)
    ));
    let connection_id = Uuid::from_u128(88);
    receive(
        &mut state,
        json!([1,frame.request_id().sequence,0,12,{"ConnectionId":connection_id}]),
        now,
    );
    let _binding = state.directory_binding(id, Uuid::from_u128(9)).unwrap();
    let scid = Uuid::from_u128(7);
    let reference =
        crate::xbox::mpsd::Reference::new(scid, "MinecraftLobby".into(), "Hosted World".into())
            .unwrap();
    let events = receive(
        &mut state,
        json!([3,12,{"shoulderTaps":[{"resource":format!("{scid}~minecraftlobby~hosted world"),"branch":Uuid::from_u128(10),"changeNumber":42}]}]),
        now,
    );
    assert!(
        matches!(events.as_slice(), [Event::SessionsChanged { subscription, changes }] if *subscription == id && changes.len() == 1 && changes[0].is_for(&reference) && changes[0].change_number == 42)
    );
    state.disconnect();
    assert!(matches!(
        state.directory_binding(id, Uuid::from_u128(9)),
        Err(Error::Disconnected)
    ));
}

#[test]
fn malformed_duplicate_or_oversize_input_retires_state_without_exposing_private_material() {
    let now = Instant::now();
    for bytes in [
        b"[1,1,0]".to_vec(),
        b"[1,1,0,4,{\"ConnectionId\":\"private-invalid\"}]".to_vec(),
        vec![b' '; MAX_MESSAGE_BYTES + 1],
    ] {
        let mut state = connection();
        let (_, frame) = state
            .subscribe(
                Resource::session_directory(),
                now,
                now + Duration::from_secs(10),
            )
            .unwrap();
        let error = match state.receive(state.epoch(), &bytes, now) {
            Err(error) => error,
            Ok(_) => panic!("invalid snapshot accepted"),
        };
        assert!(!format!("{error:?} {error}").contains("private-invalid"));
        assert!(!state.is_current(&frame));
        assert!(matches!(
            state.disconnect().as_slice(),
            [Event::Failed { .. }, Event::Disconnected]
        ));
    }
    let mut state = connection();
    active(&mut state, now, 5);
    let (_, frame) = state
        .subscribe(state.social_resource(), now, now + Duration::from_secs(10))
        .unwrap();
    assert!(matches!(
        state.receive(
            state.epoch(),
            format!("[1,{},0,5,{{}}]", frame.request_id().sequence).as_bytes(),
            now
        ),
        Err(Error::Invalid(_))
    ));
    assert!(!state.is_connected());
}

#[test]
fn bounded_admission_and_stale_handles_leave_unrelated_state_intact() {
    let now = Instant::now();
    let mut state = connection();
    assert!(matches!(
        state.subscribe(state.social_resource(), now, now),
        Err(Error::Invalid(_))
    ));
    let mut frames = Vec::new();
    for _ in 0..MAX_SUBSCRIPTIONS {
        frames.push(
            state
                .subscribe(state.social_resource(), now, now + Duration::from_secs(10))
                .unwrap()
                .1,
        );
    }
    assert!(matches!(
        state.subscribe(state.social_resource(), now, now + Duration::from_secs(10)),
        Err(Error::Limit)
    ));
    assert_eq!(state.subscriptions().count(), MAX_SUBSCRIPTIONS);
    assert!(frames.iter().all(|frame| state.is_current(frame)));
    let other = Connection::new(state::Scope {
        epoch: Epoch(Uuid::from_u128(2)),
        ..connection().scope
    });
    assert!(
        state
            .cancel(RequestId {
                epoch: other.epoch(),
                sequence: 1
            })
            .is_empty()
    );
    assert!(matches!(
        state.receive(other.epoch(), b"[4]", now),
        Err(Error::WrongHandle)
    ));
    assert!(state.is_connected());
    assert!(matches!(
        Resource::new("https://user:private@social.xboxlive.com/users".into()),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Resource::new(format!(
            "https://social.xboxlive.com/{}",
            "x".repeat(MAX_RESOURCE_BYTES)
        )),
        Err(Error::Limit)
    ));
    let events = state.close();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Failed { .. }))
            .count(),
        MAX_PENDING_REQUESTS
    );
    assert!(state.close().is_empty());
    assert_eq!(state.subscriptions().count(), 0);
}
