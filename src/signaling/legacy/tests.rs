use super::*;
use std::time::Duration;

/// Only original Server frames install credentials, preserving receipt time, wait cutoffs and renewal.
#[test]
fn pushed_credentials_require_server_and_keep_original_lifetime() {
    let now = Instant::now();
    let mut state = Legacy::new();
    let request = state
        .request_credentials(now + Duration::from_secs(5))
        .unwrap();
    let credential = json!({"ExpirationInSeconds":30,"TurnAuthServers":[]}).to_string();
    let frame = |from: &str, payload: &str| {
        serde_json::to_vec(&json!({"Type":2,"From":from,"Message":payload})).unwrap()
    };
    assert!(matches!(
        state
            .receive(&frame("peer", &credential), now)
            .unwrap()
            .as_slice(),
        [Event::Ignored]
    ));
    assert!(state.credentials(now).is_none());
    let events = state.receive(&frame("Server", &credential), now).unwrap();
    assert!(
        matches!(events.as_slice(),[Event::Completed { request:got,result:Ok(()) }] if *got==request)
    );
    assert_eq!(
        state.credentials(now).unwrap().expires_at(),
        now + Duration::from_secs(30)
    );
    let cached = state
        .request_credentials(now + Duration::from_secs(2))
        .unwrap();
    assert!(
        matches!(state.expire(now).as_slice(),[Event::Completed { request:got,result:Ok(()) }] if *got==cached)
    );
    assert!(
        state
            .receive(&frame("Server", "[30,[]]"), now)
            .unwrap()
            .iter()
            .all(|event| matches!(event, Event::Ignored))
    );
    assert!(state.credentials(now + Duration::from_secs(30)).is_none());
    let expired = state
        .request_credentials(now + Duration::from_secs(30))
        .unwrap();
    assert!(
        matches!(state.expire(now + Duration::from_secs(30)).as_slice(),[Event::Completed { request:got,result:Err(Failure::TimedOut) }] if *got==expired)
    );
    let next = state
        .request_credentials(now + Duration::from_secs(40))
        .unwrap();
    assert!(
        matches!(state.receive(&frame("Server",&credential),now + Duration::from_secs(31)).unwrap().as_slice(),[Event::Completed { request:got,result:Ok(()) }] if *got==next)
    );
    assert_eq!(
        state
            .credentials(now + Duration::from_secs(31))
            .unwrap()
            .expires_at(),
        now + Duration::from_secs(61)
    );
}

/// Offers retain the actual UUID through telemetry, unknown/invalid outcomes and final delivery.
#[test]
fn offer_delivery_is_distinct_from_flushing_and_accepted_telemetry() {
    let now = Instant::now();
    let mut state = Legacy::new();
    let message = Uuid::from_u128(1);
    let outgoing = state
        .send_signal(
            "remote",
            message,
            "CONNECTREQUEST 7 original-sdp",
            true,
            now + Duration::from_secs(5),
        )
        .unwrap();
    let request = outgoing.request_id().unwrap();
    let wire: Value = serde_json::from_slice(outgoing.as_bytes()).unwrap();
    assert_eq!(
        wire,
        json!({"Type":1,"To":"remote","Message":"CONNECTREQUEST 7 original-sdp","MessageId":message})
    );
    assert!(state.flushed(request, now).is_empty());
    let outcome = |kind, id, body| {
        serde_json::to_vec(&json!({"Type":kind,"MessageId":id,"Message":body})).unwrap()
    };
    for frame in [
        outcome(3, message, "{}"),
        outcome(4, Uuid::from_u128(2), "{}"),
        outcome(4, message, "[]"),
        outcome(4, message, "{\"DeliveredOn\":\"invalid\"}"),
    ] {
        assert!(matches!(
            state.receive(&frame, now).unwrap().as_slice(),
            [Event::Ignored]
        ));
    }
    let delivered = outcome(4, message, "{\"DeliveredOn\":\"2026-10-19T00:00:00Z\"}");
    assert!(
        matches!(state.receive(&delivered,now).unwrap().as_slice(),[Event::Completed { request:got,result:Ok(()) }] if *got==request)
    );
    assert!(matches!(
        state.receive(&delivered, now).unwrap().as_slice(),
        [Event::Ignored]
    ));
    let early = state
        .send_signal(
            "remote",
            Uuid::from_u128(3),
            "CONNECTREQUEST 8 original",
            true,
            now + Duration::from_secs(5),
        )
        .unwrap();
    let early_id = early.request_id().unwrap();
    let failed = outcome(
        0,
        Uuid::from_u128(3),
        "{\"Code\":2,\"Message\":\"private diagnostic\"}",
    );
    assert!(
        state.receive(&failed, now).unwrap().is_empty(),
        "delivery cannot finish an unflushed original frame"
    );
    assert!(matches!(
        state
            .receive(&outcome(4, Uuid::from_u128(3), "{}"), now)
            .unwrap()
            .as_slice(),
        [Event::Ignored]
    ));
    assert!(
        matches!(state.flushed(early_id, now).as_slice(), [Event::Completed { request: got, result: Err(Failure::DeliveryCode(2)) }] if *got == early_id)
    );
    let signal = state
        .receive(
            &serde_json::to_vec(
                &json!({"Type":1,"From":"actual-network","Message":"opaque-signal"}),
            )
            .unwrap(),
            now,
        )
        .unwrap();
    assert!(
        matches!(signal.as_slice(),[Event::LegacySignal(signal)] if signal.sender()=="actual-network"&&signal.signal()=="opaque-signal")
    );
}

/// Local write completion, timeout and cancellation release only their exact bounded original handles.
#[test]
fn flushed_writes_and_cancelled_waits_keep_deadlines_and_capacity() {
    let now = Instant::now();
    let mut state = Legacy::new();
    let ping = state.ping(now + Duration::from_secs(1)).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(ping.as_bytes()).unwrap(),
        json!({"Type":0,"MessageId":Uuid::nil()})
    );
    assert!(matches!(
        state.flushed(ping.request_id().unwrap(), now).as_slice(),
        [Event::Completed { result: Ok(()), .. }]
    ));
    let local = state
        .send_signal(
            "remote",
            Uuid::from_u128(2),
            "CONNECTRESPONSE 8 original",
            false,
            now + Duration::from_secs(5),
        )
        .unwrap();
    let delivered =
        serde_json::to_vec(&json!({"Type":4,"MessageId":Uuid::from_u128(2),"Message":"{}"}))
            .unwrap();
    assert!(matches!(
        state.receive(&delivered, now).unwrap().as_slice(),
        [Event::Ignored]
    ));
    assert!(matches!(
        state.flushed(local.request_id().unwrap(), now).as_slice(),
        [Event::Completed { result: Ok(()), .. }]
    ));
    let write = state
        .send_signal(
            "remote",
            Uuid::from_u128(1),
            "CONNECTRESPONSE 7 original",
            false,
            now,
        )
        .unwrap();
    assert!(matches!(
        state.flushed(write.request_id().unwrap(), now).as_slice(),
        [Event::Completed {
            result: Err(Failure::TimedOut),
            ..
        }]
    ));
    let pending: Vec<_> = (0..MAX_PENDING_REQUESTS)
        .map(|_| {
            state
                .request_credentials(now + Duration::from_secs(10))
                .unwrap()
        })
        .collect();
    assert!(matches!(state.request_credentials(now), Err(Error::Limit)));
    assert!(state.cancel(pending[0]));
    let last = state.request_credentials(now).unwrap();
    assert!(!pending.contains(&last));
    let expired = state.expire(now);
    assert!(
        matches!(expired.as_slice(),[Event::Completed { request,result:Err(Failure::TimedOut) }] if *request==last)
    );
    assert_eq!(state.close().len(), MAX_PENDING_REQUESTS - 1);
    assert!(matches!(state.ping(now), Err(Error::Closed)));
    assert!(state.close().is_empty());
}

/// Moving pushed credentials preserves their original lifetime without manufacturing another Server event.
#[test]
fn pushed_credential_transfer_clears_cache_without_extending_expiry() {
    let now = Instant::now();
    let mut state = Legacy::new();
    let message = json!({"Type":2,"From":"Server","Message":json!({
        "ExpirationInSeconds":30,"TurnAuthServers":[]}).to_string()});
    let wire = serde_json::to_vec(&message).unwrap();
    state.receive(&wire, now).unwrap();
    let transferred = state
        .take_credentials(now + Duration::from_secs(1))
        .unwrap();
    assert_eq!(transferred.expires_at(), now + Duration::from_secs(30));
    assert!(state.credentials(now).is_none());
    assert!(state.take_credentials(now).is_none());
    state.receive(&wire, now).unwrap();
    assert!(
        state
            .take_credentials(now + Duration::from_secs(30))
            .is_none()
    );
}
