use super::{wire::*, *};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Builds one original nested peer message in the service's single-envelope callback form.
fn incoming(sender: Uuid, envelope: Uuid, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":"callback", "method":RECEIVE,
        "params":{"From":sender,"Id":envelope,"Message":json!({
            "jsonrpc":"2.0","method":method,"params":params}).to_string()}}))
    .unwrap()
}

/// Encodes a service response using the exact handle from its outgoing request.
fn accepted(outgoing: &Outgoing, result: Value) -> Vec<u8> {
    let request: Value = serde_json::from_slice(outgoing.as_bytes()).unwrap();
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result})).unwrap()
}

/// Counts terminal events without depending on callback reply ordering.
fn completed(events: &[Event], request: RequestId, expected: Result<(), Failure>) -> bool {
    events.iter().any(|event| {
        matches!(event, Event::Completed {request: id, result}
        if *id == request && *result == expected)
    })
}

/// Separates service acceptance from peer delivery and acknowledges only caller-accepted signals.
#[test]
fn correlation_handles_delivery_order_peer_binding_callbacks_and_cancellation() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(30);
    let recipient = Uuid::from_u128(1);
    let message = Uuid::from_u128(2);
    let mut state = Messaging::new(7);
    let sent = state
        .send_signal(recipient, message, "opaque-offer", true, deadline)
        .unwrap();
    let id = sent.request_id().unwrap();
    let wire: Value = serde_json::from_slice(sent.as_bytes()).unwrap();
    assert_eq!(wire["method"], SEND);
    assert_eq!(wire["params"]["toPlayerId"], recipient.to_string());
    let inner: Value = serde_json::from_str(wire["params"]["message"].as_str().unwrap()).unwrap();
    assert_eq!(
        inner["params"],
        json!({"netherNetId":"7","message":"opaque-offer"})
    );
    let wrong = incoming(
        Uuid::from_u128(3),
        Uuid::from_u128(4),
        RECEIPT,
        json!({"messageId":message}),
    );
    assert!(!completed(&state.receive(&wrong, now).unwrap(), id, Ok(())));
    let receipt = incoming(
        recipient,
        Uuid::from_u128(4),
        RECEIPT,
        json!({"messageId":message}),
    );
    assert!(!completed(
        &state.receive(&receipt, now).unwrap(),
        id,
        Ok(())
    ));
    assert!(completed(
        &state.receive(&accepted(&sent, Value::Null), now).unwrap(),
        id,
        Ok(())
    ));
    assert!(
        state
            .receive(&accepted(&sent, Value::Null), now)
            .unwrap()
            .iter()
            .all(|event| matches!(event, Event::Ignored))
    );

    let sent = state
        .send_signal(
            recipient,
            Uuid::from_u128(5),
            "opaque-candidate",
            true,
            deadline,
        )
        .unwrap();
    let second = sent.request_id().unwrap();
    assert!(!completed(
        &state.receive(&accepted(&sent, Value::Null), now).unwrap(),
        second,
        Ok(())
    ));
    assert!(completed(
        &state
            .receive(
                &incoming(
                    recipient,
                    Uuid::from_u128(4),
                    RECEIPT,
                    json!({"messageId":Uuid::from_u128(5)})
                ),
                now
            )
            .unwrap(),
        second,
        Ok(())
    ));
    let sent = state
        .send_signal(
            recipient,
            Uuid::from_u128(6),
            "opaque-candidate",
            false,
            deadline,
        )
        .unwrap();
    assert!(state.cancel(sent.request_id().unwrap()));
    assert!(!state.cancel(sent.request_id().unwrap()));
    assert!(
        state
            .receive(&accepted(&sent, Value::Null), now)
            .unwrap()
            .iter()
            .all(|event| matches!(event, Event::Ignored))
    );
    let events = state
        .receive(
            &incoming(
                recipient,
                message,
                WEBRTC,
                json!({"netherNetId":"9","message":"opaque-remote"}),
            ),
            now,
        )
        .unwrap();
    // Receiving supplies only the service callback response. Peer acknowledgement needs acceptance.
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Reply(_)))
            .count(),
        1
    );
    let received = events
        .into_iter()
        .find_map(|event| match event {
            Event::Signal(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert_eq!(received.sender(), recipient);
    assert_eq!(received.network_id(), "9");
    assert_eq!(received.signal(), "opaque-remote");
    let ack = state
        .acknowledge(&received, Uuid::from_u128(7), deadline)
        .unwrap();
    let ack: Value = serde_json::from_slice(ack.as_bytes()).unwrap();
    let ack: Value = serde_json::from_str(ack["params"]["message"].as_str().unwrap()).unwrap();
    assert_eq!(ack["method"], RECEIPT);
    assert_eq!(ack["params"]["messageId"], message.to_string());
    let unknown = state
        .receive(
            br#"{"jsonrpc":"2.0","id":17,"method":"future_method","params":{"SECRET":"ignored"}}"#,
            now,
        )
        .unwrap();
    assert!(unknown.iter().any(|event| matches!(event, Event::Ignored)));
    assert!(
        unknown
            .iter()
            .any(|event| matches!(event, Event::Reply(reply)
        if serde_json::from_slice::<Value>(reply.as_bytes()).unwrap()["result"].is_null()))
    );
    let batch = json!([
        {"jsonrpc":"2.0","id":"first","method":PONG},
        {"jsonrpc":"2.0","id":"second","method":"future_method"}
    ]);
    let events = state
        .receive(&serde_json::to_vec(&batch).unwrap(), now)
        .unwrap();
    let replies: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Reply(reply) => Some(serde_json::from_slice::<Value>(reply.as_bytes()).unwrap()),
            _ => None,
        })
        .collect();
    assert_eq!(
        replies,
        [json!([
            {"jsonrpc":"2.0","id":"first","result":null},
            {"jsonrpc":"2.0","id":"second","result":null}
        ])]
    );
}

/// Protects monotonic expiry, request capacity, atomic batch framing and redacted failures.
#[test]
fn lifecycle_bounds_requests_and_rejects_malformed_batches_without_consuming_responses() {
    let now = Instant::now();
    let mut state = Messaging::new(1);
    let mut requests = Vec::new();
    for _ in 0..MAX_PENDING_REQUESTS {
        requests.push(state.ping(now + Duration::from_secs(1)).unwrap());
    }
    assert!(matches!(state.ping(now), Err(Error::Limit)));
    let first = requests[0].request_id().unwrap();
    let response: Value = serde_json::from_slice(&accepted(&requests[0], Value::Null)).unwrap();
    let malformed =
        serde_json::to_vec(&json!([response, {"jsonrpc":"2.0","id":false,"result":null}])).unwrap();
    let error = state.receive(&malformed, now).err().unwrap();
    assert!(!format!("{error:?} {error}").contains("SECRET"));
    assert!(completed(
        &state
            .receive(&accepted(&requests[0], Value::Null), now)
            .unwrap(),
        first,
        Ok(())
    ));
    let late = state.ping(now).unwrap();
    let events = state.receive(&accepted(&late, Value::Null), now).unwrap();
    assert!(completed(
        &events,
        late.request_id().unwrap(),
        Err(Failure::TimedOut)
    ));
    let expired = state.expire(now + Duration::from_secs(1));
    assert_eq!(expired.len(), MAX_PENDING_REQUESTS - 1);
    let pending = state.ping(now + Duration::from_secs(3)).unwrap();
    assert!(completed(
        &state.close(),
        pending.request_id().unwrap(),
        Err(Failure::Closed)
    ));
    assert!(matches!(state.ping(now), Err(Error::Closed)));
    assert!(state.close().is_empty());
    let mut fresh = Messaging::new(2);
    assert!(matches!(
        fresh.receive(
            &serde_json::to_vec(&json!({"jsonrpc":"2.0",
        "id":"x".repeat(MAX_CALLBACK_ID_BYTES + 1),"method":PONG}))
            .unwrap(),
            now
        ),
        Err(Error::Limit)
    ));
    assert!(matches!(
        fresh.receive(&vec![b' '; MAX_MESSAGE_BYTES + 1], now),
        Err(Error::Limit)
    ));
    assert!(matches!(
        fresh.receive(
            &serde_json::to_vec(&vec![Value::Null; MAX_BATCH_MESSAGES + 1]).unwrap(),
            now
        ),
        Err(Error::Limit)
    ));
    let huge = "\\".repeat(MAX_MESSAGE_BYTES / 2);
    assert!(matches!(
        fresh.send_signal(Uuid::from_u128(1), Uuid::from_u128(2), &huge, false, now),
        Err(Error::Limit)
    ));
}

/// Installs only correlated valid TURN results and never exposes remote diagnostics in failures.
#[test]
fn turn_cache_and_delivery_errors_preserve_credential_and_request_ownership() {
    let now = Instant::now();
    let mut state = Messaging::new(1);
    let request = state
        .request_credentials(now + Duration::from_secs(30))
        .unwrap();
    assert!(state.request_credentials(now).is_err());
    let result = json!({"ExpirationInSeconds":60,"TurnAuthServers":[{
        "Username":"fixture-user","Password":"SECRET","Urls":["turn:example.invalid:3478"]}]});
    assert!(completed(
        &state.receive(&accepted(&request, result), now).unwrap(),
        request.request_id().unwrap(),
        Ok(())
    ));
    assert_eq!(
        state.credentials(now).unwrap().servers()[0].password(),
        "SECRET"
    );
    assert!(state.credentials(now + Duration::from_secs(60)).is_none());
    let invalid = state
        .request_credentials(now + Duration::from_secs(30))
        .unwrap();
    let events = state
        .receive(
            &accepted(
                &invalid,
                json!({"ExpirationInSeconds":0,"diagnostic":"SECRET"}),
            ),
            now,
        )
        .unwrap();
    assert!(completed(
        &events,
        invalid.request_id().unwrap(),
        Err(Failure::InvalidResponse)
    ));
    let recipient = Uuid::from_u128(1);
    let message = Uuid::from_u128(2);
    let sent = state
        .send_signal(
            recipient,
            message,
            "opaque",
            true,
            now + Duration::from_secs(5),
        )
        .unwrap();
    let error = json!({"jsonrpc":"2.0","id":3,"method":RECEIVE_ERROR,
        "params":{"messageId":message,"code":2,"message":"SECRET"}});
    let events = state
        .receive(&serde_json::to_vec(&error).unwrap(), now)
        .unwrap();
    assert!(completed(
        &events,
        sent.request_id().unwrap(),
        Err(Failure::DeliveryCode(2))
    ));
    assert!(!format!("{:?}", Failure::DeliveryCode(2)).contains("SECRET"));
}

/// A correlated response may move out once, retaining its receipt-anchored expiry and sensitive fields.
#[test]
fn turn_credential_transfer_preserves_original_owner_and_expiry() {
    let now = Instant::now();
    let mut state = Messaging::new(7);
    let result = json!({"ExpirationInSeconds":30,"TurnAuthServers":[{
        "Username":"transfer-user","Password":"transfer-password","Urls":["turn:fixture.invalid:3478"]}]});
    let request = state
        .request_credentials(now + Duration::from_secs(5))
        .unwrap();
    let events = state
        .receive(&accepted(&request, result.clone()), now)
        .unwrap();
    assert!(completed(&events, request.request_id().unwrap(), Ok(())));
    let transferred = state
        .take_credentials(now + Duration::from_secs(1))
        .unwrap();
    assert!(state.credentials(now).is_none());
    assert!(state.take_credentials(now).is_none());
    assert_eq!(transferred.expires_at(), now + Duration::from_secs(30));
    assert_eq!(transferred.servers()[0].username(), "transfer-user");
    assert_eq!(transferred.servers()[0].password(), "transfer-password");
    assert_eq!(
        transferred.servers()[0].urls(),
        ["turn:fixture.invalid:3478"]
    );
    assert!(!transferred.valid(now + Duration::from_secs(30)));

    let request = state
        .request_credentials(now + Duration::from_secs(5))
        .unwrap();
    state.receive(&accepted(&request, result), now).unwrap();
    assert!(
        state
            .take_credentials(now + Duration::from_secs(30))
            .is_none()
    );
    assert!(state.credentials(now).is_none());
}
