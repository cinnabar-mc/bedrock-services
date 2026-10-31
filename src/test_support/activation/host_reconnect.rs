//! Fixed host publication, one same-member rebind, and exact original conditional retirement.

use super::*;
use crate::xbox::{
    mpsd::test_support::header,
    test_support::{read_request, write_response},
};
use friend::service::Reply;

/// Reuses every original acquisition/publication response, then accepts only bounded host recovery IO.
/// A failed app recovery can still synchronize and remove its original member before tasks are joined.
pub(super) async fn serve(
    listener: TcpListener,
    state: Shared,
    version: String,
    mut accepted: Option<tokio::net::TcpStream>,
) {
    loop {
        let tcp = match accepted.take() {
            Some(tcp) => tcp,
            None => listener.accept().await.unwrap().0,
        };
        let mut stream = rta::websocket::test_support::acceptor()
            .accept(tcp)
            .await
            .unwrap();
        let (bytes, end, length) = read_request(&mut stream).await;
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        let target = headers.split_whitespace().nth(1).unwrap();
        if host_properties::hold_request(
            &state,
            &mut stream,
            target,
            headers,
            &bytes[end..end + length],
        )
        .await
        {
            continue;
        }
        let (reply, publication, leave) = {
            let mut state = state.lock().unwrap();
            let step = state.verified_http_requests + 1;
            assert!(step <= EXCHANGES + 4, "finite host recovery request bound");
            let reply = if step <= 16 {
                let (status, headers, body) = script::respond(
                    step,
                    target,
                    headers,
                    &bytes[end..end + length],
                    &mut state,
                    &version,
                );
                Reply {
                    status,
                    headers: headers
                        .into_iter()
                        .map(|(name, value)| (name.into(), value.into()))
                        .collect(),
                    body,
                }
            } else {
                respond(target, headers, &bytes[end..end + length], &mut state)
            };
            state.verified_http_requests += 1;
            let publication = step == 13;
            let leave = reply.status == 204;
            (reply, publication, leave)
        };
        let body = if matches!(reply.status, 204 | 304) {
            Vec::new()
        } else {
            serde_json::to_vec(&reply.body).unwrap()
        };
        let mut response_headers: Vec<_> = reply
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        response_headers.push(("Date", super::super::script::DATE));
        write_response(&mut stream, reply.status, response_headers, &body).await;
        {
            let mut state = state.lock().unwrap();
            reconnect::flushed(target, headers, &reply, &mut state);
            let mut facts = state.reconnect.as_ref().unwrap().observed.lock().unwrap();
            facts.publications += usize::from(publication);
            facts.leaves += usize::from(leave);
        }
        if leave {
            return;
        }
    }
}

/// Verifies the same account proof/reference and never creates or rejoins a replacement membership.
fn respond(target: &str, headers: &str, body: &[u8], state: &mut State) -> Reply {
    script::verify_directory(target, headers, body, state);
    script::verify_target(target, state);
    if let Some(reply) = host_properties::snapshot(headers, body, state) {
        return reply;
    }
    if let Some(reply) = reconnect::respond(target, headers, body, state) {
        return reply;
    }
    let validator = state
        .reconnect
        .as_ref()
        .unwrap()
        .validator
        .as_ref()
        .unwrap();
    if headers.starts_with("GET ") {
        assert!(body.is_empty());
        assert_eq!(header(headers, "if-none-match"), validator);
        return Reply::json(304, Value::Null);
    }
    assert!(headers.starts_with("PUT "));
    assert_eq!(header(headers, "if-match"), validator);
    let actual: Value = serde_json::from_slice(body).unwrap();
    if actual.get("properties").is_some() {
        assert!(
            !state.reconnect.as_ref().unwrap().properties_applied,
            "one original occupancy properties PUT, without replay"
        );
        assert_eq!(
            actual,
            json!({"properties":{"custom":state.snapshot["properties"]["custom"]}})
        );
        let mut reply = Reply::json(200, state.snapshot.clone());
        reply.headers.push(("ETag".into(), validator.clone()));
        return reply;
    }
    assert_eq!(actual, json!({"members":{"me":null}}));
    Reply::json(204, Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::{Event, websocket::MessagingSocket};
    use p384::ecdsa::SigningKey;

    mod properties;

    /// Proves the host sibling's physical replacement and same-member HTTP contract before app use.
    #[tokio::test]
    async fn hosted_fixture_rebinds_the_original_publication_after_physical_rta_loss() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let cap = NonZeroU32::new(2).unwrap();
            let HostedAuthority { mut account, mut peer, .. } = HostedAuthority::acquire_activation(
                xbox::Config::default(),
                minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
                cap, "42".into(), "fixture-audience".into(),
            ).await;
            let mut recovery = peer.hold_host_rta_reconnect();
            let key = SigningKey::from_slice(&[1; 48]).unwrap();
            account.multiplayer_token(key.verifying_key()).await.unwrap();
            let request = account.messaging_connection().await.unwrap();
            let messaging_id = request.player_messaging_id();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut messaging = MessagingSocket::connect(&request, 9, Default::default()).await.unwrap();
            let turn = messaging.request_credentials(deadline).unwrap();
            assert!(matches!(messaging.drive().await, Ok(Event::Completed { request, result: Ok(()) }) if request == turn));
            let headers = rta::websocket::upgrade_headers().unwrap();
            let mut request = account.rta_connection(rta::Generation::new(7).unwrap(), headers).await.unwrap();
            let mut socket = RtaSocket::connect(&mut request, Default::default()).await.unwrap();
            let (subscription, _) = socket.subscribe(rta::Resource::session_directory(), deadline).unwrap();
            assert!(matches!(socket.drive().await, Ok(rta::Event::Subscribed { subscription: got, .. }) if got == subscription));
            let stable = Uuid::from_u128(2);
            let original = socket.connection().directory_binding(subscription, stable).unwrap();
            let reference = mpsd::Reference::new(Uuid::from_u128(7), "Fixture".into(), "Original".into()).unwrap();
            let mut properties = json!({"MaxMemberCount":cap.get(),"nonces":{},"SupportedConnections":[{
                "NetherNetId":9,"PmsgId":messaging_id,
            }]});
            let mut directory = account.mpsd();
            let mut attempt = directory.publish_attempt(&reference, mpsd::Publish {
                binding: original, member: Default::default(), constants: None,
                max_members: Some(cap), properties: Some(properties.clone()),
                join: mpsd::Restriction::Followed, read: mpsd::Restriction::Followed,
            }).unwrap();
            let mut session = directory.publish_retained(&mut attempt).await.unwrap();
            assert_eq!(directory.sync(&mut session).await.unwrap(), mpsd::Update::Unchanged);
            properties["nonces"]["456"] = json!("original-peer-nonce");
            assert_eq!(directory.set_properties_bound(&mut session, original, &properties).await.unwrap(), mpsd::Update::Updated);
            directory.publish_activity(&session).await.unwrap();
            recovery.disconnect_ready(&mut socket).await;
            assert!(matches!(socket.drive().await, Ok(rta::Event::Disconnected)));
            let mut events = Vec::new();
            account.recover_rta(&mut socket, deadline, |event| events.push(event)).await.unwrap();
            assert!(events.iter().any(|event| matches!(event, rta::Event::Subscribed { subscription: got, .. } if *got == subscription)));
            let replacement = socket.connection().directory_binding(subscription, stable).unwrap();
            let mut directory = account.mpsd();
            let rebound = directory.bind(&mut session, replacement).await;
            let synchronized = directory.sync(&mut session).await;
            let observed_rebind = recovery.rebound().await;
            let rebound_bound = session.is_bound(replacement) && !session.is_bound(original);
            let left = directory.leave_bound(&mut session, replacement).await;
            socket.abort();
            messaging.close();
            let closed = messaging.drive().await.err();
            drop(messaging);
            let observed = peer.finish_activation().await;
            let facts = recovery.observation();
            assert!(rebound_bound && session.is_closed());
            assert_eq!(rebound.unwrap(), mpsd::Update::Updated);
            assert_eq!(synchronized.unwrap(), mpsd::Update::Unchanged);
            assert_eq!(left.unwrap(), mpsd::Update::Closed);
            assert!(observed_rebind && facts.first_retired && facts.synchronized);
            assert_eq!((facts.upgrades, facts.acknowledgments, facts.rebinds, facts.publications, facts.leaves), (2, 2, 1, 1, 1));
            assert_eq!(closed, Some(crate::signaling::websocket::SocketError::Closed));
            assert_eq!(observed.rta, HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
            assert!(matches!(observed.messaging, HostedSocketTerminal::Close | HostedSocketTerminal::Eof));
        }).await.expect("finite original host recovery fixture");
    }
}
