//! Actual original occupancy-write cancellation, same-member recovery and conditional retirement.

use super::*;

/// The same applied document survives a canceled response with either original or rebound cleanup.
#[tokio::test]
async fn hosted_fixture_cancels_one_applied_properties_response_before_rebind_and_leave() {
    for recover in [false, true] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let cap = NonZeroU32::new(2).unwrap();
            let HostedAuthority { mut account, mut peer, .. } = HostedAuthority::acquire_activation(
                xbox::Config::default(), minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
                cap, "42".into(), "fixture-audience".into(),
            ).await;
            let mut recovery = peer.hold_host_rta_reconnect();
            let mut hold = peer.hold_host_properties_response();
            let key = SigningKey::from_slice(&[1; 48]).unwrap();
            account.multiplayer_token(key.verifying_key()).await.unwrap();
            let request = account.messaging_connection().await.unwrap();
            let messaging_id = request.player_messaging_id();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut messaging = MessagingSocket::connect(&request, 9, Default::default()).await.unwrap();
            let turn = messaging.request_credentials(deadline).unwrap();
            assert!(matches!(messaging.drive().await, Ok(Event::Completed { request, result: Ok(()) }) if request == turn));
            let mut request = account.rta_connection(rta::Generation::new(7).unwrap(), rta::websocket::upgrade_headers().unwrap()).await.unwrap();
            let mut socket = RtaSocket::connect(&mut request, Default::default()).await.unwrap();
            let (subscription, _) = socket.subscribe(rta::Resource::session_directory(), deadline).unwrap();
            assert!(matches!(socket.drive().await, Ok(rta::Event::Subscribed { subscription: got, .. }) if got == subscription));
            let stable = Uuid::from_u128(2);
            let original = socket.connection().directory_binding(subscription, stable).unwrap();
            let reference = mpsd::Reference::new(Uuid::from_u128(7), "Fixture".into(), "Original".into()).unwrap();
            let mut properties = json!({"MemberCount":1,"MaxMemberCount":cap.get(),"nonces":{},"SupportedConnections":[{
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
            properties["MemberCount"] = json!(2);
            let requested;
            let disconnected;
            {
                let pending = directory.set_properties_bound(&mut session, original, &properties);
                tokio::pin!(pending);
                requested = tokio::select! {
                    requested = hold.requested() => requested,
                    _ = &mut pending => false,
                };
                recovery.disconnect();
                disconnected = tokio::select! {
                    event = socket.drive() => matches!(event, Ok(rta::Event::Disconnected)),
                    _ = &mut pending => false,
                };
            }
            let dirty = session.needs_sync();
            let terminal = loop {
                if let Err(error) = socket.drive().await { break error; }
            };
            let synchronized_original = directory.sync(&mut session).await;
            let applied_snapshot = session.description().properties.as_ref()
                .and_then(|section| section.custom.as_ref()) == Some(&properties);
            let mut binding = original;
            let mut rebound = !recover;
            if recover {
                let events = account.recover_rta(&mut socket, deadline).await.unwrap();
                assert!(events.iter().any(|event| matches!(event, rta::Event::Subscribed { subscription: got, .. } if *got == subscription)));
                binding = socket.connection().directory_binding(subscription, stable).unwrap();
                let mut directory = account.mpsd();
                let bound = directory.bind(&mut session, binding).await;
                let synced = directory.sync(&mut session).await;
                rebound = bound.is_ok() && synced.is_ok() && session.is_bound(binding)
                    && !session.is_bound(original) && recovery.rebound().await;
            }
            let left = account.mpsd().leave_bound(&mut session, binding).await;
            socket.abort();
            recovery.stop();
            messaging.close();
            let closed = messaging.drive().await.err();
            drop(messaging);
            let observed = peer.finish_activation().await;
            let facts = recovery.observation();
            assert!(requested && disconnected && dirty && applied_snapshot);
            assert!(synchronized_original.is_ok() && rebound);
            assert_eq!(terminal, rta::websocket::SocketError::Closed);
            assert_eq!(hold.applied(), 1, "one actual full-document occupancy write");
            assert_eq!(left.unwrap(), mpsd::Update::Closed);
            assert_eq!((facts.publications, facts.leaves), (1, 1));
            assert_eq!((facts.upgrades, facts.acknowledgments, facts.rebinds),
                (1 + usize::from(recover), 1 + usize::from(recover), usize::from(recover)));
            assert!(facts.first_retired && facts.synchronized == recover);
            assert_eq!(closed, Some(crate::signaling::websocket::SocketError::Closed));
            assert!(matches!(observed.rta, HostedSocketTerminal::Close | HostedSocketTerminal::Eof
                | HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)));
            assert!(matches!(observed.messaging, HostedSocketTerminal::Close | HostedSocketTerminal::Eof));
        }).await.expect("finite original properties-write recovery fixture");
    }
}
