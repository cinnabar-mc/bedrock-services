use super::*;
use crate::signaling::{Event, websocket::SocketError};
use p384::ecdsa::SigningKey;

/// Actual socket receipts and signed conditional writes share the original finite acquired account.
#[tokio::test]
async fn activation_visitors_route_original_senders_and_preserve_conditional_occupancy() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let deadline = Instant::now() + Duration::from_secs(10);
        let cap = NonZeroU32::new(u32::try_from(XUIDS.len() + 1).unwrap()).unwrap();
        let title = "42".to_owned();
        let HostedActivationVisitors {
            authority: HostedAuthority { mut account, peer, .. },
            mut visitors,
            host_messaging_id,
        } = HostedAuthority::acquire_activation_visitors(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            cap, title.clone(), "fixture-audience".into(), deadline,
        ).await;
        let key = SigningKey::from_slice(&[1; 48]).unwrap();
        account.multiplayer_token(key.verifying_key()).await.unwrap();
        let request = account.messaging_connection().await.unwrap();
        assert_eq!(request.player_messaging_id(), host_messaging_id);
        let mut host = MessagingSocket::connect(&request, 9, Default::default()).await.unwrap();
        credentials(&mut host, deadline).await;
        for visitor in &mut visitors {
            credentials(&mut visitor.socket, deadline).await;
            exchange(&mut host, visitor, host_messaging_id, deadline).await;
        }
        let headers = rta::websocket::upgrade_headers().unwrap();
        let mut request = account.rta_connection(rta::Generation::new(7).unwrap(), headers).await.unwrap();
        let mut rta = RtaSocket::connect(&mut request, Default::default()).await.unwrap();
        let (subscription, _) = rta.subscribe(rta::Resource::session_directory(), deadline).unwrap();
        assert!(matches!(rta.drive().await, Ok(rta::Event::Subscribed {subscription: got, ..}) if got == subscription));
        let binding = rta.connection().directory_binding(subscription, Uuid::from_u128(2)).unwrap();
        let reference = mpsd::Reference::new(Uuid::from_u128(7), "Fixture".into(), "Original".into()).unwrap();
        let mut properties = json!({"MemberCount":1,"MaxMemberCount":cap.get(),"nonces":{},
            "SupportedConnections":[{"NetherNetId":9,"PmsgId":host_messaging_id}]});
        let mut directory = account.mpsd();
        let mut attempt = directory.publish_attempt(&reference, mpsd::Publish {
            binding, member: Default::default(), constants: None, max_members: Some(cap),
            properties: Some(properties.clone()), join: mpsd::Restriction::Followed,
            read: mpsd::Restriction::Followed,
        }).unwrap();
        let mut session = directory.publish_retained(&mut attempt).await.unwrap();
        assert_eq!(directory.sync(&mut session).await.unwrap(), mpsd::Update::Unchanged);
        for xuid in XUIDS { properties["nonces"][xuid] = json!(format!("nonce-{xuid}")); }
        directory.set_properties_bound(&mut session, binding, &properties).await.unwrap();
        directory.publish_activity(&session).await.unwrap();
        directory.invite(&session, XUIDS[0], &title).await.unwrap();
        for (index, count) in OCCUPANCY.into_iter().enumerate() {
            properties["MemberCount"] = json!(count);
            assert_eq!(directory.set_properties_bound(&mut session, binding, &properties).await.unwrap(), mpsd::Update::Updated);
            peer.wait_activation_visitor_writes(index + 1).await;
            assert!(session.is_bound(binding));
        }
        assert_eq!(directory.sync(&mut session).await.unwrap(), mpsd::Update::Unchanged);
        assert_eq!(directory.leave_bound(&mut session, binding).await.unwrap(), mpsd::Update::Closed);
        rta.abort();
        for visitor in &mut visitors { close(&mut visitor.socket).await; }
        close(&mut host).await;
        let observed = peer.finish_activation_visitors().await;
        assert_eq!(observed.member_counts, OCCUPANCY);
        assert_eq!(observed.activation.max_members, cap.get());
        assert_eq!(observed.activation.invited_xuid, XUIDS[0]);
        assert_eq!(observed.activation.rta, HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
        for terminal in std::iter::once(observed.activation.messaging).chain(observed.guests) {
            assert!(matches!(terminal, HostedSocketTerminal::Close | HostedSocketTerminal::Eof));
        }
    }).await.unwrap();
}

/// Drives the actual correlated request before borrowing credentials from its original SDK owner.
async fn credentials(socket: &mut MessagingSocket, deadline: Instant) {
    let request = socket.request_credentials(deadline).unwrap();
    assert!(
        matches!(socket.drive().await, Ok(Event::Completed { request: got, result: Ok(()) }) if got == request)
    );
    assert!(socket.credentials().unwrap().servers().is_empty());
}

/// Completes only after the host's actual received signal produced its original peer receipt.
async fn exchange(
    host: &mut MessagingSocket,
    guest: &mut HostedVisitor,
    host_id: Uuid,
    deadline: Instant,
) {
    let request = guest
        .socket
        .send_signal(host_id, Uuid::new_v4(), "fixture-offer", true, deadline)
        .unwrap();
    let sender_id = guest.messaging_id;
    let network_id = guest.network_id;
    let receiver = async {
        let signal = loop {
            if let Event::Signal(signal) = host.drive().await.unwrap() {
                break signal;
            }
        };
        assert_eq!(signal.sender(), sender_id);
        assert_eq!(signal.network_id(), network_id.to_string());
        assert_eq!(signal.signal(), "fixture-offer");
        let ack = host.acknowledge(&signal, Uuid::new_v4(), deadline).unwrap();
        loop {
            if let Event::Completed { request, result } = host.drive().await.unwrap() {
                assert_eq!(request, ack);
                result.unwrap();
                break;
            }
        }
    };
    let sender = async {
        loop {
            if let Event::Completed {
                request: got,
                result,
            } = guest.socket.drive().await.unwrap()
            {
                assert_eq!(got, request);
                result.unwrap();
                break;
            }
        }
    };
    tokio::join!(receiver, sender);
}

/// Retires the original socket and requires the owner's exact closed result.
async fn close(socket: &mut MessagingSocket) {
    socket.close();
    assert_eq!(socket.drive().await.err(), Some(SocketError::Closed));
}
