use super::*;
use crate::signaling::{Event, RequestId, websocket::SocketError};
use p384::ecdsa::SigningKey;

/// Exercises both actual signaling dialects after decoded catalogue, bound join and host nonce.
#[tokio::test]
async fn friend_fixture_routes_both_original_dialects_and_conditional_leave() {
    for dialect in [HostedFriendDialect::Messaging, HostedFriendDialect::Legacy] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let deadline = Instant::now() + Duration::from_secs(10);
            let HostedFriend { authority: HostedAuthority { mut account, identity, peer }, mut host, mut membership } =
                HostedAuthority::acquire_friend(xbox::Config::default(),
                    minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)), dialect,
                    "fixture-audience".into(), deadline).await;
            let host_observed = Instant::now();
            let host_service_time = account.service_time();
            let (mut socket, mut session, binding, subscription) = listed_join(&mut account, deadline).await;
            membership.joined().await;
            let no_nonce_before_admission = session.description().properties.as_ref().unwrap()
                .custom.as_ref().unwrap()["nonces"].get(identity.xuid()).is_none();
            let no_early_member = !host.member_admitted(identity.xuid(), NONCE);
            membership.admit();
            assert!(matches!(socket.drive().await.unwrap(), rta::Event::SessionsChanged {subscription: got, ..} if got == subscription));
            let updated = account.mpsd().sync(&mut session).await.unwrap();
            let actual_nonce = session.description().properties.as_ref().unwrap().custom.as_ref()
                .unwrap()["nonces"][identity.xuid()].as_str().unwrap().to_owned();
            let original_member = host.member_admitted(identity.xuid(), &actual_nonce);
            let wrong_member = host.member_admitted(HOST_XUID, &actual_nonce)
                || host.member_admitted(identity.xuid(), "unpublished-nonce");
            let key = SigningKey::from_slice(&[1;48]).unwrap();
            let minted = account.multiplayer_token(key.verifying_key()).await.unwrap();
            let public_key = minted.public_key_der().to_vec();
            let host_mint_time = host_service_time.checked_add(host_observed.elapsed()).unwrap();
            let mint_expires = minted.expires_at();
            let local = 77;
            let request = match dialect {
                HostedFriendDialect::Messaging => account.messaging_connection().await.unwrap(),
                HostedFriendDialect::Legacy => account.legacy_signaling_connection(local).await.unwrap(),
            };
            let mut visitor = MessagingSocket::connect(&request, local, Default::default()).await.unwrap();
            let (visitor_ice, host_ice) = tokio::join!(credentials(&mut visitor, deadline), credentials(host.socket.as_mut().unwrap(), deadline));
            exchange(&mut visitor, host.socket.as_mut().unwrap(), dialect, deadline).await;
            let left = account.mpsd().leave_bound(&mut session, binding).await;
            let member_retired = !host.member_admitted(identity.xuid(), &actual_nonce);
            socket.abort();
            let (visitor_closed, host_closed) = tokio::join!(closed(&mut visitor), closed(host.socket.as_mut().unwrap()));
            drop((visitor, host));
            let observed = peer.finish_friend().await;
            assert!(host_mint_time < mint_expires, "acquired host clock rejects the original service mint as expired");
            assert!(no_nonce_before_admission, "fixture manufactured early admission");
            assert!(no_early_member && original_member && !wrong_member && member_retired);
            assert_eq!(actual_nonce, NONCE);
            assert_eq!(updated, mpsd::Update::Updated);
            assert_eq!(left.unwrap(), mpsd::Update::Closed);
            assert!(visitor_ice && host_ice);
            assert_eq!((visitor_closed, host_closed), (Some(SocketError::Closed), Some(SocketError::Closed)));
            assert_eq!((observed.joins, observed.leaves), (1, 1));
            assert!(observed.nonce_published);
            assert_eq!(observed.minted_public_key, public_key);
            assert_eq!(observed.rta, HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
            for terminal in [observed.signaling, observed.host] {
                assert!(matches!(terminal, Some(HostedSocketTerminal::Close | HostedSocketTerminal::Eof)));
            }
        }).await.expect("finite original friend fixture");
    }
}

/// Leaving the real member while admission is held never needs a mint, socket upgrade or invented Ready.
#[tokio::test]
async fn friend_fixture_held_membership_leaves_without_nonce_or_transport() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let deadline = Instant::now() + Duration::from_secs(10);
        let HostedFriend {
            authority: HostedAuthority {
                mut account, peer, ..
            },
            mut host,
            mut membership,
        } = HostedAuthority::acquire_friend(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            HostedFriendDialect::Messaging,
            "fixture-audience".into(),
            deadline,
        )
        .await;
        let (mut socket, mut session, binding, _) = listed_join(&mut account, deadline).await;
        membership.joined().await;
        let left = account.mpsd().leave_bound(&mut session, binding).await;
        socket.abort();
        host.socket.as_mut().unwrap().abort();
        drop((host, membership));
        let observed = peer.finish_friend().await;
        assert_eq!(left.unwrap(), mpsd::Update::Closed);
        assert_eq!((observed.joins, observed.leaves), (1, 1));
        assert!(!observed.nonce_published && observed.minted_public_key.is_empty());
        assert!(observed.signaling.is_none() && observed.host.is_none());
        assert_eq!(
            observed.rta,
            HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
        );
    })
    .await
    .expect("finite held original friend member");
}

/// Drives original service calls and derives the handle/reference/binding only from their decoded results.
async fn listed_join(
    account: &mut Minecraft,
    deadline: Instant,
) -> (
    RtaSocket,
    Box<mpsd::Session>,
    mpsd::Binding,
    rta::SubscriptionId,
) {
    assert!(
        account
            .realms()
            .await
            .unwrap()
            .list()
            .await
            .unwrap()
            .is_empty()
    );
    let activities = account
        .social()
        .activities(minecraft::SERVICE_CONFIG_ID, &[])
        .await
        .unwrap();
    assert_eq!(activities.len(), 1);
    let activity = &activities[0];
    let reference = mpsd::Reference::try_from(activity.session.as_ref().unwrap()).unwrap();
    let mut request = account
        .rta_connection(
            rta::Generation::new(7).unwrap(),
            rta::websocket::upgrade_headers().unwrap(),
        )
        .await
        .unwrap();
    let mut socket = RtaSocket::connect(&mut request, Default::default())
        .await
        .unwrap();
    let (subscription, _) = socket
        .subscribe(rta::Resource::session_directory(), deadline)
        .unwrap();
    assert!(
        matches!(socket.drive().await.unwrap(), rta::Event::Subscribed {subscription: got, ..} if got == subscription)
    );
    let binding = socket
        .connection()
        .directory_binding(subscription, Uuid::from_u128(2))
        .unwrap();
    let mut directory = account.mpsd();
    let mut attempt = directory
        .join_attempt(activity.id.unwrap(), binding, Default::default())
        .unwrap();
    let mpsd::JoinOutcome::Joined(session) = directory.join(&mut attempt).await.unwrap() else {
        panic!("original join did not return membership");
    };
    assert!(session.reference().same(&reference) && session.is_bound(binding));
    (socket, session, binding, subscription)
}

/// Completes the actual retained credential request before observing its unchanged cache.
async fn credentials(socket: &mut MessagingSocket, deadline: Instant) -> bool {
    let request = socket.request_credentials(deadline).unwrap();
    completed(socket, request).await;
    socket.credentials().unwrap().servers().is_empty()
}

/// Requires the actual correlated completion rather than local command admission.
async fn completed(socket: &mut MessagingSocket, request: RequestId) {
    assert!(
        matches!(socket.drive().await.unwrap(), Event::Completed {request: got, result: Ok(())} if got == request)
    );
}

/// Requires the fixed host to receive the actual original opaque signal on its own socket.
async fn exchange(
    visitor: &mut MessagingSocket,
    host: &mut MessagingSocket,
    dialect: HostedFriendDialect,
    deadline: Instant,
) {
    let id = Uuid::from_u128(0x7450);
    let request = match dialect {
        HostedFriendDialect::Messaging => visitor
            .send_signal(HOST_MESSAGING, id, "original-offer", false, deadline)
            .unwrap(),
        HostedFriendDialect::Legacy => visitor
            .send_legacy_signal(
                &HOST_NETWORK.to_string(),
                id,
                "original-offer",
                true,
                deadline,
            )
            .unwrap(),
    };
    let ((), received) = tokio::join!(completed(visitor, request), host.drive());
    match received.unwrap() {
        Event::Signal(signal) => {
            assert_eq!(signal.sender(), MESSAGING_ID);
            assert_eq!(signal.network_id(), "77");
            assert_eq!(signal.signal(), "original-offer");
            let receipt = host
                .acknowledge(&signal, Uuid::from_u128(0x7451), deadline)
                .unwrap();
            completed(host, receipt).await;
        }
        Event::LegacySignal(signal) => {
            assert_eq!(signal.sender(), "77");
            assert_eq!(signal.signal(), "original-offer");
        }
        _ => panic!("original friend signal was not delivered"),
    }
}

/// Uses the same original close state and returns only its actual terminal cause.
async fn closed(socket: &mut MessagingSocket) -> Option<SocketError> {
    socket.close();
    loop {
        if let Err(error) = socket.drive().await {
            return Some(error);
        }
    }
}

/// Verifies the finite reconnect service through actual signed upgrade, rebind, sync and original leave.
#[tokio::test]
async fn friend_fixture_reconnects_one_original_acknowledged_membership() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let deadline = Instant::now() + Duration::from_secs(10);
        let HostedFriend { authority: HostedAuthority { mut account, mut peer, .. }, mut host, mut membership } =
            HostedAuthority::acquire_friend(xbox::Config::default(),
                minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)), HostedFriendDialect::Messaging,
                "fixture-audience".into(), deadline).await;
        let mut recovery = peer.hold_rta_reconnect();
        let (mut socket, mut session, original, subscription) = listed_join(&mut account, deadline).await;
        membership.joined().await;
        membership.admit();
        assert!(matches!(socket.drive().await.unwrap(), rta::Event::SessionsChanged { .. }));
        account.mpsd().sync(&mut session).await.unwrap();
        recovery.disconnect();
        assert!(matches!(socket.drive().await.unwrap(), rta::Event::Disconnected));
        let mut request = account.rta_connection(socket.connection().generation(), rta::websocket::upgrade_headers().unwrap()).await.unwrap();
        socket.reconnect(&mut request, Default::default()).await.unwrap();
        socket.resubscribe(subscription, deadline).unwrap();
        assert!(matches!(socket.drive().await.unwrap(), rta::Event::Subscribed { subscription: got, .. } if got == subscription));
        let binding = socket.connection().directory_binding(subscription, Uuid::from_u128(2)).unwrap();
        assert!(session.is_bound(original));
        let rebound = account.mpsd().bind(&mut session, binding).await;
        let synchronized = account.mpsd().sync(&mut session).await;
        let observed_rebind = recovery.rebound().await;
        let original_replaced = !session.is_bound(original) && session.is_bound(binding);
        let left = account.mpsd().leave_bound(&mut session, binding).await;
        socket.abort();
        host.socket.as_mut().unwrap().abort();
        drop(host);
        recovery.stop();
        let observed = peer.finish_friend().await;
        let facts = recovery.observation();
        assert_eq!(rebound.unwrap(), mpsd::Update::Updated);
        assert_eq!(synchronized.unwrap(), mpsd::Update::Unchanged);
        assert!(original_replaced && observed_rebind && facts.first_retired && facts.synchronized);
        assert_eq!((facts.upgrades, facts.acknowledgments, facts.rebinds), (2, 2, 1));
        assert_eq!(left.unwrap(), mpsd::Update::Closed);
        assert_eq!((observed.joins, observed.leaves), (1, 1));
        assert_eq!(observed.rta, HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
    }).await.expect("finite original reconnect fixture");
}

/// Cleanup may cancel an unused accept, but must retain an already verified replacement socket.
#[tokio::test]
async fn friend_fixture_stop_retains_accepted_replacement_until_physical_retirement() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let deadline = Instant::now() + Duration::from_secs(10);
        let HostedFriend {
            authority:
                HostedAuthority {
                    mut account,
                    mut peer,
                    ..
                },
            mut host,
            mut membership,
        } = HostedAuthority::acquire_friend(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            HostedFriendDialect::Messaging,
            "fixture-audience".into(),
            deadline,
        )
        .await;
        let mut recovery = peer.hold_rta_reconnect();
        let (mut socket, mut session, binding, _) = listed_join(&mut account, deadline).await;
        membership.joined().await;
        membership.admit();
        assert!(matches!(
            socket.drive().await.unwrap(),
            rta::Event::SessionsChanged { .. }
        ));
        account.mpsd().sync(&mut session).await.unwrap();
        recovery.disconnect();
        assert!(matches!(
            socket.drive().await.unwrap(),
            rta::Event::Disconnected
        ));
        let mut request = account
            .rta_connection(
                socket.connection().generation(),
                rta::websocket::upgrade_headers().unwrap(),
            )
            .await
            .unwrap();
        socket
            .reconnect(&mut request, Default::default())
            .await
            .unwrap();
        recovery.replacement_upgraded().await;
        let left = account.mpsd().leave_bound(&mut session, binding).await;
        host.socket.as_mut().unwrap().abort();
        drop(host);
        recovery.stop();
        for _ in 0..32 {
            if peer
                .activation
                .as_ref()
                .unwrap()
                .rta
                .as_ref()
                .unwrap()
                .is_finished()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let retired_while_client_owned = peer
            .activation
            .as_ref()
            .unwrap()
            .rta
            .as_ref()
            .unwrap()
            .is_finished();
        socket.abort();
        let observed = peer.finish_friend().await;
        let facts = recovery.observation();
        assert_eq!(left.unwrap(), mpsd::Update::Closed);
        assert_eq!((observed.joins, observed.leaves), (1, 1));
        assert!(facts.first_retired);
        assert!(observed.signaling.is_none() && observed.host.is_none());
        assert_eq!(
            observed.rta,
            HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(facts.acknowledgments, 1, "replacement never resubscribed");
        assert_eq!(
            facts.upgrades, 2,
            "verified replacement upgrade was discarded by cleanup"
        );
        assert!(
            !retired_while_client_owned,
            "accepted replacement owner retired before its physical socket"
        );
    })
    .await
    .expect("finite accepted replacement retirement fixture");
}
