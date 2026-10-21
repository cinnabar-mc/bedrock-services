//! Actual canceled member-only writes, with one retained original HTTP/socket owner.

use super::*;

/// Proves both fixed holds with a real canceled PUT and the original one-join/one-leave lifecycle.
#[tokio::test]
async fn friend_fixture_canceled_rebind_reconciles_applied_and_late_original_writes() {
    for applied in [true, false] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let deadline = Instant::now() + Duration::from_secs(10);
            let HostedFriend {
                authority: HostedAuthority { mut account, mut peer, .. },
                mut host, mut membership,
            } = HostedAuthority::acquire_friend(
                xbox::Config::default(),
                minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
                HostedFriendDialect::Messaging, "fixture-audience".into(), deadline,
            ).await;
            let mut recovery = peer.hold_rta_reconnect();
            let mut hold = if applied {
                peer.hold_friend_rebind_response()
            } else {
                peer.hold_friend_rebind_application()
            };
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
            let candidate = socket.connection().directory_binding(subscription, Uuid::from_u128(2)).unwrap();
            let reached = {
                let mut directory = account.mpsd();
                let pending = directory.bind(&mut session, candidate);
                tokio::pin!(pending);
                tokio::select! {
                    _ = hold.requested() => true,
                    _ = &mut pending => false,
                }
            };
            let dirty = session.needs_sync();
            let old_observed = if !applied && reached {
                let synchronized = account.mpsd().sync(&mut session).await;
                synchronized.is_ok() && session.is_bound(original) && !session.is_bound(candidate)
            } else { applied };
            hold.release();
            let canceled_socket = hold.retired().await;
            let synchronized = account.mpsd().sync(&mut session).await;
            let candidate_observed = session.is_bound(candidate) && !session.is_bound(original);
            let left = account.mpsd().leave_bound(&mut session, candidate).await;
            socket.abort();
            host.socket.as_mut().unwrap().abort();
            drop(host);
            recovery.stop();
            let observed = peer.finish_friend().await;
            let facts = recovery.observation();
            assert!(reached && dirty && old_observed);
            assert!(canceled_socket.is_ok(), "original canceled request did not retire by EOF");
            assert!(synchronized.is_ok() && candidate_observed);
            assert_eq!(left.unwrap(), mpsd::Update::Closed);
            assert_eq!((observed.joins, observed.leaves), (1, 1));
            assert_eq!((facts.upgrades, facts.acknowledgments, facts.rebinds), (2, 2, 1));
            assert!(facts.first_retired && facts.synchronized);
            assert_eq!(observed.rta, HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
            assert!(observed.signaling.is_none() && observed.host.is_none());
        }).await.expect("finite original canceled rebind fixture");
    }
}
