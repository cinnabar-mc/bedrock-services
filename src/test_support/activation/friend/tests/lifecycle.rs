//! Actual original-socket cancellation and post-flush replacement routing controls.

use super::*;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

/// An uncached read recovers the same applied member before its original conditional removal.
#[tokio::test]
async fn friend_fixture_uncached_read_preserves_original_member_and_conditional_leave() {
    let mut outcomes = Vec::new();
    for dialect in [HostedFriendDialect::Messaging, HostedFriendDialect::Legacy] {
        let outcome = tokio::time::timeout(Duration::from_secs(15), async {
            let deadline = Instant::now() + Duration::from_secs(10);
            let HostedFriend {
                authority:
                    HostedAuthority {
                        mut account, peer, ..
                    },
                mut host,
                mut membership,
            } = HostedAuthority::acquire_friend(
                xbox::Config::default(),
                minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
                dialect,
                "fixture-audience".into(),
                deadline,
            )
            .await;
            let (mut socket, session, binding, _) = listed_join(&mut account, deadline).await;
            membership.joined().await;
            let reference = session.reference().clone();
            // The server applied this join; reconciliation must not depend on a retained local ETag.
            drop(session);
            let recovered =
                tokio::time::timeout_at(deadline.into(), account.mpsd().read(&reference)).await;
            let (read, bound, left) = match recovered {
                Ok(Ok(mut session)) => {
                    let bound = session.reference().same(&reference) && session.is_bound(binding);
                    let left = tokio::time::timeout_at(
                        deadline.into(),
                        account.mpsd().leave_bound(&mut session, binding),
                    )
                    .await;
                    (true, bound, matches!(left, Ok(Ok(mpsd::Update::Closed))))
                }
                _ => (false, false, false),
            };
            socket.abort();
            host.socket.as_mut().unwrap().abort();
            drop((socket, host, membership, account));
            let (normal_retirement, cleanup_panicked) = if left {
                let finished = AssertUnwindSafe(peer.finish_friend()).catch_unwind().await;
                let cleanup_panicked = finished.is_err();
                let normal = finished.is_ok_and(|observed| {
                    observed.joins == 1
                        && observed.leaves == 1
                        && !observed.nonce_published
                        && observed.minted_public_key.is_empty()
                        && observed.signaling.is_none()
                        && observed.host.is_none()
                        && observed.rta == HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
                });
                (normal, cleanup_panicked)
            } else {
                // This owner joins all three tasks before exposing an original handler panic.
                let aborted = AssertUnwindSafe(peer.abort_activation())
                    .catch_unwind()
                    .await;
                (false, aborted.is_err())
            };
            (read, bound, left, normal_retirement, cleanup_panicked)
        })
        .await
        .expect("finite uncached original member read and retirement");
        outcomes.push(outcome);
    }
    assert!(
        outcomes.iter().all(|(read, _, _, _, _)| *read),
        "uncached original member read failed after owner cleanup: {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .all(|(_, bound, left, normal, panicked)| { *bound && *left && *normal && !*panicked }),
        "recovered membership lost its original binding, conditional leave or retirement: {outcomes:?}"
    );
}

/// Retires the same actual member/socket while the finite disconnect control remains armed.
async fn abort_original(admitted: bool) -> (HostedRtaReconnectObservation, bool) {
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
            membership,
        } = HostedAuthority::acquire_friend(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            HostedFriendDialect::Messaging,
            "fixture-audience".into(),
            deadline,
        )
        .await;
        let mut membership = Some(membership);
        let mut recovery = peer.hold_rta_reconnect();
        let (mut socket, mut session, binding, _) = listed_join(&mut account, deadline).await;
        membership.as_mut().unwrap().joined().await;
        if admitted {
            membership.take().unwrap().admit();
            assert!(matches!(
                socket.drive().await.unwrap(),
                rta::Event::SessionsChanged { .. }
            ));
            account.mpsd().sync(&mut session).await.unwrap();
        }
        let left = account.mpsd().leave_bound(&mut session, binding).await;
        socket.abort();
        host.socket.as_mut().unwrap().abort();
        drop(host);
        recovery.stop();
        let retirement = peer.activation.as_ref().unwrap().rta.as_ref().unwrap();
        let retired_while_armed = tokio::time::timeout_at(deadline.into(), async {
            while !retirement.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        recovery.release_disconnect_wait();
        let observed = peer.finish_friend().await;
        let facts = recovery.observation();
        drop(membership);
        assert_eq!(left.unwrap(), mpsd::Update::Closed);
        assert_eq!((observed.joins, observed.leaves), (1, 1));
        assert_eq!(
            observed.rta,
            HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
        );
        assert!(observed.signaling.is_none() && observed.host.is_none());
        assert_eq!(facts.upgrades, 1);
        (facts, retired_while_armed)
    })
    .await
    .expect("finite original armed cancellation")
}

/// The original acknowledgment was received even though the member never obtained a nonce.
#[tokio::test]
async fn friend_fixture_abort_before_admission_retains_flushed_acknowledgment() {
    let (facts, retired) = abort_original(false).await;
    assert!(retired, "original physical socket did not retire");
    assert_eq!(
        facts.acknowledgments, 1,
        "the actual flushed acknowledgment was lost"
    );
    assert!(facts.first_retired);
}

/// An unused disconnect control cannot keep a physically retired admitted socket alive.
#[tokio::test]
async fn friend_fixture_abort_after_admission_retires_while_disconnect_is_armed() {
    let (facts, retired) = abort_original(true).await;
    assert_eq!(facts.acknowledgments, 1);
    assert!(
        retired,
        "original retirement waited for an unused disconnect request"
    );
    assert!(facts.first_retired);
}

/// A real bind after the flushed replacement acknowledgment cannot depend on delayed telemetry.
#[tokio::test]
async fn friend_fixture_post_ack_bind_precedes_observation_accounting() {
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
        let mut accounting = peer.hold_replacement_ack_accounting();
        let (mut socket, mut session, original, subscription) = listed_join(&mut account, deadline).await;
        membership.joined().await;
        membership.admit();
        assert!(matches!(socket.drive().await.unwrap(), rta::Event::SessionsChanged { .. }));
        account.mpsd().sync(&mut session).await.unwrap();
        recovery.disconnect();
        assert!(matches!(socket.drive().await.unwrap(), rta::Event::Disconnected));
        let mut request = account.rta_connection(
            socket.connection().generation(), rta::websocket::upgrade_headers().unwrap(),
        ).await.unwrap();
        socket.reconnect(&mut request, Default::default()).await.unwrap();
        socket.resubscribe(subscription, deadline).unwrap();
        assert!(matches!(socket.drive().await.unwrap(), rta::Event::Subscribed { subscription: got, .. } if got == subscription));
        accounting.requested().await;
        let before = recovery.observation();
        let binding = socket.connection().directory_binding(subscription, Uuid::from_u128(2)).unwrap();
        let rebound = account.mpsd().bind(&mut session, binding).await;
        let bound = session.is_bound(binding);
        drop(accounting);
        let synchronized = if rebound.is_ok() {
            Some(account.mpsd().sync(&mut session).await)
        } else { None };
        let observed_rebind = if synchronized.as_ref().is_some_and(Result::is_ok) {
            recovery.rebound().await
        } else { false };
        let left = account.mpsd().leave_bound(&mut session, if bound { binding } else { original }).await;
        socket.abort();
        host.socket.as_mut().unwrap().abort();
        drop(host);
        recovery.stop();
        // Even a wrong-route handler panic must join every original owner before the oracle.
        let finished = AssertUnwindSafe(peer.finish_friend()).catch_unwind().await;
        let facts = recovery.observation();
        assert_eq!((before.upgrades, before.acknowledgments), (2, 1));
        assert!(rebound.is_ok(), "an acknowledged replacement bind was routed as an ordinary leave");
        let observed = finished.expect("original fixture handlers retired normally");
        assert!(bound && observed_rebind && facts.synchronized);
        assert_eq!(synchronized.expect("actual post-bind sync").unwrap(), mpsd::Update::Unchanged);
        assert_eq!(left.unwrap(), mpsd::Update::Closed);
        assert_eq!((observed.joins, observed.leaves), (1, 1));
        assert_eq!((facts.upgrades, facts.acknowledgments, facts.rebinds), (2, 2, 1));
        assert_eq!(observed.rta, HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
    }).await.expect("finite post-ack original binding");
}
