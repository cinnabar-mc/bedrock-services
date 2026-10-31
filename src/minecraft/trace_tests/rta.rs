//! Real protected RTA upgrades and directory operations against the shared peer.

use super::*;
use crate::xbox::{
    mpsd,
    rta::{
        self, Event,
        websocket::{self, RtaSocket},
    },
};
use std::time::Instant;

#[derive(Default)]
pub(super) struct Trace {
    socket: Option<RtaSocket>,
    subscriptions: Vec<rta::SubscriptionId>,
    membership: Option<Box<mpsd::Session>>,
}

/// Opens and subscribes through the real account owner, preserving the original fixture TLS identity.
async fn subscribe(peer: &mut Peer<'_>, owner: &mut Minecraft, count: usize) -> Result<(), Error> {
    owner.xbox.trace_rta_transport = Some((peer.address, peer.ca.clone()));
    let mut request = owner
        .rta_connection(
            rta::Generation::new(1).unwrap(),
            websocket::upgrade_headers().unwrap(),
        )
        .await
        .map_err(|_| Error::Invalid("trace RTA acquisition"))?;
    let mut socket = RtaSocket::connect(&mut request, websocket::Options::default())
        .await
        .map_err(|_| Error::Invalid("trace RTA upgrade"))?;
    for _ in 0..count {
        let (subscription, _) = socket
            .subscribe(
                rta::Resource::session_directory(),
                Instant::now() + Duration::from_secs(15),
            )
            .map_err(|_| Error::Invalid("trace RTA subscribe"))?;
        match socket.drive().await {
            Ok(Event::Subscribed {
                subscription: received,
                ..
            }) if received == subscription => {}
            _ => return Err(Error::Invalid("trace RTA acknowledgement")),
        }
        peer.rta.subscriptions.push(subscription);
    }
    peer.rta.socket = Some(socket);
    Ok(())
}

/// Runs each new plan step through the existing SDK operation that owns its service behavior.
pub(super) async fn run(
    peer: &mut Peer<'_>,
    owner: &mut Minecraft,
    verb: &str,
) -> Result<(), Error> {
    if verb == "rta-drop" {
        peer.oracle
            .call(json!({"op":"drop-rta","session":peer.session}));
        let socket = peer.rta.socket.as_mut().unwrap();
        loop {
            match socket.drive().await {
                Ok(Event::Disconnected) | Err(_) => {
                    break;
                }
                _ => {}
            }
        }
        let mut events = Vec::new();
        owner
            .recover_rta(socket, Instant::now() + Duration::from_secs(15), |event| {
                if matches!(event, Event::Disconnected) {
                    events.retain(|event| {
                        matches!(
                            event,
                            Event::Failed {
                                cause: rta::Failure::Status(_),
                                ..
                            }
                        )
                    });
                }
                events.push(event)
            })
            .await
            .map_err(|_| Error::Invalid("trace RTA recovery"))?;
        let restored = events
            .iter()
            .filter_map(|event| match event {
                Event::Subscribed { subscription, .. } => Some(*subscription),
                _ => None,
            })
            .collect::<Vec<_>>();
        let rejected = events
            .iter()
            .filter_map(|event| match event {
                Event::Failed {
                    subscription,
                    cause,
                    ..
                } => {
                    assert_eq!(*cause, rta::Failure::Status(1));
                    Some(*subscription)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let active = socket.connection().subscriptions().collect::<Vec<_>>();
        assert!(complete_restoration(
            &peer.rta.subscriptions,
            &restored,
            &rejected,
            &active
        ));
        for subscription in &restored {
            assert!(
                socket
                    .connection()
                    .directory_binding(*subscription, uuid::Uuid::from_u128(11))
                    .is_ok()
            );
        }
        if !rejected.is_empty() {
            return Err(Error::Invalid("trace RTA resource rejection"));
        }
        if let Some(session) = peer.rta.membership.as_mut() {
            let binding = socket
                .connection()
                .directory_binding(peer.rta.subscriptions[0], uuid::Uuid::from_u128(11))
                .unwrap();
            if !matches!(
                owner.mpsd().bind(session, binding).await,
                Ok(mpsd::Update::Updated)
            ) {
                return Err(Error::Invalid("trace membership rebind"));
            }
        }
        return Ok(());
    }
    if verb == "rta-active" {
        let connection = peer.rta.socket.as_ref().unwrap().connection();
        let active = peer
            .rta
            .subscriptions
            .iter()
            .filter(|id| {
                connection
                    .directory_binding(**id, uuid::Uuid::from_u128(11))
                    .is_ok()
            })
            .count();
        return if active == 1 && connection.subscriptions().count() == 1 {
            Ok(())
        } else {
            Err(Error::Invalid("trace RTA sibling inactive"))
        };
    }
    if peer.rta.socket.is_none() {
        subscribe(
            peer,
            owner,
            if verb == "rta-subscribe-pair" { 2 } else { 1 },
        )
        .await?;
    }
    if matches!(verb, "rta-subscribe" | "rta-subscribe-pair") {
        return Ok(());
    }
    let binding = peer
        .rta
        .socket
        .as_ref()
        .unwrap()
        .connection()
        .directory_binding(peer.rta.subscriptions[0], uuid::Uuid::from_u128(11))
        .unwrap();
    let mut directory = owner.mpsd();
    let mut attempt = directory
        .join_attempt(
            uuid::Uuid::from_u128(9),
            binding,
            mpsd::MemberData::default(),
        )
        .map_err(|_| Error::Invalid("trace join intent"))?;
    loop {
        match directory
            .join(&mut attempt)
            .await
            .map_err(|_| Error::Invalid("trace directory join"))?
        {
            mpsd::JoinOutcome::Joined(session) => {
                directory
                    .publish_activity(&session)
                    .await
                    .map_err(|_| Error::Invalid("trace activity publication"))?;
                peer.rta.membership = Some(session);
                return Ok(());
            }
            mpsd::JoinOutcome::Precondition { retry_after, .. } => {
                tokio::time::pause();
                tokio::time::advance(retry_after).await;
                tokio::time::resume();
            }
            _ => return Err(Error::Invalid("trace join exhausted")),
        }
    }
}

/// Requires exactly one outcome per original handle and the corresponding active resource set.
fn complete_restoration<T: Eq>(
    expected: &[T],
    restored: &[T],
    rejected: &[T],
    active: &[T],
) -> bool {
    rejected.len() <= 1
        && rejected
            .first()
            .is_none_or(|id| Some(id) == expected.first())
        && restored.len() + rejected.len() == expected.len()
        && expected.iter().all(|id| {
            restored
                .iter()
                .chain(rejected)
                .filter(|got| *got == id)
                .count()
                == 1
        })
        && active.len() == restored.len()
        && restored
            .iter()
            .all(|id| active.iter().filter(|got| *got == id).count() == 1)
}

/// A missing sibling or repeated completion cannot pass a recovery trace.
#[test]
fn recovery_outcomes_cover_every_original_subscription() {
    assert!(!complete_restoration(&[1, 2], &[1], &[], &[1]));
    assert!(!complete_restoration(&[1, 2], &[1, 1], &[], &[1]));
    assert!(!complete_restoration(&[1, 2], &[1, 2], &[], &[1]));
    assert!(complete_restoration(&[1, 2], &[1, 2], &[], &[1, 2]));
    assert!(complete_restoration(&[1, 2], &[2], &[1], &[2]));
    assert!(!complete_restoration(&[1, 2], &[1], &[2], &[1]));
}
