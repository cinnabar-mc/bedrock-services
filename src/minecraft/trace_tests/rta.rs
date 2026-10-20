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
    subscription: Option<rta::SubscriptionId>,
    membership: Option<Box<mpsd::Session>>,
}

/// Opens and subscribes through the real account owner, preserving the original fixture TLS identity.
async fn subscribe(peer: &mut Peer<'_>, owner: &mut Minecraft) -> Result<(), Error> {
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
    peer.rta.socket = Some(socket);
    peer.rta.subscription = Some(subscription);
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
        let events = owner
            .recover_rta(socket, Instant::now() + Duration::from_secs(15))
            .await
            .map_err(|_| Error::Invalid("trace RTA recovery"))?;
        assert!(events.iter().any(|event|matches!(event,Event::Subscribed{subscription,..} if Some(*subscription)==peer.rta.subscription)));
        if let Some(session) = peer.rta.membership.as_mut() {
            let binding = socket
                .connection()
                .directory_binding(peer.rta.subscription.unwrap(), uuid::Uuid::from_u128(11))
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
    if peer.rta.socket.is_none() {
        subscribe(peer, owner).await?;
    }
    if verb == "rta-subscribe" {
        return Ok(());
    }
    let binding = peer
        .rta
        .socket
        .as_ref()
        .unwrap()
        .connection()
        .directory_binding(peer.rta.subscription.unwrap(), uuid::Uuid::from_u128(11))
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
