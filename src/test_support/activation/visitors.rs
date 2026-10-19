//! Fixed two-visitor service routing and four conditional occupancy publications.

mod directory;

use super::*;
use crate::signaling::websocket::{MessagingSocket, test_support as messaging};
use tokio::sync::Notify;

const GUEST_IDS: [Uuid; 2] = [Uuid::from_u128(0x7121), Uuid::from_u128(0x7122)];
const NETWORK_IDS: [u64; 2] = [0x7201, 0x7202];
const XUIDS: [&str; 2] = ["456", super::super::HOSTED_WORLD_SECOND_VISITOR_XUID];
const OCCUPANCY: [u32; 4] = [2, 3, 2, 1];

/// Actual guest service socket with fixed non-authoritative routing metadata.
/// Its synthetic header authenticates no retail account, game identity or membership.
pub struct HostedVisitor {
    /// Actual bounded SDK socket, driven by the normal client transport consumer.
    pub socket: MessagingSocket,
    /// Network identifier used by that socket's existing signaling state.
    pub network_id: u64,
    /// Synthetic service sender identity derived from the original fixture socket.
    pub messaging_id: Uuid,
    /// Fixed member present in the real decoded directory response; not a Login grant.
    pub xuid: &'static str,
}

/// One real acquired host account and exactly two caller-owned guest service sockets.
pub struct HostedActivationVisitors {
    /// Original signed account and finite service-task retirement owner.
    pub authority: HostedAuthority,
    /// Guest framing sockets; callers supply independently verified signed game identities.
    pub visitors: [HostedVisitor; 2],
    /// Host routing identity from the same protected fixture credential source.
    pub host_messaging_id: Uuid,
}

/// Actual fixed HTTP writes and physical guest-socket retirements after all tasks join.
pub struct HostedVisitorsObservation {
    /// Original protected host acquisition, creation, invitation and socket retirement.
    pub activation: HostedActivationObservation,
    /// Occupancy values independently checked in their original conditional writes.
    pub member_counts: [u32; 4],
    /// Physical termination of the two guest service sockets, in original order.
    pub guests: [HostedSocketTerminal; 2],
}

#[derive(Default)]
pub(super) struct Observed {
    writes: usize,
    flushed: usize,
    guests: Option<[HostedSocketTerminal; 2]>,
    changed: Arc<Notify>,
}

pub(super) struct Services {
    peers: [messaging::Peer; 2],
    deadline: Instant,
}

impl Services {
    /// Polls the actual original host and two guest service peers in one retained task.
    pub(super) async fn run<S>(
        self,
        socket: tokio_websockets::WebSocketStream<S>,
        state: Shared,
    ) -> HostedSocketTerminal
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (host, guests) = tokio::time::timeout_at(
            self.deadline.into(),
            messaging::relay::activation(socket, MESSAGING_ID, self.peers, GUEST_IDS),
        )
        .await
        .expect("fixed visitor relay original deadline");
        state.lock().unwrap().visitors.as_mut().unwrap().guests = Some(guests);
        host
    }
}

/// Extends the same original account/task owner, never an opaque Session or approval constructor.
pub(in crate::test_support) async fn acquire(
    auth: xbox::Config,
    minecraft: minecraft::Config,
    max_members: NonZeroU32,
    title_id: String,
    audience: String,
    deadline: Instant,
) -> HostedActivationVisitors {
    assert!(max_members.get() > u32::try_from(XUIDS.len()).unwrap());
    assert!(deadline > Instant::now());
    tokio::time::timeout_at(deadline.into(), async {
        let (first, first_peer) = messaging::pair(NETWORK_IDS[0]).await;
        let (second, second_peer) = messaging::pair(NETWORK_IDS[1]).await;
        let authority = acquire_inner(
            auth,
            minecraft,
            max_members,
            title_id,
            audience,
            Scenario::Visitors(Box::new(Services {
                peers: [first_peer, second_peer],
                deadline,
            })),
        )
        .await;
        let mut sockets = [first, second].into_iter();
        let visitors = std::array::from_fn(|index| HostedVisitor {
            socket: sockets.next().unwrap(),
            network_id: NETWORK_IDS[index],
            messaging_id: GUEST_IDS[index],
            xuid: XUIDS[index],
        });
        HostedActivationVisitors {
            authority,
            visitors,
            host_messaging_id: MESSAGING_ID,
        }
    })
    .await
    .expect("fixed visitor acquisition original deadline")
}

impl HostedPeer {
    /// Waits for the specified prefix of real occupancy responses to flush on the original HTTP task.
    /// This is service observation only; the caller must separately check application acknowledgment.
    pub async fn wait_activation_visitor_writes(&self, count: usize) {
        assert!((1..=OCCUPANCY.len()).contains(&count));
        let state = &self.activation.as_ref().unwrap().state;
        let changed = Arc::clone(&state.lock().unwrap().visitors.as_ref().unwrap().changed);
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if state.lock().unwrap().visitors.as_ref().unwrap().flushed >= count {
                return;
            }
            notified.await;
        }
    }

    /// Joins the same three finite service tasks before interpreting the fixed visitor observations.
    pub async fn finish_activation_visitors(mut self) -> HostedVisitorsObservation {
        let peer = self
            .activation
            .as_mut()
            .expect("two-visitor activation scenario");
        let activation = peer.finish(self.http.as_mut().unwrap()).await;
        let observed = peer.state.lock().unwrap().visitors.take().unwrap();
        assert_eq!(observed.writes, OCCUPANCY.len());
        assert_eq!(observed.flushed, OCCUPANCY.len());
        self.http = None;
        self.activation = None;
        HostedVisitorsObservation {
            activation,
            member_counts: OCCUPANCY,
            guests: observed.guests.expect("actual guest socket retirements"),
        }
    }
}

/// Adds only the fixed second member to the actual decoded creation response.
pub(super) fn created(state: &mut State) {
    state.snapshot["members"]["2"] =
        json!({"constants":{"system":{"xuid":XUIDS[1]}},"properties":{"system":{"active":true}}});
}

/// Requires actual nonces for both members before public activity or invitations are accepted.
pub(super) fn acknowledged(state: &State) {
    for xuid in XUIDS {
        assert!(
            state.snapshot["properties"]["custom"]["nonces"][xuid]
                .as_str()
                .is_some_and(|nonce| !nonce.is_empty())
        );
    }
}

/// Marks only responses already flushed by the original HTTP owner and wakes observation waiters.
pub(super) fn flushed(state: &mut State) {
    let observed = state.visitors.as_mut().unwrap();
    observed.flushed = observed.writes;
    observed.changed.notify_waiters();
}

pub(super) use directory::respond;

#[cfg(test)]
mod tests;
