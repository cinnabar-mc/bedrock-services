//! One fixed friend catalogue/member service scenario, retaining the original acquired account.

mod directory;
pub(super) mod service;
pub(super) mod sockets;
#[cfg(test)]
mod tests;

use super::*;
use crate::signaling::websocket::{MessagingSocket, test_support as messaging};
use tokio::sync::oneshot;

const HOST_XUID: &str = "456";
const HOST_NETWORK: u64 = 0x7401;
const HOST_MESSAGING: Uuid = Uuid::from_u128(0x7402);
const HANDLE: Uuid = Uuid::from_u128(0x7403);
const BRANCH: Uuid = Uuid::from_u128(0x7404);
const NONCE: &str = "fixed-friend-member-nonce";
const TEMPLATE: &str = "MinecraftLobby";
const NAME: &str = "ControlledFriend";

/// A genuinely acquired synthetic account and its fixed service/host observation owners.
/// This supplies no game session, opaque application selection or membership approval.
pub struct HostedFriend {
    /// Original account acquisition and finite HTTP/RTA/signaling task owner.
    pub authority: HostedAuthority,
    /// Actual controlled host signaling socket; its routing metadata is not a Login grant.
    pub host: HostedFriendHost,
    /// Observes the real join response before allowing the service to publish its nonce.
    pub membership: HostedFriendMembership,
}

/// Original host-side framing socket and its fixed service routing identity.
pub struct HostedFriendHost {
    /// Original socket, present on acquisition. Take it once for the real transport server;
    /// retain this same observation owner for member checks and explicitly retire the socket.
    pub socket: Option<MessagingSocket>,
    /// Network identity used by this same socket and the complete directory response.
    pub network_id: u64,
    /// Player Messaging UUID route.
    pub messaging_id: Uuid,
    state: Shared,
}

impl HostedFriendHost {
    /// Observes this fixed acquired account's actual joined member and flushed nonce snapshot.
    /// This mutates no authorization and discloses no nonce. The real game acceptor must
    /// independently verify the original issuer signature and identity before consulting it.
    pub fn member_admitted(&self, xuid: &str, nonce: &str) -> bool {
        let state = self.state.lock().unwrap();
        let friend = state.friend.as_ref().unwrap();
        friend.joins == 1
            && friend.nonce_published
            && friend.leaves == 0
            && xuid == super::super::script::HOST_XUID
            && state.snapshot["members"]["me"]["constants"]["system"]["xuid"] == xuid
            && state.snapshot["properties"]["custom"]["nonces"][xuid].as_str() == Some(nonce)
    }
}

/// A finite service barrier, not a client event or admission constructor.
/// Dropping it withholds the nonce; the original HTTP peer can still process conditional leave.
pub struct HostedFriendMembership {
    joined: oneshot::Receiver<()>,
    admit: oneshot::Sender<()>,
    observed: bool,
}

impl HostedFriendMembership {
    /// Completes only after the protected original join response was completely flushed.
    pub async fn joined(&mut self) {
        if !self.observed {
            (&mut self.joined)
                .await
                .expect("original friend join was not flushed");
            self.observed = true;
        }
    }

    /// Allows the same service's shoulder tap and subsequent HTTP snapshot to carry its own nonce.
    /// The application must still decode/validate the snapshot and prepare the real game transport.
    pub fn admit(self) {
        assert!(
            self.observed,
            "observe actual membership before host admission"
        );
        self.admit
            .send(())
            .expect("original friend RTA owner retired");
    }
}

/// Actual service facts read only after all original finite peers have joined.
pub struct HostedFriendObservation {
    /// Number of actual validated handle-join writes; the fixed scenario admits exactly one.
    pub joins: usize,
    /// Number of actual conditional local-member removals.
    pub leaves: usize,
    /// Whether the original nonce snapshot actually flushed after the post-membership barrier.
    pub nonce_published: bool,
    /// Public connection SPKI from the original signed multiplayer mint request, if any.
    pub minted_public_key: Vec<u8>,
    /// Exact terminal of the original protected account RTA socket.
    pub rta: HostedSocketTerminal,
    /// Exact terminal if the service observed the protected signaling upgrade and started routing.
    /// None means the original unused/pending accept task was aborted and joined, not a clean Close.
    pub signaling: Option<HostedSocketTerminal>,
    /// Exact terminal of the original host signaling socket, if the relay started.
    pub host: Option<HostedSocketTerminal>,
}

pub(super) struct Observed {
    protocol: u32,
    joined: Option<oneshot::Sender<()>>,
    admit: Option<oneshot::Receiver<()>>,
    joins: usize,
    leaves: usize,
    nonce_published: bool,
    nonce_available: bool,
    listed_realms: bool,
    listed_friends: bool,
    realms_token: bool,
    host_terminal: Option<HostedSocketTerminal>,
    signaling_open: bool,
}

impl Observed {
    /// Allows the opt-in recovery control only before the actual original upgrade and join.
    pub(super) fn reconnect_can_arm(&self) -> bool {
        self.joins == 0 && self.admit.is_some()
    }

    /// Requires the same actual joined member and original flushed nonce before physical interruption.
    pub(super) fn reconnect_can_close(&self) -> bool {
        self.joins == 1 && self.leaves == 0 && self.nonce_published
    }
}

pub(super) struct Services {
    host: messaging::Peer,
    joined: Option<oneshot::Sender<()>>,
    admit: Option<oneshot::Receiver<()>>,
    deadline: Instant,
}

impl Services {
    /// Copies only fixed metadata into the original shared scenario, moving barrier handles once.
    pub(super) fn observed(&mut self, protocol: u32) -> Observed {
        Observed {
            protocol,
            joined: self.joined.take(),
            admit: self.admit.take(),
            joins: 0,
            leaves: 0,
            nonce_published: false,
            nonce_available: false,
            listed_realms: false,
            listed_friends: false,
            realms_token: false,
            host_terminal: None,
            signaling_open: false,
        }
    }

    /// Routes actual frames using the original codec; this service acceptance is not game admission.
    pub(super) async fn run<S>(
        self,
        socket: tokio_websockets::WebSocketStream<S>,
        state: Shared,
    ) -> HostedSocketTerminal
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        state
            .lock()
            .unwrap()
            .friend
            .as_mut()
            .unwrap()
            .signaling_open = true;
        let (visitor, host) = tokio::time::timeout_at(
            self.deadline.into(),
            messaging::relay::friend::run(socket, self.host, [MESSAGING_ID, HOST_MESSAGING]),
        )
        .await
        .expect("finite original friend signaling relay");
        state.lock().unwrap().friend.as_mut().unwrap().host_terminal = Some(host);
        visitor
    }
}

impl HostedAuthority {
    /// Acquires one real synthetic account for a fixed catalogue/handle join and original leave.
    /// All physical traffic is confined to the existing verified loopback fixture transport.
    /// The audience is the caller's existing verifier policy; no application value is duplicated here.
    pub async fn acquire_friend(
        auth: xbox::Config,
        minecraft: minecraft::Config,
        audience: String,
        deadline: Instant,
    ) -> HostedFriend {
        assert!(deadline > Instant::now());
        tokio::time::timeout_at(deadline.into(), async {
            let (socket, host) = messaging::pair(HOST_NETWORK).await;
            let (joined, observed) = oneshot::channel();
            let (admit, released) = oneshot::channel();
            let authority = acquire_inner(
                auth,
                minecraft,
                NonZeroU32::new(2).unwrap(),
                "1".into(),
                audience,
                Scenario::Friend(Box::new(Services {
                    host,
                    joined: Some(joined),
                    admit: Some(released),
                    deadline,
                })),
            )
            .await;
            let state = Arc::clone(&authority.peer.activation.as_ref().unwrap().state);
            HostedFriend {
                authority,
                host: HostedFriendHost {
                    socket: Some(socket),
                    network_id: HOST_NETWORK,
                    messaging_id: HOST_MESSAGING,
                    state,
                },
                membership: HostedFriendMembership {
                    joined: observed,
                    admit,
                    observed: false,
                },
            }
        })
        .await
        .expect("finite original friend account acquisition")
    }
}

impl HostedPeer {
    /// Joins the original HTTP/RTA/signaling owners after real local-member leave and socket retirement.
    /// If signaling never reached routing, its retained accept task is aborted and joined explicitly;
    /// that result makes no successful socket-close claim. Dropping this future aborts its original tasks.
    pub async fn finish_friend(mut self) -> HostedFriendObservation {
        let peer = self
            .activation
            .as_mut()
            .expect("original friend service owner");
        let opened = peer
            .state
            .lock()
            .unwrap()
            .friend
            .as_ref()
            .unwrap()
            .signaling_open;
        if !opened {
            peer.messaging.as_ref().unwrap().abort();
        }
        let (http_result, rta_result, signaling_result) = tokio::join!(
            self.http.as_mut().unwrap(),
            peer.rta.as_mut().unwrap(),
            peer.messaging.as_mut().unwrap()
        );
        self.http = None;
        peer.rta = None;
        peer.messaging = None;
        http_result.unwrap();
        let rta = rta_result.unwrap();
        let signaling = if opened {
            Some(signaling_result.unwrap())
        } else {
            joined_abort(signaling_result);
            None
        };
        let mut state = peer.state.lock().unwrap();
        let minted_public_key = std::mem::take(&mut state.minted_public_key);
        let observed = state.friend.as_mut().expect("fixed friend scenario");
        assert_eq!(observed.leaves, 1, "original member was not removed");
        HostedFriendObservation {
            joins: observed.joins,
            leaves: observed.leaves,
            nonce_published: observed.nonce_published,
            minted_public_key,
            rta,
            signaling,
            host: observed.host_terminal.take(),
        }
    }
}
