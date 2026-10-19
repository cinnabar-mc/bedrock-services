//! One finite original-account/public-activation service scenario, entirely caller-runtime owned.

mod script;
mod sockets;
pub(crate) mod transport;

use super::*;
use aws_lc_rs::{
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::KeyPair as _,
};
use std::{io, num::NonZeroU32, sync::Mutex};
use tokio::net::TcpListener;
use transport::Transport;

const AUTH_ORIGIN: &str = "https://hosted-world-service.invalid/";
const SIGNALING_ORIGIN: &str = "https://hosted-world-signaling.invalid/";
const TITLE: &str = "AB12";
/// Public key identifier shared by the finite issuer token and its application verifier cache.
pub const HOSTED_ACTIVATION_KEY_ID: &str = "hosted-activation-issuer";

const MESSAGING_ID: Uuid = Uuid::from_u128(0x7101);
const EXCHANGES: usize = 19;

/// Exact observed termination of the original physical fixture socket, without inferred success.
#[derive(Debug, PartialEq, Eq)]
pub enum HostedSocketTerminal {
    /// An actual WebSocket Close frame was received and its reply flushed.
    Close,
    /// The actual socket stream returned EOF.
    Eof,
    /// The actual transport returned this specific IO error kind.
    Io(io::ErrorKind),
    /// An unexpected frame or protocol/library error ended the fixture.
    Protocol,
}

/// Public metadata observed from actual original requests after all finite peer tasks joined.
pub struct HostedActivationObservation {
    /// Full title document transmitted in the original If-None-Match creation request.
    pub created_properties: Value,
    /// Capacity transmitted in constants.system.maxMembersCount on that same creation.
    pub max_members: u32,
    /// Public connection SPKI actually received in the original mint request.
    pub minted_public_key: Vec<u8>,
    /// Recipient actually sent in the original activity-bound invitation.
    pub invited_xuid: String,
    /// Exact physical original RTA retirement; no replacement client is created to close it.
    pub rta: HostedSocketTerminal,
    /// Exact physical original Messaging retirement.
    pub messaging: HostedSocketTerminal,
}

/// Observed request prefix after every original fixture server has been aborted and joined.
pub struct HostedActivationPrefix {
    /// Last sequential HTTP request whose complete original contract was verified, not inferred delivered responses.
    pub verified_http_requests: usize,
    /// Actual public SPKI from the original mint request; empty if that request never arrived.
    pub minted_public_key: Vec<u8>,
}

struct State {
    issuer: RsaKeyPair,
    max_members: NonZeroU32,
    title_id: String,
    audience: String,
    proof: Option<Value>,
    reference: Option<mpsd::Reference>,
    snapshot: Value,
    created_properties: Value,
    created_capacity: Option<u32>,
    minted_public_key: Vec<u8>,
    invited_xuid: String,
    headers: Vec<String>,
    session_id: Option<Uuid>,
    verified_http_requests: usize,
}

type Shared = Arc<Mutex<State>>;

pub(super) struct Peer {
    pub(super) public_key: Vec<u8>,
    state: Shared,
    rta: Option<JoinHandle<HostedSocketTerminal>>,
    messaging: Option<JoinHandle<HostedSocketTerminal>>,
}

impl Peer {
    /// Aborts every original service task and retains all handles until every cancellation is joined.
    pub(super) async fn abort(&mut self, http: &mut JoinHandle<()>) -> HostedActivationPrefix {
        http.abort();
        self.rta.as_ref().unwrap().abort();
        self.messaging.as_ref().unwrap().abort();
        let (http, rta, messaging) = tokio::join!(
            http,
            self.rta.as_mut().unwrap(),
            self.messaging.as_mut().unwrap()
        );
        self.rta = None;
        self.messaging = None;
        joined_abort(http);
        joined_abort(rta);
        joined_abort(messaging);
        let mut state = self.state.lock().unwrap();
        HostedActivationPrefix {
            verified_http_requests: state.verified_http_requests,
            minted_public_key: std::mem::take(&mut state.minted_public_key),
        }
    }

    /// Joins every retained original server before interpreting any completion result.
    pub(super) async fn finish(
        &mut self,
        http: &mut JoinHandle<()>,
    ) -> HostedActivationObservation {
        let (http, rta, messaging) = tokio::join!(
            http,
            self.rta.as_mut().unwrap(),
            self.messaging.as_mut().unwrap()
        );
        self.rta = None;
        self.messaging = None;
        http.unwrap();
        let rta = rta.unwrap();
        let messaging = messaging.unwrap();
        let mut state = self.state.lock().unwrap();
        HostedActivationObservation {
            created_properties: std::mem::take(&mut state.created_properties),
            max_members: state
                .created_capacity
                .expect("observed original create capacity"),
            minted_public_key: std::mem::take(&mut state.minted_public_key),
            invited_xuid: std::mem::take(&mut state.invited_xuid),
            rta,
            messaging,
        }
    }
}

/// Cancellation is expected here; a server assertion/panic cannot become successful prefix evidence.
fn joined_abort<T>(result: Result<T, tokio::task::JoinError>) {
    if let Err(error) = result {
        assert!(error.is_cancelled(), "original hosted fixture task failed");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        for task in [&self.rta, &self.messaging].into_iter().flatten() {
            task.abort();
        }
    }
}

/// Starts the finite actual acquisition and retains every original task without fabricating membership.
pub(super) async fn acquire(
    auth: xbox::Config,
    minecraft: minecraft::Config,
    max_members: NonZeroU32,
    title_id: String,
    audience: String,
) -> HostedAuthority {
    assert!(usize::try_from(max_members.get()).is_ok_and(|limit| limit <= mpsd::MAX_MEMBERS));
    assert!(
        title_id
            .parse::<u32>()
            .is_ok_and(|id| id != 0 && id.to_string() == title_id)
    );
    assert!(!audience.is_empty() && audience.len() <= 1024);
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rta = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let messaging = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transport = Arc::new(Transport::new(
        http.local_addr().unwrap(),
        rta.local_addr().unwrap(),
        messaging.local_addr().unwrap(),
    ));
    let issuer = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let public_key = issuer.public_key().as_ref().to_vec();
    let headers = rta::websocket::upgrade_headers().unwrap();
    let mut headers: Vec<String> = headers.keys().map(|key| key.as_str().to_owned()).collect();
    headers.sort();
    headers.extend(["user-agent".into(), "accept".into()]);
    let state = Arc::new(Mutex::new(State {
        issuer,
        max_members,
        title_id,
        audience,
        proof: None,
        reference: None,
        snapshot: Value::Null,
        created_properties: Value::Null,
        created_capacity: None,
        minted_public_key: Vec::new(),
        invited_xuid: String::new(),
        headers,
        session_id: None,
        verified_http_requests: 0,
    }));
    let peer = Peer {
        public_key,
        state: Arc::clone(&state),
        rta: Some(tokio::spawn(sockets::rta(rta, Arc::clone(&state)))),
        messaging: Some(tokio::spawn(sockets::messaging(messaging))),
    };
    let game_version = minecraft.game_version.clone();
    let task = tokio::spawn(script::serve(http, Arc::clone(&state), game_version));
    let address = transport.http;
    let fixture_peer = HostedPeer {
        address,
        http: Some(task),
        server: None,
        scenario: super::script::Scenario::activation(),
        auth,
        minecraft,
        activation: Some(peer),
    };
    let credentials = Credentials::from_tokens(
        fixture_peer.auth.client_id.clone(),
        "synthetic-access".into(),
        "synthetic-refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .unwrap();
    let account = Account::new(
        transport.account_http(&fixture_peer.auth.user_agent),
        fixture_peer.auth.clone(),
        credentials,
    )
    .unwrap();
    let mut account = Minecraft::new(account, fixture_peer.minecraft.clone()).unwrap();
    account.hosted_activation_http(transport);
    let identity = account.xbox_authorization().await.unwrap();
    assert_eq!(identity.xuid(), super::script::HOST_XUID);
    HostedAuthority {
        account,
        identity,
        peer: fixture_peer,
    }
}

#[cfg(test)]
mod tests;
