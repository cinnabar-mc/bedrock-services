//! Fixed synthetic hosted-authority scenario for owning application regressions.
//!
//! This nondefault feature never changes normal endpoints or certificate trust.
//! Its finite HTTP peer and verified local TLS peer run on the caller's runtime.
//! Methods panic on a scenario mismatch; this is not a configurable service client.

mod script;

/// Non-retail issuer returned only by the fixed hosted-world discovery response.
pub const HOSTED_WORLD_ISSUER: &str = "https://hosted-world-fixture.invalid/tenant/";

use crate::{
    http::Http,
    minecraft::{self, Minecraft},
    oauth::Credentials,
    xbox::{self, Account, Authorization, Checkpoint, mpsd, rta},
};
use futures_util::{SinkExt, StreamExt};
use rta::websocket::{RtaSocket, SocketError, test_support::Server};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, UNIX_EPOCH},
};
use tokio::task::JoinHandle;
use tokio_websockets::Message;
use uuid::Uuid;

/// Original signed account identity and its fixed finite synthetic service peer.
pub struct HostedAuthority {
    /// Account that actually acquired its proof-bound credentials.
    pub account: Minecraft,
    /// Identity returned by the account's actual signed authorization chain.
    pub identity: Arc<Authorization>,
    /// Owns only this scenario's synthetic HTTP/TLS peers and explicit cleanup.
    pub peer: HostedPeer,
}

/// Actual acknowledged RTA owner and signed decoded directory snapshot.
pub struct HostedMembership {
    /// Verified TLS/WebSocket owner whose acknowledged connection supplied the binding.
    pub socket: RtaSocket,
    /// Actual desired subscription acknowledged by the synthetic service.
    pub subscription: rta::SubscriptionId,
    /// Binding derived from that acknowledgment and the supplied stable session subscription.
    pub binding: mpsd::Binding,
    /// Snapshot decoded by the real signed directory read under a concrete validator.
    pub session: mpsd::Session,
}

/// Finite synthetic peer; Drop aborts only its own outstanding HTTP task.
/// Keep this owner until explicit conditional leave and socket retirement finish.
pub struct HostedPeer {
    address: SocketAddr,
    http: Option<JoinHandle<()>>,
    server: Option<Server>,
    scenario: script::Scenario,
    auth: xbox::Config,
    minecraft: minecraft::Config,
}

impl HostedAuthority {
    /// Adds one actual public discovery response before the original revoke/refresh/leave sequence.
    /// Only this synthetic Minecraft account's private HTTP owner uses the fixed fixture route.
    pub async fn acquire_world(auth: xbox::Config, minecraft: minecraft::Config) -> Self {
        let (address, task, scenario) = script::start_world(&minecraft.game_version).await;
        let mut peer = HostedPeer {
            address,
            http: Some(task),
            server: None,
            scenario,
            auth,
            minecraft,
        };
        let (mut account, identity) = peer.acquire_account().await;
        account.hosted_fixture_http(address);
        Self {
            account,
            identity,
            peer,
        }
    }

    /// Acquires the explicit signed activity/invite sibling on the original hosted membership.
    /// Call host, acknowledge properties, publish_activity, invite the configured peer, sync, leave and finish.
    /// Capacity/title are expected request metadata; neither creates a listening route or world authority.
    pub async fn acquire_activity(
        auth: xbox::Config,
        minecraft: minecraft::Config,
        max_members: std::num::NonZeroU32,
        invite_title_id: String,
    ) -> Self {
        let (address, task, scenario) = script::start_activity(max_members, invite_title_id).await;
        let mut peer = HostedPeer {
            address,
            http: Some(task),
            server: None,
            scenario,
            auth,
            minecraft,
        };
        let (account, identity) = peer.acquire_account().await;
        Self {
            account,
            identity,
            peer,
        }
    }

    /// Acquires the finite revocation sibling; call host, acknowledge, revoke, refresh, leave and finish.
    pub async fn acquire_revocation(auth: xbox::Config, minecraft: minecraft::Config) -> Self {
        let (address, task, scenario) = script::start_revocation().await;
        let mut peer = HostedPeer {
            address,
            http: Some(task),
            server: None,
            scenario,
            auth,
            minecraft,
        };
        let (account, identity) = peer.acquire_account().await;
        Self {
            account,
            identity,
            peer,
        }
    }

    /// Acquires one original synthetic identity through actual device, NSAL and SISU exchanges.
    /// Call host, property acknowledgment, fresh-account, restore-account, leave and finish in order.
    pub async fn acquire(auth: xbox::Config, minecraft: minecraft::Config) -> Self {
        let (address, task, scenario) = script::start().await;
        let mut peer = HostedPeer {
            address,
            http: Some(task),
            server: None,
            scenario,
            auth,
            minecraft,
        };
        let (account, identity) = peer.acquire_account().await;
        Self {
            account,
            identity,
            peer,
        }
    }
}

impl HostedPeer {
    /// Makes the actual revocation event the next ready delivery on this same original socket.
    pub async fn revoke_member_ready(&mut self, socket: &mut RtaSocket) {
        self.revoke_member().await;
        rta::websocket::test_support::retain_ready_resync(socket).await;
    }

    /// Sends one actual protocol resync so the owning host performs its real signed refresh.
    pub async fn revoke_member(&mut self) {
        assert!(self.scenario.revocation());
        self.server
            .as_mut()
            .expect("actual hosted socket")
            .send(Message::text(rta::fixture_resync_message()))
            .await
            .unwrap();
    }

    /// Opens protected verified TLS, acknowledges the real subscription, then reads the bound session.
    pub async fn host(
        &mut self,
        account: &mut Minecraft,
        reference: &mpsd::Reference,
        session_subscription: Uuid,
        generation: rta::Generation,
        peer_xuid: &str,
    ) -> HostedMembership {
        assert!(self.server.is_none());
        self.scenario
            .configure(reference, session_subscription, peer_xuid);
        let headers = rta::websocket::upgrade_headers().unwrap();
        let mut signed: Vec<String> = headers.keys().map(|name| name.as_str().into()).collect();
        signed.sort();
        signed.extend(["user-agent".into(), "accept".into()]);
        self.scenario.rta_headers(signed.clone());
        let mut request = account.rta_connection(generation, headers).await.unwrap();
        let transmitted = request
            .headers()
            .iter()
            .map(|(name, value)| format!("{}: {}\r\n", name.as_str(), value.to_str().unwrap()))
            .collect::<String>();
        let signed: Vec<_> = signed.iter().map(String::as_str).collect();
        xbox::mpsd::test_support::verify(
            request.url().path(),
            &format!("GET {} HTTP/1.1\r\n{transmitted}", request.url().path()),
            &[],
            &self.scenario.proof(),
            &signed,
        );
        let (mut socket, mut server) = rta::websocket::test_support::pair(&mut request, None).await;
        assert!(account.owns_rta(socket.connection()));
        let resource = rta::Resource::session_directory();
        let expected = resource.as_str().to_owned();
        let (subscription, request_id) = socket
            .subscribe(resource, Instant::now() + Duration::from_secs(30))
            .unwrap();
        let application = async {
            assert!(matches!(socket.drive().await,
                Ok(rta::Event::Subscribed { request, subscription: id, .. })
                    if request == request_id && id == subscription));
        };
        let service = async {
            let message = server.next().await.unwrap().unwrap();
            assert!(message.is_text());
            let received: Value = serde_json::from_slice(message.as_payload()).unwrap();
            assert_eq!(received, json!([1, received[1], expected]));
            server
                .send(Message::text(
                    json!([
                        1, received[1], 0, 19, {"ConnectionId": script::CONNECTION}
                    ])
                    .to_string(),
                ))
                .await
                .unwrap();
        };
        tokio::join!(application, service);
        let binding = socket
            .connection()
            .directory_binding(subscription, session_subscription)
            .unwrap();
        let session = xbox::mpsd::test_support::directory(account.mpsd(), self.address)
            .read(reference)
            .await
            .unwrap();
        assert!(session.is_bound(binding));
        self.server = Some(server);
        HostedMembership {
            socket,
            subscription,
            binding,
            session,
        }
    }

    /// Executes one actual original-binding conditional custom-property write and decoded acknowledgment.
    pub async fn set_properties_bound(
        &mut self,
        account: &mut Minecraft,
        session: &mut mpsd::Session,
        binding: mpsd::Binding,
        custom: &Value,
    ) {
        assert_eq!(
            xbox::mpsd::test_support::directory(account.mpsd(), self.address)
                .set_properties_bound(session, binding, custom)
                .await
                .unwrap(),
            mpsd::Update::Updated
        );
        assert!(session.is_bound(binding));
        assert_eq!(
            session
                .description()
                .properties
                .as_ref()
                .unwrap()
                .custom
                .as_ref(),
            Some(custom)
        );
    }

    /// Acquires another actual proof while independently verifying the same synthetic Xbox identity.
    pub async fn fresh_account(&mut self) -> (Minecraft, Arc<Authorization>) {
        self.acquire_account().await
    }

    /// Restores and authorizes an original checkpoint only after a fresh policy response with Date.
    pub async fn restore_account(
        &mut self,
        checkpoint: Checkpoint,
    ) -> (Minecraft, Arc<Authorization>) {
        let account = Account::restore(self.http(), self.auth.clone(), checkpoint).unwrap();
        let mut account = Minecraft::new(account, self.minecraft.clone()).unwrap();
        let identity = account.xbox_authorization().await.unwrap();
        assert_eq!(identity.xuid(), script::HOST_XUID);
        (account, identity)
    }

    /// Leaves the exact original membership through its actual conditional HTTP owner.
    pub async fn leave_bound(
        &mut self,
        account: &mut Minecraft,
        session: &mut mpsd::Session,
        binding: mpsd::Binding,
    ) {
        assert_eq!(
            xbox::mpsd::test_support::directory(account.mpsd(), self.address)
                .leave_bound(session, binding)
                .await
                .unwrap(),
            mpsd::Update::Closed
        );
        assert!(session.is_closed());
    }

    /// Completes physical RTA close and joins the finite HTTP script after original membership leave.
    pub async fn finish(mut self, socket: &mut RtaSocket) {
        socket.close();
        let mut server = self.server.take().expect("actual hosted socket");
        let application = async {
            assert!(matches!(socket.drive().await, Ok(rta::Event::Disconnected)));
            assert!(matches!(socket.drive().await, Err(SocketError::Closed)));
        };
        let service = async {
            server.close().await.unwrap();
        };
        tokio::join!(application, service);
        self.http.take().unwrap().await.unwrap();
    }

    /// Constructs only this fixed peer's private acquisition client with the supplied actual policy.
    fn http(&self) -> Http {
        Http::fixture_agent(self.address, &self.auth.user_agent)
    }

    /// Reuses the actual account constructors and authorization decoder, with no opaque state injection.
    async fn acquire_account(&mut self) -> (Minecraft, Arc<Authorization>) {
        let credentials = Credentials::from_tokens(
            self.auth.client_id.clone(),
            "synthetic-access".into(),
            "synthetic-refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .unwrap();
        let mut account = Account::new(self.http(), self.auth.clone(), credentials).unwrap();
        if self.scenario.revocation() || self.scenario.activity() {
            mpsd::test_support::inherit_fixture_base(&mut account, self.address);
        }
        let mut account = Minecraft::new(account, self.minecraft.clone()).unwrap();
        let identity = account.xbox_authorization().await.unwrap();
        assert_eq!(identity.xuid(), script::HOST_XUID);
        (account, identity)
    }
}

impl Drop for HostedPeer {
    fn drop(&mut self) {
        if let Some(task) = self.http.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod revocation_tests;

#[cfg(test)]
mod world_tests;

#[cfg(test)]
mod activity_tests;
