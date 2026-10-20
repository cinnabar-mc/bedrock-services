//! One opt-in physical RTA interruption on the existing signed friend service owner.

use super::*;
use crate::xbox::mpsd::test_support::header;
use futures_util::SinkExt;
use tokio::sync::oneshot;
use tokio_websockets::Message;

/// Finite control for one original socket close and one replacement acknowledgment.
/// Arm before the first RTA upgrade. Dropping this owner releases only fixture waits.
pub struct HostedRtaReconnect {
    close: Option<oneshot::Sender<()>>,
    stop: Option<oneshot::Sender<()>>,
    rebound: oneshot::Receiver<()>,
    observed: Arc<Mutex<HostedRtaReconnectObservation>>,
    #[cfg(test)]
    replacement_upgrade: oneshot::Receiver<()>,
}

/// Coarse actual wire facts, available without identities, credentials or payloads.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostedRtaReconnectObservation {
    /// Independently verified physical upgrades on the original listener.
    pub upgrades: usize,
    /// Fully flushed original subscription acknowledgments.
    pub acknowledgments: usize,
    /// The original socket observed a physical Close reply.
    pub first_closed: bool,
    /// The original protected stream retired by Close, EOF or its exact abort EOF kind.
    pub first_retired: bool,
    /// Same-member conditional rebind writes accepted by the original directory.
    pub rebinds: usize,
    /// Explicit subsequent sync responses flushed by the original HTTP owner.
    pub synchronized: bool,
}

pub(super) struct Services {
    close: Option<oneshot::Receiver<()>>,
    stop: Option<oneshot::Receiver<()>>,
    rebound: Option<oneshot::Sender<()>>,
    observed: Arc<Mutex<HostedRtaReconnectObservation>>,
    connection: Uuid,
    validator: Option<String>,
    rebind_ready: bool,
    #[cfg(test)]
    replacement_upgrade: Option<oneshot::Sender<()>>,
    #[cfg(test)]
    ack_accounting_hold: Option<super::subscription::SubscriptionHold>,
}

impl HostedPeer {
    /// Arms one fixed friend RTA interruption before any upgrade or membership exists.
    /// The original account, signed HTTP/TLS peers and service route stay unchanged.
    pub fn hold_rta_reconnect(&mut self) -> HostedRtaReconnect {
        let peer = self
            .activation
            .as_ref()
            .expect("original protected activation peer");
        let mut state = peer.state.lock().unwrap();
        assert!(state.friend.is_some(), "fixed friend reconnect scenario");
        let friend = state.friend.as_ref().unwrap();
        assert!(
            friend.reconnect_can_arm(),
            "arm before first RTA socket and membership"
        );
        assert!(state.reconnect.is_none());
        let (close, closed) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let (rebound, observed_rebind) = oneshot::channel();
        #[cfg(test)]
        let (replacement_upgrade, upgraded) = oneshot::channel();
        let observed = Arc::new(Mutex::new(HostedRtaReconnectObservation::default()));
        state.reconnect = Some(Services {
            close: Some(closed),
            stop: Some(stopped),
            rebound: Some(rebound),
            observed: Arc::clone(&observed),
            connection: Uuid::new_v4(),
            validator: None,
            rebind_ready: false,
            #[cfg(test)]
            replacement_upgrade: Some(replacement_upgrade),
            #[cfg(test)]
            ack_accounting_hold: None,
        });
        HostedRtaReconnect {
            close: Some(close),
            stop: Some(stop),
            rebound: observed_rebind,
            observed,
            #[cfg(test)]
            replacement_upgrade: upgraded,
        }
    }

    /// Holds only telemetry after the replacement acknowledgment has actually flushed.
    #[cfg(test)]
    pub(super) fn hold_replacement_ack_accounting(&mut self) -> HostedSubscriptionHold {
        let (hold, service) = super::subscription::hold();
        let mut state = self.activation.as_ref().unwrap().state.lock().unwrap();
        let recovery = state.reconnect.as_mut().unwrap();
        assert!(recovery.ack_accounting_hold.is_none());
        recovery.ack_accounting_hold = Some(service);
        hold
    }
}

impl HostedRtaReconnect {
    /// Requests the physical close; the service verifies acknowledged actual membership first.
    pub fn disconnect(&mut self) {
        let _ = self
            .close
            .take()
            .expect("one original interruption")
            .send(());
    }

    /// Waits for the actual replacement binding and subsequent sync response flush.
    pub async fn rebound(&mut self) -> bool {
        (&mut self.rebound).await.is_ok()
    }

    /// Ends only an unused replacement-accept wait during original-owner cleanup.
    /// An already accepted replacement must still retire through its actual client socket.
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Observes the verified replacement upgrade before its first subscription arrives.
    #[cfg(test)]
    pub(super) async fn replacement_upgraded(&mut self) {
        (&mut self.replacement_upgrade)
            .await
            .expect("verified original replacement upgrade");
    }

    /// Releases only the retained unused close request after a cancellation observation.
    #[cfg(test)]
    pub(super) fn release_disconnect_wait(&mut self) {
        self.close.take();
    }

    /// Captures bounded original observations after the caller has joined all fixture tasks.
    pub fn observation(&self) -> HostedRtaReconnectObservation {
        *self.observed.lock().unwrap()
    }
}

/// Reports only an actual verified replacement upgrade, without consuming its input.
#[cfg(test)]
pub(super) fn upgraded(state: &Shared) {
    let mut state = state.lock().unwrap();
    if let Some(recovery) = state.reconnect.as_mut()
        && recovery.observed.lock().unwrap().upgrades == 1
        && let Some(upgraded) = recovery.replacement_upgrade.take()
    {
        let _ = upgraded.send(());
    }
}

/// Records a successful acknowledgment send independently of admission and request routing.
pub(super) fn acknowledged(state: &Shared) {
    if let Some(recovery) = &state.lock().unwrap().reconnect {
        recovery.observed.lock().unwrap().acknowledgments += 1;
    }
}

/// Preserves the actual original terminal on every exit, including cancellation before admission.
fn first_terminal(
    observed: &Mutex<HostedRtaReconnectObservation>,
    terminal: HostedSocketTerminal,
) -> HostedSocketTerminal {
    let mut facts = observed.lock().unwrap();
    facts.first_closed = terminal == HostedSocketTerminal::Close;
    facts.first_retired = matches!(
        &terminal,
        HostedSocketTerminal::Close
            | HostedSocketTerminal::Eof
            | HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
    );
    terminal
}

/// Reuses the same protected acceptor and request verification for exactly one replacement.
pub(super) async fn run(
    listener: TcpListener,
    state: Shared,
    mut socket: super::sockets::Socket,
    sequence: Value,
) -> HostedSocketTerminal {
    let (close, mut stop, observed, connection) = {
        let mut state = state.lock().unwrap();
        let recovery = state.reconnect.as_mut().unwrap();
        (
            recovery.close.take().unwrap(),
            recovery.stop.take().unwrap(),
            Arc::clone(&recovery.observed),
            recovery.connection,
        )
    };
    observed.lock().unwrap().upgrades = 1;
    if let Err(terminal) =
        super::friend::sockets::admit(&mut socket, Arc::clone(&state), sequence).await
    {
        return first_terminal(&observed, terminal);
    }
    let requested = tokio::select! {
        requested = close => requested.is_ok(),
        terminal = super::sockets::terminal(&mut socket) => {
            return first_terminal(&observed, terminal);
        }
    };
    if !requested {
        let terminal = super::sockets::terminal(&mut socket).await;
        return first_terminal(&observed, terminal);
    }
    {
        let state = state.lock().unwrap();
        let friend = state.friend.as_ref().unwrap();
        assert!(
            friend.reconnect_can_close(),
            "interrupt only actual admitted membership"
        );
        assert_eq!(
            state.snapshot["members"]["me"]["properties"]["system"]["connection"],
            json!(super::super::script::CONNECTION)
        );
    }
    socket.send(Message::close(None, "")).await.unwrap();
    let first = first_terminal(&observed, super::sockets::terminal(&mut socket).await);
    let (tcp, _) = tokio::select! {
        _ = &mut stop => return first,
        accepted = listener.accept() => accepted.unwrap(),
    };
    let mut replacement = super::sockets::upgrade_rta(tcp, &state).await;
    observed.lock().unwrap().upgrades += 1;
    let sequence = match super::sockets::subscription(&mut replacement).await {
        Ok(sequence) => sequence,
        Err(terminal) => return terminal,
    };
    state
        .lock()
        .unwrap()
        .reconnect
        .as_mut()
        .unwrap()
        .rebind_ready = true;
    replacement
        .send(Message::text(
            json!([1,sequence,0,29,{"ConnectionId":connection}]).to_string(),
        ))
        .await
        .unwrap();
    #[cfg(test)]
    {
        let hold = state
            .lock()
            .unwrap()
            .reconnect
            .as_mut()
            .unwrap()
            .ack_accounting_hold
            .take();
        if let Some(hold) = hold {
            hold.wait().await;
        }
    }
    acknowledged(&state);
    super::sockets::terminal(&mut replacement).await
}

/// Checks only the opted-in extra requests; all ordinary script cases remain original.
pub(super) fn respond(
    target: &str,
    headers: &str,
    body: &[u8],
    state: &mut State,
) -> Option<friend::service::Reply> {
    let recovery = state.reconnect.as_mut()?;
    if !recovery.rebind_ready {
        return None;
    }
    let reference = state.reference.as_ref().unwrap();
    let mut url = url::Url::parse(crate::xbox::mpsd::test_support::DIRECTORY_ENDPOINT).unwrap();
    url.path_segments_mut().unwrap().extend([
        "serviceconfigs",
        &reference.service_config_id().to_string(),
        "sessionTemplates",
        reference.template_name(),
        "sessions",
        reference.name(),
    ]);
    if target != url.path() {
        return None;
    }
    let mut facts = recovery.observed.lock().unwrap();
    if headers.starts_with("PUT ")
        && serde_json::from_slice::<Value>(body).unwrap()["members"]["me"].is_object()
    {
        assert_eq!(facts.rebinds, 0, "one original member rebind");
        assert_eq!(
            header(headers, "if-match"),
            recovery.validator.as_deref().unwrap()
        );
        let change: Value = serde_json::from_slice(body).unwrap();
        let binding = &change["members"]["me"]["properties"]["system"];
        let original = &state.snapshot["members"]["me"]["properties"]["system"];
        assert_eq!(
            change,
            json!({"members":{"me":{"properties":{"system":{
                "active":true,"connection":recovery.connection,"subscription":original["subscription"]
            }}}}})
        );
        assert_eq!(binding["subscription"], original["subscription"]);
        state.snapshot["members"]["me"]["properties"]["system"] = binding.clone();
        facts.rebinds = 1;
        let mut reply = friend::service::Reply::json(200, state.snapshot.clone());
        reply
            .headers
            .push(("ETag".into(), recovery.validator.clone().unwrap()));
        return Some(reply);
    }
    if headers.starts_with("GET ") && facts.rebinds == 1 && !facts.synchronized {
        assert!(body.is_empty());
        assert_eq!(
            header(headers, "if-none-match"),
            recovery.validator.as_deref().unwrap()
        );
        return Some(friend::service::Reply::json(304, Value::Null));
    }
    None
}

/// Records only actual flushed validators and sync completion on the original HTTP task.
pub(super) fn flushed(
    target: &str,
    headers: &str,
    reply: &friend::service::Reply,
    state: &mut State,
) {
    let Some(recovery) = &mut state.reconnect else {
        return;
    };
    for (name, value) in &reply.headers {
        if name.eq_ignore_ascii_case("etag") {
            recovery.validator = Some(value.clone());
        }
    }
    let mut facts = recovery.observed.lock().unwrap();
    if headers.starts_with("GET ")
        && target.starts_with("/serviceconfigs/")
        && facts.rebinds == 1
        && !facts.synchronized
    {
        facts.synchronized = true;
        let _ = recovery.rebound.take().unwrap().send(());
    }
}
