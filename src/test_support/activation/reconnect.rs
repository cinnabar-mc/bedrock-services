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
        let observed = Arc::new(Mutex::new(HostedRtaReconnectObservation::default()));
        state.reconnect = Some(Services {
            close: Some(closed),
            stop: Some(stopped),
            rebound: Some(rebound),
            observed: Arc::clone(&observed),
            connection: Uuid::new_v4(),
            validator: None,
        });
        HostedRtaReconnect {
            close: Some(close),
            stop: Some(stop),
            rebound: observed_rebind,
            observed,
        }
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

    /// Captures bounded original observations after the caller has joined all fixture tasks.
    pub fn observation(&self) -> HostedRtaReconnectObservation {
        *self.observed.lock().unwrap()
    }
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
        return terminal;
    }
    observed.lock().unwrap().acknowledgments = 1;
    if close.await.is_err() {
        return super::sockets::terminal(&mut socket).await;
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
    let first = super::sockets::terminal(&mut socket).await;
    {
        let mut facts = observed.lock().unwrap();
        facts.first_closed = first == HostedSocketTerminal::Close;
        facts.first_retired = matches!(
            &first,
            HostedSocketTerminal::Close
                | HostedSocketTerminal::Eof
                | HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
        );
    }
    let (mut replacement, sequence) = tokio::select! {
        _ = &mut stop => return first,
        accepted = super::sockets::accept_rta(&listener, &state) => accepted,
    };
    observed.lock().unwrap().upgrades += 1;
    replacement
        .send(Message::text(
            json!([1,sequence,0,29,{"ConnectionId":connection}]).to_string(),
        ))
        .await
        .unwrap();
    observed.lock().unwrap().acknowledgments += 1;
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
    if recovery.observed.lock().unwrap().acknowledgments != 2 {
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
