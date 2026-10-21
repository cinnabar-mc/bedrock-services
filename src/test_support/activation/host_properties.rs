//! One full host occupancy write held across actual original RTA retirement.

use super::*;
use crate::xbox::mpsd::test_support::header;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::oneshot,
};

/// Observes one actual signed host document write without creating or approving membership.
/// Drop releases only the fixture hold; successful retirement still requires the real socket facts.
pub struct HostedPropertiesHold {
    requested: oneshot::Receiver<()>,
    _release: oneshot::Sender<()>,
    applied: Arc<Mutex<usize>>,
}

pub(super) struct Hold {
    requested: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
    first_retired: oneshot::Receiver<bool>,
    applied: Arc<Mutex<usize>>,
}

impl HostedPeer {
    /// Holds the next post-activation occupancy PUT response until original RTA retirement.
    /// Arm after hold_host_rta_reconnect and before its first upgrade. Only MemberCount1→2 changes.
    pub fn hold_host_properties_response(&mut self) -> HostedPropertiesHold {
        let mut state = self.activation.as_ref().unwrap().state.lock().unwrap();
        assert!(!state.rta_upgraded && state.friend.is_none() && state.reference.is_none());
        let recovery = state
            .reconnect
            .as_mut()
            .expect("arm the original host reconnect first");
        assert!(recovery.properties_hold.is_none() && recovery.first_terminal.is_none());
        let (requested, observed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (retired, first_retired) = oneshot::channel();
        let applied = Arc::new(Mutex::new(0));
        recovery.first_terminal = Some(retired);
        recovery.properties_hold = Some(Hold {
            requested,
            release: released,
            first_retired,
            applied: Arc::clone(&applied),
        });
        HostedPropertiesHold {
            requested: observed,
            _release: release,
            applied,
        }
    }
}

impl HostedPropertiesHold {
    /// Waits for actual original signature/reference/validator/full-document validation and application.
    pub async fn requested(&mut self) -> bool {
        (&mut self.requested).await.is_ok()
    }

    /// Counts only this actual applied occupancy PUT; capture after joining original service tasks.
    pub fn applied(&self) -> usize {
        *self.applied.lock().unwrap()
    }
}

/// Retains the original stream without sending a replacement response or spawning a service task.
pub(super) async fn hold_request(
    shared: &Shared,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    target: &str,
    headers: &str,
    body: &[u8],
) -> bool {
    let hold = {
        let mut state = shared.lock().unwrap();
        if state.verified_http_requests < 16
            || !headers.starts_with("PUT ")
            || state
                .reconnect
                .as_ref()
                .is_none_or(|r| r.properties_hold.is_none())
        {
            return false;
        }
        let value: Value = serde_json::from_slice(body).unwrap();
        if value.get("properties").is_none() {
            return false;
        }
        script::verify_directory(target, headers, body, &state);
        script::verify_target(target, &state);
        let recovery = state.reconnect.as_ref().unwrap();
        assert_eq!(
            header(headers, "if-match"),
            recovery.validator.as_deref().unwrap()
        );
        assert!(!recovery.properties_applied);
        let mut expected = state.snapshot["properties"]["custom"].clone();
        assert_eq!(expected["MemberCount"], 1);
        expected["MemberCount"] = json!(2);
        assert_eq!(value, json!({"properties":{"custom":expected}}));
        assert!(state.verified_http_requests < EXCHANGES + 4);
        state.verified_http_requests += 1;
        state.snapshot["properties"]["custom"] = value["properties"]["custom"].clone();
        let change = state.snapshot["changeNumber"]
            .as_u64()
            .unwrap()
            .checked_add(1)
            .unwrap();
        state.snapshot["changeNumber"] = json!(change);
        let recovery = state.reconnect.as_mut().unwrap();
        recovery.validator = Some("\"host-occupied\"".into());
        recovery.properties_applied = true;
        let hold = recovery.properties_hold.take().unwrap();
        *hold.applied.lock().unwrap() += 1;
        hold
    };
    let Hold {
        requested,
        release,
        first_retired,
        ..
    } = hold;
    let _ = requested.send(());
    let retired = tokio::select! {
        retired = first_retired => retired.unwrap_or(false),
        _ = release => false,
    };
    // Only the actual old socket terminal releases this successful scenario. Drop can unblock a
    // failed caller, but neither it nor arbitrary IO errors become successful retirement evidence.
    let terminal = stream.read(&mut [0]).await;
    assert!(
        matches!(terminal, Ok(0))
            || matches!(terminal, Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof),
        "original canceled occupancy response did not retire by EOF"
    );
    assert!(
        retired,
        "original RTA did not physically retire before held response cleanup"
    );
    true
}

/// Returns the complete actually applied document for dirty or old-validator reconciliation.
pub(super) fn snapshot(
    headers: &str,
    body: &[u8],
    state: &State,
) -> Option<friend::service::Reply> {
    let recovery = state.reconnect.as_ref().unwrap();
    if !recovery.properties_applied || !headers.starts_with("GET ") {
        return None;
    }
    assert!(body.is_empty());
    let previous = header(headers, "if-none-match");
    let validator = recovery.validator.as_deref().unwrap();
    if previous == validator {
        return Some(friend::service::Reply::json(304, Value::Null));
    }
    assert!(previous.is_empty() || previous == "\"host-acknowledged\"");
    let mut reply = friend::service::Reply::json(200, state.snapshot.clone());
    reply.headers.push(("ETag".into(), validator.into()));
    Some(reply)
}
