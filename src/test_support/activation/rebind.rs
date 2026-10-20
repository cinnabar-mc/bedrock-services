//! One canceled original friend PUT, held before application or before its response.

use super::*;
use crate::xbox::{
    mpsd::test_support::header,
    test_support::{read_request, write_response},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::oneshot,
};

/// Retains one verified friend rebind request until the caller cancels its borrowed operation.
/// Drop releases only the original service handler; it does not create or remove membership.
pub struct HostedRebindHold {
    requested: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    retired: oneshot::Receiver<io::Result<()>>,
}

pub(super) struct Hold {
    applied: bool,
    requested: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
    retired: oneshot::Sender<io::Result<()>>,
}

impl HostedPeer {
    /// Holds the original validated PUT after application, before sending any response bytes.
    /// Arm after hold_rta_reconnect and before the first RTA upgrade; cancel the PUT before release.
    pub fn hold_friend_rebind_response(&mut self) -> HostedRebindHold {
        arm(self, true)
    }

    /// Holds one validated PUT before application and permits one real old-snapshot cleanup GET.
    /// Release applies that same retained PUT; no replacement write or new membership is created.
    pub fn hold_friend_rebind_application(&mut self) -> HostedRebindHold {
        arm(self, false)
    }
}

/// Installs only this fixed original-member sibling, with no endpoint or response policy input.
fn arm(peer: &mut HostedPeer, applied: bool) -> HostedRebindHold {
    let mut state = peer.activation.as_ref().unwrap().state.lock().unwrap();
    assert!(state.friend.as_ref().unwrap().reconnect_can_arm());
    let recovery = state
        .reconnect
        .as_mut()
        .expect("arm original RTA reconnect first");
    assert!(recovery.rebind_hold.is_none());
    let (requested, observed) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (retired, retirement) = oneshot::channel();
    recovery.rebind_hold = Some(Hold {
        applied,
        requested,
        release: released,
        retired,
    });
    HostedRebindHold {
        requested: observed,
        release: Some(release),
        retired: retirement,
    }
}

impl HostedRebindHold {
    /// Waits for actual signed request validation, at the selected application boundary.
    pub async fn requested(&mut self) {
        (&mut self.requested)
            .await
            .expect("original rebind was not observed");
    }

    /// Releases the same handler after the caller has canceled its original request future.
    pub fn release(&mut self) {
        self.release.take();
    }

    /// Requires actual HTTP EOF or TLS abort EOF on the original canceled request's socket.
    /// Other errors and unexpected request bytes remain failures.
    pub async fn retired(&mut self) -> io::Result<()> {
        (&mut self.retired)
            .await
            .map_err(|_| io::Error::other("original rebind handler lost"))?
    }
}

/// Retains at most one original request/stream; the same task may serve one reconciliation read.
pub(super) async fn cancelled_request(
    listener: &TcpListener,
    shared: &Shared,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    target: &str,
    headers: &str,
    body: &[u8],
) -> bool {
    let Some((hold, binding)) = ({
        let mut state = shared.lock().unwrap();
        if state
            .reconnect
            .as_ref()
            .is_some_and(|r| r.rebind_hold.is_some())
        {
            super::reconnect::rebind(target, headers, body, &state).map(|binding| {
                super::script::verify_directory(target, headers, body, &state);
                assert!(state.verified_http_requests < 32);
                state.verified_http_requests += 1;
                let hold = state
                    .reconnect
                    .as_mut()
                    .unwrap()
                    .rebind_hold
                    .take()
                    .unwrap();
                state.reconnect.as_mut().unwrap().canceled_bind = true;
                if hold.applied {
                    super::reconnect::apply_rebind(binding.clone(), &mut state);
                }
                (hold, binding)
            })
        } else {
            None
        }
    }) else {
        return false;
    };
    let Hold {
        applied,
        requested,
        mut release,
        retired,
    } = hold;
    let _ = requested.send(());
    if applied {
        let _ = release.await;
    } else {
        tokio::select! {
            _ = &mut release => {},
            accepted = listener.accept() => {
                let (tcp, _) = accepted.unwrap();
                old_snapshot(tcp, shared, target).await;
                let _ = release.await;
            }
        }
        super::reconnect::apply_rebind(binding, &mut shared.lock().unwrap());
    }
    let result = match stream.read(&mut [0]).await {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected canceled rebind input",
        )),
    };
    let _ = retired.send(result);
    true
}

/// Serves one actual unconditional same-reference read while the original PUT is still unapplied.
async fn old_snapshot(tcp: tokio::net::TcpStream, shared: &Shared, target: &str) {
    let mut stream = rta::websocket::test_support::acceptor()
        .accept(tcp)
        .await
        .unwrap();
    let (bytes, end, length) = read_request(&mut stream).await;
    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
    let received = headers.split_whitespace().nth(1).unwrap();
    let reply = {
        let mut state = shared.lock().unwrap();
        assert!(headers.starts_with("GET ") && received == target && length == 0);
        assert!(header(headers, "if-none-match").is_empty());
        super::script::verify_directory(received, headers, &[], &state);
        assert!(state.verified_http_requests < 32);
        state.verified_http_requests += 1;
        let recovery = state.reconnect.as_ref().unwrap();
        assert_eq!(recovery.observed.lock().unwrap().rebinds, 0);
        let mut reply = friend::service::Reply::json(200, state.snapshot.clone());
        reply
            .headers
            .push(("ETag".into(), recovery.validator.clone().unwrap()));
        reply
    };
    let body = serde_json::to_vec(&reply.body).unwrap();
    let mut headers: Vec<_> = reply
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    headers.push(("Date", super::super::script::DATE));
    write_response(&mut stream, 200, headers, &body).await;
}
