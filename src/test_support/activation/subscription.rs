//! One explicit hold after the original verified subscription request, before its acknowledgment.

use tokio::sync::oneshot;

/// Observes the actual subscription request and keeps its original service acknowledgment pending.
/// Drop releases the same handler; abort and join the fixture first when testing an incomplete prefix.
pub struct HostedSubscriptionHold {
    requested: oneshot::Receiver<()>,
    _release: oneshot::Sender<()>,
}

pub(super) struct SubscriptionHold {
    requested: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// Creates only a finite observation/release pair; neither side owns a task or socket.
pub(super) fn hold() -> (HostedSubscriptionHold, SubscriptionHold) {
    let (requested, observed) = oneshot::channel();
    let (release, resumed) = oneshot::channel();
    (
        HostedSubscriptionHold {
            requested: observed,
            _release: release,
        },
        SubscriptionHold {
            requested,
            release: resumed,
        },
    )
}

impl HostedSubscriptionHold {
    /// Waits until the original handler has verified the actual protected subscription request.
    /// This does not acknowledge it or alter application membership or authority.
    pub async fn requested(&mut self) {
        (&mut self.requested)
            .await
            .expect("original subscription request was not observed");
    }
}

impl SubscriptionHold {
    /// Reports only the actual parsed request, then retains its handler until the caller releases it.
    pub(super) async fn wait(self) {
        let _ = self.requested.send(());
        let _ = self.release.await;
    }
}
