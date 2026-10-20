//! Caller-driven reconnect, bounded backoff and ordered restoration of desired resources.

use super::*;
use crate::xbox::Account;

/// Redacted failures from a caller-bounded RTA recovery operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryError {
    /// The caller's original recovery deadline elapsed.
    #[error("RTA recovery deadline elapsed")]
    Deadline,
    /// The supplied account, generation or subscription lifecycle cannot be recovered.
    #[error(transparent)]
    State(#[from] Error),
    /// A subscription was explicitly rejected by the replacement connection.
    #[error("RTA subscription restoration returned {status}")]
    Subscription {
        /// Desired resource whose restoration the service rejected.
        subscription: SubscriptionId,
        /// Numeric RTA service rejection, without its diagnostic payload.
        status: i32,
    },
}

#[derive(Default)]
pub(super) struct Backoff {
    attempt: u32,
    next: Option<tokio::time::Instant>,
}

impl Backoff {
    /// Retains capped 1/2/4/8/16/32/60-second waits plus up to 50% jitter across cancellations.
    fn failed(&mut self, now: tokio::time::Instant, jitter: f64) {
        let base = (1_u64 << self.attempt.min(6)).min(60);
        self.attempt = self.attempt.saturating_add(1);
        self.next = Some(now + Duration::from_secs_f64(base as f64 * (1.0 + 0.5 * jitter)));
    }
}

struct Guard<'a> {
    socket: &'a mut RtaSocket,
    complete: bool,
}

impl Drop for Guard<'_> {
    /// Cancels partial handshakes on their physical socket while retaining desired local handles.
    fn drop(&mut self) {
        if !self.complete {
            self.socket.abort();
        }
    }
}

impl RtaSocket {
    /// Recovers a disconnected socket and restores its desired subscriptions before returning snapshots.
    /// Drain the old socket's pending completions before calling. This method creates no task.
    /// Keep driving the socket afterward and apply returned events in order,
    /// including rebinding MPSD memberships from each new directory snapshot. Cancellation drops partial
    /// transport work; desired handles and any scheduled backoff survive a later call.
    ///
    /// # Errors
    /// Returns account/lifecycle mismatches, explicit subscription rejection, or the caller's deadline.
    /// Transient acquisition, upgrade and interrupted-resubscribe failures retry until that deadline.
    pub async fn recover(
        &mut self,
        account: &mut Account,
        deadline: Instant,
    ) -> Result<Vec<Event>, RecoveryError> {
        if Instant::now() >= deadline {
            return Err(RecoveryError::Deadline);
        }
        if self.state.closed || self.state.is_connected() {
            return Err(Error::State.into());
        }
        if self.state.scope.proof != *account.key.verifying_key() {
            return Err(Error::WrongAccount.into());
        }
        if self.state.subscriptions().next().is_none() {
            self.abort();
            return Ok(Vec::new());
        }
        let mut guard = Guard {
            socket: self,
            complete: false,
        };
        let result = tokio::time::timeout_at(deadline.into(), async {
            loop {
                if let Some(next) = guard.socket.recovery.next {
                    #[cfg(test)]
                    if account.trace_rta_transport.is_some() {
                        // Only the shared trace peer uses a manually advanced Tokio retry clock.
                        tokio::time::pause();
                        tokio::time::advance(
                            next.saturating_duration_since(tokio::time::Instant::now()),
                        )
                        .await;
                        tokio::time::resume();
                    }
                    tokio::time::sleep_until(next).await;
                }
                if Instant::now() >= deadline {
                    return Err(RecoveryError::Deadline);
                }
                let generation = guard.socket.state.generation();
                let headers =
                    upgrade_headers().map_err(|_| Error::Invalid("recovery upgrade fields"))?;
                match account.rta_connection(generation, headers).await {
                    Err(Error::Service(_)) => {}
                    Err(error) => return Err(error.into()),
                    Ok(mut request) => {
                        guard.socket.state.check_reconnect(&request)?;
                        match guard
                            .socket
                            .reconnect(&mut request, guard.socket.options)
                            .await
                        {
                            Ok(()) => {
                                if let Some(events) =
                                    guard.socket.restore_subscriptions(deadline).await?
                                {
                                    guard.socket.recovery = Backoff::default();
                                    return Ok(events);
                                }
                            }
                            Err(SocketError::UpgradeStatus(401)) => {
                                account.reject_rta(&request);
                            }
                            Err(_) => {}
                        }
                    }
                }
                guard.socket.abort();
                guard
                    .socket
                    .recovery
                    .failed(tokio::time::Instant::now(), rand::random());
            }
        })
        .await
        .map_err(|_| RecoveryError::Deadline)?;
        guard.complete = result.is_ok();
        result
    }

    /// Restores one resource at a time so the bounded socket queue can hold every desired set.
    async fn restore_subscriptions(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<Event>>, RecoveryError> {
        let subscriptions = self.state.subscriptions().collect::<Vec<_>>();
        let mut events = Vec::new();
        for subscription in subscriptions {
            let until = deadline.min(Instant::now() + Duration::from_secs(15));
            let request = self.resubscribe(subscription, until)?;
            loop {
                let event = match self.drive().await {
                    Ok(Event::Disconnected) | Err(_) => return Ok(None),
                    Ok(Event::Failed {
                        subscription,
                        cause: crate::xbox::rta::Failure::Status(status),
                        ..
                    }) => {
                        return Err(RecoveryError::Subscription {
                            subscription,
                            status,
                        });
                    }
                    Ok(Event::Failed { .. }) => return Ok(None),
                    Ok(event) => event,
                };
                let ready = matches!(&event,Event::Subscribed { request:received,.. } if *received == request);
                if events.len() >= MAX_QUEUED_EVENTS {
                    return Err(Error::Limit.into());
                }
                events.push(event);
                if ready {
                    break;
                }
            }
        }
        Ok(Some(events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uses real original upgrade credentials and transport, then retires only that socket.
    async fn disconnected(desired: bool) -> (Account, RtaSocket) {
        let (account, mut request) = super::super::test_support::request().await;
        let (transport, peer) = super::super::test_support::transport(&request, None).await;
        let state = request.start().unwrap();
        let mut socket = RtaSocket::from_socket(transport, state, Options::default());
        if desired {
            socket
                .subscribe(
                    Resource::session_directory(),
                    Instant::now() + Duration::from_secs(15),
                )
                .unwrap();
        }
        socket.abort();
        drop(peer);
        (account, socket)
    }

    /// A canceled recovery retires partial I/O while retaining desired handles and its scheduled wait.
    #[tokio::test]
    async fn canceled_recovery_retains_desires_and_backoff() {
        let (mut account, mut socket) = disconnected(true).await;
        let until = tokio::time::Instant::now() + Duration::from_secs(60);
        socket.recovery.next = Some(until);
        {
            let recovery = socket.recover(&mut account, Instant::now() + Duration::from_secs(120));
            tokio::pin!(recovery);
            poll_fn(|cx| {
                assert!(recovery.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert!(socket.socket.is_none());
        assert_eq!(socket.state.subscriptions().count(), 1);
        assert_eq!(socket.recovery.next, Some(until));
        assert!(matches!(
            socket
                .recover(&mut account, Instant::now() - Duration::from_secs(1))
                .await,
            Err(RecoveryError::Deadline)
        ));
        assert_eq!(socket.state.subscriptions().count(), 1);
    }

    /// No desired subscriptions require no upgrade, while another proof owner is rejected before I/O.
    #[tokio::test]
    async fn empty_recovery_is_network_free_and_wrong_account_is_fenced() {
        let (mut account, mut socket) = disconnected(false).await;
        let (mut other, _) = super::super::test_support::request().await;
        assert!(matches!(
            socket
                .recover(&mut other, Instant::now() + Duration::from_secs(1))
                .await,
            Err(RecoveryError::State(Error::WrongAccount))
        ));
        assert!(
            socket
                .recover(&mut account, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The schedule caps at 60 seconds before jitter, and cache reads do not move its deadline.
    #[tokio::test(start_paused = true)]
    async fn recovery_backoff_is_capped_and_retains_its_deadline() {
        let mut backoff = Backoff::default();
        for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
            let now = tokio::time::Instant::now();
            backoff.failed(now, 0.0);
            assert_eq!(backoff.next, Some(now + Duration::from_secs(seconds)));
            tokio::time::advance(Duration::from_secs(seconds)).await;
        }
        let now = tokio::time::Instant::now();
        backoff.failed(now, 1.0);
        assert_eq!(backoff.next, Some(now + Duration::from_secs(90)));
    }
}
