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
    /// A terminal upgrade, framing or capacity failure prevents recovery.
    #[error(transparent)]
    Socket(#[from] SocketError),
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
            self.socket.interrupt_recovery();
        }
    }
}

impl RtaSocket {
    /// Recovers a disconnected socket and restores its desired subscriptions before returning snapshots.
    /// Drain the old socket's pending completions before calling. This method creates no task.
    /// Keep driving the socket afterward and apply returned events in order,
    /// including rebinding MPSD memberships from each new directory snapshot. Cancellation drops partial
    /// transport work; desired handles and any scheduled backoff survive a later call.
    /// An explicit service rejection returns a Failed event and retires only that desired resource.
    /// Rejections survive interruption; drive can deliver them if recovery is canceled.
    ///
    /// # Errors
    /// Returns terminal authentication, account/lifecycle or socket failures, or the caller's deadline.
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
        let desired = self.state.subscriptions().count();
        if self.recovery_events.len() + desired > MAX_QUEUED_EVENTS {
            return Err(Error::Limit.into());
        }
        if self.state.subscriptions().next().is_none() {
            self.abort();
            self.recovery = Backoff::default();
            return Ok(self.recovery_events.drain(..).collect());
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
                    Err(error) if account.retryable_rta_acquisition(&error) => {}
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
                            Err(error) if retryable_socket(error) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                guard.socket.interrupt_recovery();
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

    /// Drops epoch-dependent snapshots while preserving terminal rejections until the caller receives them.
    fn interrupt_recovery(&mut self) {
        self.recovery_events.retain(|event| {
            matches!(
                event,
                Event::Failed {
                    cause: crate::xbox::rta::Failure::Status(_),
                    ..
                }
            )
        });
        self.abort();
    }

    /// Restores one resource at a time so the bounded socket queue can hold every desired set.
    async fn restore_subscriptions(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<Event>>, RecoveryError> {
        let subscriptions = self.state.subscriptions().collect::<Vec<_>>();
        let count = subscriptions.len();
        for (index, subscription) in subscriptions.into_iter().enumerate() {
            let until = deadline.min(Instant::now() + Duration::from_secs(15));
            let request = self.resubscribe(subscription, until)?;
            loop {
                let event = match poll_fn(|cx| self.poll_drive(cx)).await {
                    Ok(Event::Disconnected) if retryable_socket(self.terminal) => return Ok(None),
                    Ok(Event::Disconnected) => return Err(self.terminal.into()),
                    Err(error) if retryable_socket(error) => return Ok(None),
                    Err(error) => return Err(error.into()),
                    Ok(
                        event @ Event::Failed {
                            cause: crate::xbox::rta::Failure::Status(_),
                            ..
                        },
                    ) => event,
                    Ok(Event::Failed { .. }) if retryable_socket(self.terminal) => return Ok(None),
                    Ok(Event::Failed { .. }) => return Err(self.terminal.into()),
                    Ok(event) => event,
                };
                let ready = matches!(&event,Event::Subscribed { request:received,.. } | Event::Failed {request:received,..} if *received == request);
                // Reserve one terminal completion for every restore that has not yet finished.
                let remaining = count - index - usize::from(ready);
                if self.recovery_events.len() + 1 + remaining > MAX_QUEUED_EVENTS {
                    return Err(Error::Limit.into());
                }
                let rejected = match &event {
                    Event::Failed { subscription, .. } => Some(*subscription),
                    _ => None,
                };
                self.recovery_events.push_back(event);
                if let Some(rejected) = rejected {
                    self.state.remove_idle(rejected)?;
                }
                if ready {
                    break;
                }
            }
        }
        Ok(Some(self.recovery_events.drain(..).collect()))
    }
}

/// Retries interrupted transport and temporary upgrade refusals without hiding terminal socket errors.
fn retryable_socket(error: SocketError) -> bool {
    matches!(
        error,
        SocketError::Transport
            | SocketError::TimedOut
            | SocketError::Closed
            | SocketError::UpgradeStatus(408 | 429 | 500..=599 | 999)
    )
}

#[cfg(test)]
mod tests;
