//! Optional caller-driven Tokio edge for one authenticated RTA socket.
//!
//! Generate [`upgrade_headers`] before Account::rta_connection signs its fields,
//! then [`RtaSocket::connect`] transmits those final headers unchanged. Continuously
//! poll [`RtaSocket::drive`] to process messages, automatic Pongs and deadlines.
//! There is no spawned task, internal runtime, heartbeat policy or automatic retry.
//! After disconnection, [`RtaSocket::recover`] can reacquire and restore desired
//! subscriptions with backoff inside the caller's deadline. Apply its returned snapshots
//! before processing later changes and rebind any affected MPSD memberships.
//! Dropping drive preserves partial writes; dropping this owner drops the socket.
//! Cancellation/expiry retires the whole socket as required by the pure owner.
//!
//! Protected requests and payloads are never logged. HTTP/TLS/WebSocket library
//! buffers can retain copies and are not guaranteed erased on drop.

mod recovery;
mod upgrade;
pub use recovery::RecoveryError;

use super::{
    Connection, ConnectionRequest, Error, Event, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS,
    RequestId, Resource, SubscriptionId,
};
use futures_util::{Sink, Stream};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::Sleep;
use tokio_websockets::Message;

/// Maximum retained application frames, excluding the one currently in the sink.
pub const MAX_QUEUED_MESSAGES: usize = 32;
/// Maximum retained application bytes, excluding the bounded active sink frame.
pub const MAX_QUEUED_BYTES: usize = 2 * MAX_MESSAGE_BYTES;
/// One prior event, all pending terminal completions, and the disconnection marker.
pub const MAX_QUEUED_EVENTS: usize = MAX_PENDING_REQUESTS + 2;
const POLL_BUDGET: usize = 32;

/// Finite establishment and graceful-close deadlines; request deadlines are supplied at admission.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// DNS, TCP, verified TLS and protected HTTP upgrade timeout.
    pub connect_timeout: Duration,
    /// Maximum time to complete a graceful close while driven.
    pub close_timeout: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(5),
        }
    }
}
impl Options {
    /// Validates deadlines before performing I/O or changing ownership.
    fn validate(self) -> Result<(), SocketError> {
        let now = Instant::now();
        if [self.connect_timeout, self.close_timeout]
            .into_iter()
            .any(|d| d.is_zero() || now.checked_add(d).is_none())
        {
            return Err(SocketError::Configuration);
        }
        Ok(())
    }
}

/// Redacted static/numeric failures; remote headers, close reasons and payloads are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SocketError {
    /// The protected request or edge options cannot be used.
    #[error("invalid RTA socket configuration")]
    Configuration,
    /// The protected issuance was already used or the lifecycle cannot be resumed.
    #[error("invalid RTA socket lifecycle")]
    State,
    /// A replacement would change XUID, proof owner or caller generation.
    #[error("RTA socket account generation mismatch")]
    WrongAccount,
    /// Upgrade refusal; 401 can explicitly reject this exact issuance through Account::reject_rta.
    #[error("RTA upgrade returned HTTP {0}")]
    UpgradeStatus(u16),
    /// DNS, socket or verified TLS failed.
    #[error("RTA socket transport failed")]
    Transport,
    /// The HTTP upgrade, WebSocket or RTA framing is invalid.
    #[error("invalid RTA socket protocol")]
    Protocol,
    /// A bounded message or collection exceeded capacity.
    #[error("RTA socket capacity exceeded")]
    Capacity,
    /// Establishment, an admitted request or graceful close reached its deadline.
    #[error("RTA socket timed out")]
    TimedOut,
    /// The caller or peer closed the socket.
    #[error("RTA socket closed")]
    Closed,
}
impl SocketError {
    /// Removes dependency diagnostics at the edge boundary.
    fn from_wire(error: tokio_websockets::Error) -> Self {
        match error {
            tokio_websockets::Error::PayloadTooLong { .. } => Self::Capacity,
            tokio_websockets::Error::Protocol(_) | tokio_websockets::Error::Upgrade(_) => {
                Self::Protocol
            }
            tokio_websockets::Error::AlreadyClosed => Self::Closed,
            _ => Self::Transport,
        }
    }
    /// Keeps account fencing distinguishable without exposing credential owners.
    fn from_state(error: Error) -> Self {
        match error {
            Error::WrongAccount => Self::WrongAccount,
            _ => Self::State,
        }
    }
}

/// Generates the transport's key and mandatory fields before final Account signing.
/// Pass the result to Account::rta_connection or Minecraft::rta_connection.
///
/// # Errors
/// Returns a redacted configuration failure if the fixed endpoint cannot form valid headers.
pub fn upgrade_headers() -> Result<reqwest::header::HeaderMap, SocketError> {
    upgrade::headers()
}

/// One physical socket, pure subscription owner and bounded wire/event queues, without tasks.
/// No Debug or serialization: resources, protected data and application payloads are private.
pub struct RtaSocket {
    socket: Option<upgrade::Socket>,
    state: Connection,
    outgoing: VecDeque<super::Outgoing>,
    queued_bytes: usize,
    events: VecDeque<Event>,
    write_active: bool,
    control_flush: bool,
    options: Options,
    close_deadline: Option<Instant>,
    terminal: SocketError,
    timer: Pin<Box<Sleep>>,
    recovery: recovery::Backoff,
}

impl RtaSocket {
    /// Opens the fixed protected destination and starts this issuance only after verified upgrade.
    /// Keep request for explicit exact-issuance rejection on UpgradeStatus(401).
    /// Cancellation drops the in-progress socket and leaves the issuance unstarted.
    ///
    /// # Errors
    /// Returns a redacted configuration, reuse, transport, protocol or numeric upgrade failure.
    pub async fn connect(
        request: &mut ConnectionRequest,
        options: Options,
    ) -> Result<Self, SocketError> {
        options.validate()?;
        request.unused().map_err(SocketError::from_state)?;
        let socket = upgrade::connect(request, options).await?;
        let state = request.start().map_err(SocketError::from_state)?;
        Ok(Self::from_socket(socket, state, options))
    }

    /// Installs already-verified I/O with all cancellation-sensitive progress in the owner.
    fn from_socket(socket: upgrade::Socket, state: Connection, options: Options) -> Self {
        Self {
            socket: Some(socket),
            state,
            outgoing: VecDeque::new(),
            queued_bytes: 0,
            events: VecDeque::new(),
            write_active: false,
            control_flush: false,
            options,
            close_deadline: None,
            terminal: SocketError::Closed,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            recovery: recovery::Backoff::default(),
        }
    }

    /// Borrows identity, desired handles and current MPSD bindings without permitting detached mutation.
    pub fn connection(&self) -> &Connection {
        &self.state
    }

    /// Explicitly closes old I/O and discards old frames/events, then attempts exactly one fresh upgrade.
    /// Account/generation/issuance are checked before closing the current socket or doing new I/O.
    /// Desired local handles survive; the caller must explicitly resubscribe and install snapshots.
    /// Failure or cancellation leaves this owner disconnected with its desired handles retained.
    ///
    /// # Errors
    /// Returns account/lifecycle fencing or the new upgrade's redacted failure.
    pub async fn reconnect(
        &mut self,
        request: &mut ConnectionRequest,
        options: Options,
    ) -> Result<(), SocketError> {
        options.validate()?;
        self.state
            .check_reconnect(request)
            .map_err(SocketError::from_state)?;
        self.finish(SocketError::Closed);
        self.events.clear();
        let socket = match upgrade::connect(request, options).await {
            Ok(socket) => socket,
            Err(error) => {
                self.terminal = error;
                return Err(error);
            }
        };
        self.state
            .reconnect(request)
            .map_err(SocketError::from_state)?;
        self.socket = Some(socket);
        self.options = options;
        self.write_active = false;
        self.control_flush = false;
        Ok(())
    }

    /// Admits one subscribe transaction; returns both the desired handle and cancelable request.
    /// # Errors
    /// Invalid state/deadline/capacity leaves no new subscription or queued frame.
    pub fn subscribe(
        &mut self,
        resource: Resource,
        deadline: Instant,
    ) -> Result<(SubscriptionId, RequestId), Error> {
        self.ensure_admission()?;
        let (subscription, outgoing) = self.state.subscribe(resource, Instant::now(), deadline)?;
        let request = outgoing.request_id();
        self.queue(outgoing);
        Ok((subscription, request))
    }

    /// Explicitly restores one desired resource after a successful reconnect.
    /// # Errors
    /// Returns invalid state/deadline/capacity before queueing output.
    pub fn resubscribe(
        &mut self,
        subscription: SubscriptionId,
        deadline: Instant,
    ) -> Result<RequestId, Error> {
        self.ensure_admission()?;
        let outgoing = self
            .state
            .resubscribe(subscription, Instant::now(), deadline)?;
        let request = outgoing.request_id();
        self.queue(outgoing);
        Ok(request)
    }

    /// Removes an idle resource locally, or admits an active unsubscribe transaction.
    /// # Errors
    /// Returns invalid state/deadline/capacity before changing subscription ownership.
    pub fn unsubscribe(
        &mut self,
        subscription: SubscriptionId,
        deadline: Instant,
    ) -> Result<Option<RequestId>, Error> {
        self.ensure_admission()?;
        let Some(outgoing) = self
            .state
            .unsubscribe(subscription, Instant::now(), deadline)?
        else {
            return Ok(None);
        };
        let request = outgoing.request_id();
        self.queue(outgoing);
        Ok(Some(request))
    }

    /// Cancels one pending request and immediately drops the whole ambiguous physical socket.
    /// Drive to drain its correlated completions; reconnect is an explicit caller decision.
    pub fn cancel(&mut self, request: RequestId) -> bool {
        let events = self.state.cancel(request);
        if events.is_empty() {
            return false;
        }
        self.events.extend(events);
        self.finish(SocketError::Closed);
        true
    }

    /// Stops admission permanently and begins a bounded close handshake; continue driving.
    pub fn close(&mut self) {
        self.events.extend(self.state.close());
        self.begin_close();
    }

    /// Retains desired resources when the peer closes only the physical transport.
    fn peer_close(&mut self) {
        self.events.extend(self.state.disconnect());
        self.begin_close();
    }

    /// Bounds the existing sink's close acknowledgement, discarding only unadmitted output.
    fn begin_close(&mut self) {
        if self.socket.is_none() || self.close_deadline.is_some() {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(self.options.close_timeout) else {
            self.finish(SocketError::Configuration);
            return;
        };
        self.close_deadline = Some(deadline);
        self.outgoing.clear();
        self.queued_bytes = 0;
    }

    /// Immediately drops I/O and fails pending requests, retaining desired resources for explicit reconnect.
    pub fn abort(&mut self) {
        self.finish(SocketError::Closed);
    }

    /// Drops physical I/O and all queued frames/events, returning disconnected pure state for another driver.
    pub fn into_connection(mut self) -> Connection {
        self.finish(SocketError::Closed);
        self.state
    }

    /// Advances writes, ordered reads, automatic controls and deadlines until one application event exists.
    /// Dropping this future preserves active-frame progress without replay. Call continuously even idle.
    /// # Errors
    /// Returns the same redacted terminal cause after retained events/completions drain.
    pub async fn drive(&mut self) -> Result<Event, SocketError> {
        poll_fn(|cx| self.poll_drive(cx)).await
    }

    /// Reserves one maximum frame and all possible pending completions before pure-state mutation.
    fn ensure_admission(&mut self) -> Result<(), Error> {
        self.tick(Instant::now());
        if self.socket.is_none() || self.close_deadline.is_some() || !self.state.is_connected() {
            return Err(Error::Disconnected);
        }
        if self.outgoing.len() >= MAX_QUEUED_MESSAGES
            || self.queued_bytes > MAX_QUEUED_BYTES - MAX_MESSAGE_BYTES
            || self.events.len() > 1
        {
            return Err(Error::Limit);
        }
        Ok(())
    }

    /// Queues only a pure-owner bounded frame after synchronous capacity reservation.
    fn queue(&mut self, outgoing: super::Outgoing) {
        self.queued_bytes += outgoing.as_str().len();
        self.outgoing.push_back(outgoing);
    }

    /// Retires I/O immediately while preserving bounded ordered outcomes and desired resources.
    fn finish(&mut self, error: SocketError) {
        self.socket = None;
        self.terminal = error;
        self.outgoing.clear();
        self.queued_bytes = 0;
        self.write_active = false;
        self.control_flush = false;
        self.close_deadline = None;
        self.events.extend(self.state.disconnect());
        debug_assert!(self.events.len() <= MAX_QUEUED_EVENTS);
    }

    /// Expires before reads/writes/admission so retired epochs cannot send buffered output.
    fn tick(&mut self, now: Instant) {
        let expired = self.state.expire(now);
        if !expired.is_empty() {
            self.events.extend(expired);
            self.finish(SocketError::TimedOut);
        }
        if self.close_deadline.is_some_and(|deadline| now >= deadline) {
            self.finish(SocketError::TimedOut);
        }
    }

    /// Admits one frame into the sink; Pending flushes retain progress and the latest caller's waker.
    fn poll_write(&mut self, cx: &mut Context<'_>) {
        let Some(socket) = self.socket.as_mut() else {
            return;
        };
        if self.write_active || self.control_flush {
            match Pin::new(&mut *socket).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.write_active = false;
                    self.control_flush = false;
                }
                Poll::Ready(Err(e)) => {
                    self.finish(SocketError::from_wire(e));
                    return;
                }
                Poll::Pending => return,
            }
        }
        while self
            .outgoing
            .front()
            .is_some_and(|f| !self.state.is_current(f))
        {
            let old = self.outgoing.pop_front().expect("checked output queue");
            self.queued_bytes -= old.as_str().len();
        }
        if self.outgoing.is_empty() {
            return;
        }
        match Pin::new(&mut *socket).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                self.finish(SocketError::from_wire(e));
                return;
            }
            Poll::Pending => return,
        }
        let outgoing = self.outgoing.pop_front().expect("checked output queue");
        self.queued_bytes -= outgoing.as_str().len();
        if let Err(e) =
            Pin::new(&mut *socket).start_send(Message::text(outgoing.as_str().as_bytes().to_vec()))
        {
            self.finish(SocketError::from_wire(e));
            return;
        }
        self.write_active = true;
        match Pin::new(socket).poll_flush(cx) {
            Poll::Ready(Ok(())) => self.write_active = false,
            Poll::Ready(Err(e)) => self.finish(SocketError::from_wire(e)),
            Poll::Pending => {}
        }
    }

    /// Polls finite work, parking on actual I/O or the earliest request/close deadline.
    fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, SocketError>> {
        self.tick(Instant::now());
        let mut exhausted = true;
        for _ in 0..POLL_BUDGET {
            self.tick(Instant::now());
            if let Some(socket) = self.socket.as_mut() {
                if self.close_deadline.is_some() {
                    match Pin::new(socket).poll_close(cx) {
                        Poll::Ready(Ok(())) => self.finish(SocketError::Closed),
                        Poll::Ready(Err(e)) => self.finish(SocketError::from_wire(e)),
                        Poll::Pending => {}
                    }
                } else {
                    self.poll_write(cx);
                }
            }
            if let Some(event) = self.events.pop_front() {
                return Poll::Ready(Ok(event));
            }
            if self.socket.is_none() {
                return Poll::Ready(Err(self.terminal));
            }
            if self.close_deadline.is_some() || self.control_flush {
                exhausted = false;
                break;
            }
            match Pin::new(self.socket.as_mut().expect("live socket")).poll_next(cx) {
                Poll::Ready(Some(Ok(message))) if message.is_text() || message.is_binary() => {
                    match self.state.receive(
                        self.state.epoch(),
                        message.as_payload(),
                        Instant::now(),
                    ) {
                        Ok(events) => {
                            self.events.extend(events);
                            if !self.state.is_connected() {
                                self.finish(SocketError::TimedOut);
                            }
                        }
                        Err(Error::Limit) => self.finish(SocketError::Capacity),
                        Err(_) => self.finish(SocketError::Protocol),
                    }
                }
                Poll::Ready(Some(Ok(message))) if message.is_ping() || message.is_pong() => {
                    self.control_flush = true
                }
                Poll::Ready(Some(Ok(message))) if message.is_close() => self.peer_close(),
                Poll::Ready(Some(Ok(_))) => self.finish(SocketError::Protocol),
                Poll::Ready(Some(Err(e))) => self.finish(SocketError::from_wire(e)),
                Poll::Ready(None) => self.finish(SocketError::Closed),
                Poll::Pending => {
                    exhausted = false;
                    break;
                }
            }
        }
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        if self.socket.is_none() {
            return Poll::Ready(Err(self.terminal));
        }
        if let Some(deadline) = self.close_deadline.or_else(|| self.state.next_deadline()) {
            self.timer
                .as_mut()
                .reset(tokio::time::Instant::from_std(deadline));
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        if exhausted || (!self.write_active && !self.control_flush && !self.outgoing.is_empty()) {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
