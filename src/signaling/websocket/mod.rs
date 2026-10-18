//! Optional Tokio WebSocket edge for Player Messaging.
//!
//! One owner holds the socket, wire buffers and bounded event queue. There are no
//! spawned tasks, internal runtimes or automatic reconnects. Call [`MessagingSocket::drive`]
//! continuously: service pings, deadlines, control replies and close handshakes
//! progress only while the caller polls it. Dropping a drive future preserves
//! partially written frames; dropping the owner immediately drops the socket.
//! Signal receipt acknowledgement remains an explicit caller decision.
//!
//! The SDK and selected WebSocket implementation do not log credentials or payloads.
//! Neither owner implements Debug. Library/TLS buffers are not guaranteed to be
//! erased on drop; do not log signals, TURN credentials or protected requests.

mod upgrade;

use super::{
    Error, Event, Failure, MAX_BATCH_MESSAGES, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, Messaging,
    Outgoing, ReceivedSignal, RequestId, TurnCredentials,
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
use uuid::Uuid;

/// Maximum queued wire messages, including one reserved callback response.
pub const MAX_QUEUED_MESSAGES: usize = 32;
/// Maximum queued JSON bytes, including one reserved maximum-size callback response.
pub const MAX_QUEUED_BYTES: usize = 2 * MAX_MESSAGE_BYTES;
/// Maximum retained events, including reserved completions for every outstanding request.
pub const MAX_QUEUED_EVENTS: usize =
    MAX_PENDING_REQUESTS + MAX_BATCH_MESSAGES * MAX_BATCH_MESSAGES + MAX_BATCH_MESSAGES;
const POLL_BUDGET: usize = 32;

/// Finite edge timeouts. Service ping frequency comes from the acquired configuration.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// DNS, TCP, TLS and HTTP upgrade deadline.
    pub connect_timeout: Duration,
    /// Maximum time to admit and complete a service ping once it is due.
    pub ping_timeout: Duration,
    /// Maximum time to finish the WebSocket close handshake while driven.
    pub close_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(5),
            close_timeout: Duration::from_secs(5),
        }
    }
}

impl Options {
    /// Rejects zero or unrepresentable deadlines before starting I/O.
    fn validate(self, now: Instant, interval: Duration) -> Result<(), SocketError> {
        for duration in [
            self.connect_timeout,
            self.ping_timeout,
            self.close_timeout,
            interval,
        ] {
            if duration.is_zero() || now.checked_add(duration).is_none() {
                return Err(SocketError::Configuration);
            }
        }
        now.checked_add(interval)
            .and_then(|due| due.checked_add(self.ping_timeout))
            .ok_or(SocketError::Configuration)?;
        Ok(())
    }
}

/// Static or numeric failures; no raw URLs, headers, server bodies or close reasons survive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SocketError {
    /// The protected upgrade or edge timeout configuration is invalid.
    #[error("invalid messaging socket configuration")]
    Configuration,
    /// The HTTP upgrade was refused; 401 may invalidate the exact ConnectionRequest issuance.
    #[error("messaging upgrade returned HTTP {0}")]
    UpgradeStatus(u16),
    /// DNS, TCP, verified TLS or socket I/O failed.
    #[error("messaging socket transport failed")]
    Transport,
    /// HTTP upgrade, WebSocket or JSON-RPC framing was malformed.
    #[error("invalid messaging socket protocol")]
    Protocol,
    /// A wire message or bounded queue exceeded its limit.
    #[error("messaging socket capacity exceeded")]
    Capacity,
    /// A connection, heartbeat or close deadline elapsed.
    #[error("messaging socket timed out")]
    TimedOut,
    /// The application heartbeat failed with a redacted correlated cause.
    #[error("messaging heartbeat failed")]
    Heartbeat(Failure),
    /// The owner or peer closed the connection.
    #[error("messaging socket closed")]
    Closed,
}

impl SocketError {
    /// Drops library diagnostics before crossing the public error boundary.
    fn from_wire(error: tokio_websockets::Error) -> Self {
        use tokio_websockets::{Error as WireError, upgrade::Error as UpgradeError};
        match error {
            WireError::Upgrade(UpgradeError::DidNotSwitchProtocols(status)) => {
                Self::UpgradeStatus(status)
            }
            WireError::PayloadTooLong { .. } => Self::Capacity,
            WireError::Protocol(_) | WireError::Upgrade(_) => Self::Protocol,
            WireError::AlreadyClosed => Self::Closed,
            _ => Self::Transport,
        }
    }
}

/// One authenticated socket and its request state, driven exclusively by its caller.
///
/// Admission is synchronous and transactional. Capacity errors produce no handle
/// or wire write, so the caller can retry after driving/draining this owner. Once
/// a frame enters the WebSocket sink, cancellation stops its wait but cannot
/// retract bytes; the driver finishes that frame without automatically resending.
/// A fresh connection always has fresh request IDs and an empty TURN cache.
pub struct MessagingSocket {
    socket: Option<upgrade::Socket>,
    state: Messaging,
    outgoing: VecDeque<Outgoing>,
    queued_bytes: usize,
    events: VecDeque<Event>,
    write_active: bool,
    control_flush: bool,
    interval: Duration,
    next_ping: Instant,
    ping: Option<RequestId>,
    options: Options,
    close_deadline: Option<Instant>,
    terminal: SocketError,
    timer: Pin<Box<Sleep>>,
}

impl MessagingSocket {
    /// Connects only to the validated WSS destination, without following redirects.
    /// Keep `request` to call Minecraft::reject_messaging on UpgradeStatus(401),
    /// then explicitly reacquire credentials and reconnect according to caller policy.
    /// Canceling this future drops any TCP/TLS/upgrade work it owns.
    ///
    /// # Errors
    /// Returns a redacted timeout, configuration, transport or numeric upgrade failure.
    pub async fn connect(
        request: &super::ConnectionRequest,
        network_id: u64,
        options: Options,
    ) -> Result<Self, SocketError> {
        options.validate(Instant::now(), request.ping_interval())?;
        let socket = upgrade::connect(request, options).await?;
        Self::from_socket(socket, network_id, request.ping_interval(), options)
    }

    /// Installs a completed, bounded upgrade without spawning a socket task.
    fn from_socket(
        socket: upgrade::Socket,
        network_id: u64,
        interval: Duration,
        options: Options,
    ) -> Result<Self, SocketError> {
        let now = Instant::now();
        options.validate(now, interval)?;
        let next_ping = now
            .checked_add(interval)
            .ok_or(SocketError::Configuration)?;
        Ok(Self {
            socket: Some(socket),
            state: Messaging::new(network_id),
            outgoing: VecDeque::new(),
            queued_bytes: 0,
            events: VecDeque::new(),
            write_active: false,
            control_flush: false,
            interval,
            next_ping,
            ping: None,
            options,
            close_deadline: None,
            terminal: SocketError::Closed,
            timer: Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                next_ping,
            ))),
        })
    }

    /// Borrows current TURN credentials without retaining an additional credential owner.
    pub fn credentials(&self) -> Option<&TurnCredentials> {
        self.state.credentials(Instant::now())
    }

    /// Admits a TURN request with an explicit response deadline.
    ///
    /// # Errors
    /// Returns core validation or local capacity/closed errors before any bytes are sent.
    pub fn request_credentials(&mut self, deadline: Instant) -> Result<RequestId, Error> {
        self.ensure_open()?;
        let outgoing = self.state.request_credentials(deadline)?;
        self.admit(outgoing)
    }

    /// Admits an opaque signal; `wait_delivery` keeps service acceptance separate from peer receipt.
    ///
    /// # Errors
    /// Returns core validation or local capacity/closed errors before any bytes are sent.
    pub fn send_signal(
        &mut self,
        recipient: Uuid,
        message: Uuid,
        signal: &str,
        wait_delivery: bool,
        deadline: Instant,
    ) -> Result<RequestId, Error> {
        self.ensure_open()?;
        let outgoing =
            self.state
                .send_signal(recipient, message, signal, wait_delivery, deadline)?;
        self.admit(outgoing)
    }

    /// Admits a receipt only after the caller's transport accepts a received signal.
    /// Capacity errors leave the signal untouched for a later local admission attempt.
    ///
    /// # Errors
    /// Returns core validation or local capacity/closed errors before any bytes are sent.
    pub fn acknowledge(
        &mut self,
        signal: &ReceivedSignal,
        message: Uuid,
        deadline: Instant,
    ) -> Result<RequestId, Error> {
        self.ensure_open()?;
        let outgoing = self.state.acknowledge(signal, message, deadline)?;
        self.admit(outgoing)
    }

    /// Cancels a pending wait and removes its frame if it has not entered the socket sink.
    /// An admitted socket write can still reach the peer; late responses are ignored.
    pub fn cancel(&mut self, request: RequestId) -> bool {
        if self.ping == Some(request) {
            return false;
        }
        self.remove_queued(request);
        self.state.cancel(request)
    }

    /// Stops admission, drops unsent messages and resolves pending waits as Closed.
    /// Continue driving to finish the bounded close handshake and drain completions.
    pub fn close(&mut self) {
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
        let events = self.state.close();
        self.accept_events(events);
    }

    /// Immediately drops socket I/O and resolves pending waits; drive to drain their outcomes.
    pub fn abort(&mut self) {
        self.finish(SocketError::Closed);
    }

    /// Pumps owned writes, reads, control frames and deadlines until an application event exists.
    /// Required callback replies are queued internally; Event::Reply is never returned.
    /// Canceling this future preserves every admitted frame and its partial write position.
    /// The caller must keep driving even when it has no application requests outstanding.
    ///
    /// # Errors
    /// Returns the terminal redacted cause after all queued events and pending completions drain.
    /// The same terminal cause is returned on subsequent calls; reconnect requires a new owner.
    pub async fn drive(&mut self) -> Result<Event, SocketError> {
        poll_fn(|cx| self.poll_drive(cx)).await
    }

    /// Rejects new requests once graceful or immediate shutdown starts.
    fn ensure_open(&self) -> Result<(), Error> {
        if self.socket.is_none() || self.close_deadline.is_some() {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    /// Leaves room for one complete callback response and every pending terminal event.
    fn admit(&mut self, outgoing: Outgoing) -> Result<RequestId, Error> {
        let request = outgoing
            .request_id()
            .ok_or(Error::Invalid("outgoing request"))?;
        let available_bytes =
            (MAX_QUEUED_BYTES - MAX_MESSAGE_BYTES).saturating_sub(self.queued_bytes);
        if self.outgoing.len() >= MAX_QUEUED_MESSAGES - 1
            || outgoing.as_bytes().len() > available_bytes
            || self.events.len() + self.state.pending_requests() > MAX_QUEUED_EVENTS
        {
            self.state.cancel(request);
            return Err(Error::Limit);
        }
        self.queue(outgoing);
        Ok(request)
    }

    /// Enqueues an already reserved frame; only this owner accounts queued bytes.
    fn queue(&mut self, outgoing: Outgoing) {
        self.queued_bytes += outgoing.as_bytes().len();
        self.outgoing.push_back(outgoing);
    }

    /// Drops unsent frames for expired or canceled request handles.
    fn remove_queued(&mut self, request: RequestId) {
        self.outgoing.retain(|outgoing| {
            if outgoing.request_id() == Some(request) {
                self.queued_bytes -= outgoing.as_bytes().len();
                false
            } else {
                true
            }
        });
    }

    /// Receives only when the complete bounded callback reply can be retained.
    fn can_receive(&self) -> bool {
        self.events.is_empty()
            && !self.control_flush
            && self.outgoing.len() < MAX_QUEUED_MESSAGES
            && self.queued_bytes <= MAX_QUEUED_BYTES - MAX_MESSAGE_BYTES
    }

    /// Keeps required responses separate from bounded caller events and internal heartbeat waits.
    fn accept_events(&mut self, events: Vec<Event>) {
        let mut ping_failure = None;
        for event in events {
            match event {
                Event::Reply(outgoing) => self.queue(outgoing),
                Event::Completed { request, result } => {
                    self.remove_queued(request);
                    if self.ping == Some(request) {
                        self.ping = None;
                        if let Err(failure) = result {
                            ping_failure = Some(failure);
                        }
                    } else {
                        self.events.push_back(Event::Completed { request, result });
                    }
                }
                event => self.events.push_back(event),
            }
        }
        if let Some(failure) = ping_failure
            && self.close_deadline.is_none()
            && self.socket.is_some()
        {
            self.finish(SocketError::Heartbeat(failure));
        }
    }

    /// Drops all I/O but preserves application events and one terminal outcome per pending handle.
    fn finish(&mut self, error: SocketError) {
        self.socket = None;
        self.terminal = error;
        self.outgoing.clear();
        self.queued_bytes = 0;
        self.close_deadline = None;
        if let Some(ping) = self.ping.take() {
            self.state.cancel(ping);
        }
        self.events.extend(self.state.close());
    }

    /// Advances caller-driven clocks without ever retrying an ambiguous write.
    fn tick(&mut self, now: Instant) {
        let events = self.state.expire(now);
        self.accept_events(events);
        if self.socket.is_none() {
            return;
        }
        if let Some(deadline) = self.close_deadline {
            if now >= deadline {
                self.finish(SocketError::TimedOut);
            }
            return;
        }
        if self.ping.is_none() && now >= self.next_ping {
            let Some(deadline) = self.next_ping.checked_add(self.options.ping_timeout) else {
                self.finish(SocketError::Configuration);
                return;
            };
            if now >= deadline {
                self.finish(SocketError::TimedOut);
                return;
            }
            if let Ok(outgoing) = self.state.ping(deadline)
                && let Ok(request) = self.admit(outgoing)
            {
                self.ping = Some(request);
                if let Some(next) = now.checked_add(self.interval) {
                    self.next_ping = next;
                } else {
                    self.finish(SocketError::Configuration);
                }
            }
        }
    }

    /// Admits at most one application frame into the library sink until it is fully flushed.
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
                Poll::Ready(Err(error)) => {
                    self.finish(SocketError::from_wire(error));
                    return;
                }
                Poll::Pending => return,
            }
        }
        if self.outgoing.is_empty() {
            return;
        }
        match Pin::new(&mut *socket).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                self.finish(SocketError::from_wire(error));
                return;
            }
            Poll::Pending => return,
        }
        let outgoing = self.outgoing.pop_front().expect("checked wire queue");
        self.queued_bytes -= outgoing.as_bytes().len();
        let message = Message::text(outgoing.as_bytes().to_vec());
        if let Err(error) = Pin::new(&mut *socket).start_send(message) {
            self.finish(SocketError::from_wire(error));
            return;
        }
        self.write_active = true;
        match Pin::new(socket).poll_flush(cx) {
            Poll::Ready(Ok(())) => self.write_active = false,
            Poll::Ready(Err(error)) => self.finish(SocketError::from_wire(error)),
            Poll::Pending => {}
        }
    }

    /// Polls a finite amount of socket work with all cancellation-sensitive ownership in fields.
    fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, SocketError>> {
        self.tick(Instant::now());
        let mut exhausted = true;
        for _ in 0..POLL_BUDGET {
            if let Some(socket) = self.socket.as_mut() {
                if self.close_deadline.is_some() {
                    match Pin::new(socket).poll_close(cx) {
                        Poll::Ready(Ok(())) => self.finish(SocketError::Closed),
                        Poll::Ready(Err(error)) => self.finish(SocketError::from_wire(error)),
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
            if self.close_deadline.is_some() || !self.can_receive() {
                exhausted = false;
                break;
            }
            let read = Pin::new(self.socket.as_mut().expect("live socket")).poll_next(cx);
            match read {
                Poll::Ready(Some(Ok(message))) if message.is_text() || message.is_binary() => {
                    match self.state.receive(message.as_payload(), Instant::now()) {
                        Ok(events) => self.accept_events(events),
                        Err(Error::Limit) => self.finish(SocketError::Capacity),
                        Err(_) => self.finish(SocketError::Protocol),
                    }
                }
                Poll::Ready(Some(Ok(message))) if message.is_ping() || message.is_pong() => {
                    // The library queues the automatic pong; flush it before reading more control frames.
                    self.control_flush = true;
                }
                Poll::Ready(Some(Ok(message))) if message.is_close() => self.close(),
                Poll::Ready(Some(Ok(_))) => self.finish(SocketError::Protocol),
                Poll::Ready(Some(Err(error))) => self.finish(SocketError::from_wire(error)),
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
        let now = Instant::now();
        let ping_deadline = if self.ping.is_some() {
            None
        } else if self.next_ping > now {
            Some(self.next_ping)
        } else {
            self.next_ping.checked_add(self.options.ping_timeout)
        };
        let deadline = self.close_deadline.or_else(|| {
            self.state
                .next_deadline()
                .into_iter()
                .chain(ping_deadline)
                .min()
        });
        if let Some(deadline) = deadline {
            self.timer
                .as_mut()
                .reset(tokio::time::Instant::from_std(deadline));
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        // A ready read/write may exhaust the per-poll budget without registering an I/O waker.
        if exhausted || (!self.write_active && !self.control_flush && !self.outgoing.is_empty()) {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests;
