use super::{
    Error, Failure, MAX_BATCH_MESSAGES, MAX_CALLBACK_ID_BYTES, MAX_MESSAGE_BYTES,
    MAX_PENDING_REQUESTS, Outgoing, RequestId, TurnCredentials, wire,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{collections::HashMap, time::Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// An incoming opaque NetherNet message. The transport codec decides whether to accept it.
/// This has no Debug or serialization implementation because SDP may contain an identity token.
pub struct ReceivedSignal {
    sender: Uuid,
    message_id: Uuid,
    network_id: String,
    signal: Zeroizing<String>,
}

impl ReceivedSignal {
    /// Returns the sender's messaging UUID, used as the routing identity on this service.
    pub fn sender(&self) -> Uuid {
        self.sender
    }
    /// Returns the sender's separately advertised NetherNet network identifier.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }
    /// Borrows the opaque signal for the existing NetherNet codec and admission policy.
    pub fn signal(&self) -> &str {
        &self.signal
    }
}

/// Bounded outputs from one received WebSocket message or an explicit lifecycle operation.
#[non_exhaustive]
pub enum Event {
    /// A request finished; successful TURN requests install credentials on the state owner.
    Completed {
        /// The handle returned when the request was admitted.
        request: RequestId,
        /// Only numeric service failures or redacted local causes are retained.
        result: Result<(), Failure>,
    },
    /// The caller must explicitly acknowledge this after its transport accepts the signal.
    Signal(ReceivedSignal),
    /// A required response to a server callback; send it even when its events are ignored.
    Reply(Outgoing),
    /// A well-formed unsupported or uncorrelated message was skipped; no raw text is retained.
    Ignored,
}

#[derive(Clone, Copy)]
enum Kind {
    Ping,
    Turn,
    Send {
        message: Uuid,
        recipient: Uuid,
        wait_delivery: bool,
        delivered: bool,
    },
}

struct Pending {
    kind: Kind,
    deadline: Instant,
    accepted: bool,
}

/// A single connection's request correlation, delivery waits and TURN cache.
///
/// Feed complete WebSocket text messages into `receive` and send returned replies.
/// Register a request before writing its bytes. A canceled write has an ambiguous
/// outcome: cancel its handle, or close this owner and the socket; never resend it
/// automatically. Handles are scoped to this owner and never reused within it.
/// The caller owns ping scheduling and reconnects. Dropping this state drops secrets.
pub struct Messaging {
    network_id: String,
    next_id: u64,
    pending: HashMap<RequestId, Pending>,
    credentials: Option<(RequestId, TurnCredentials)>,
    closed: bool,
}

impl Messaging {
    /// Creates fresh state using the same local network ID advertised to peers.
    pub fn new(network_id: u64) -> Self {
        Self {
            network_id: network_id.to_string(),
            next_id: 1,
            pending: HashMap::new(),
            credentials: None,
            closed: false,
        }
    }

    /// Borrows unexpired TURN credentials; a new connection starts with no cached result.
    pub fn credentials(&self, now: Instant) -> Option<&TurnCredentials> {
        self.credentials
            .as_ref()
            .map(|(_, credentials)| credentials)
            .filter(|credentials| credentials.valid(now))
    }

    /// Transfers the current unexpired credential owner without cloning or extending its lifetime.
    /// This clears the cache; taking a cached result alone proves no fresh service response.
    pub fn take_credentials(&mut self, now: Instant) -> Option<TurnCredentials> {
        self.credentials
            .take()
            .map(|(_, credentials)| credentials)
            .filter(|credentials| credentials.valid(now))
    }

    /// Returns the pending count for terminal-event reservation in the optional socket owner.
    #[cfg(feature = "signaling-tokio")]
    pub(super) fn pending_requests(&self) -> usize {
        self.pending.len()
    }

    /// Returns the earliest request deadline or cached credential expiry for the caller's timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .map(|pending| pending.deadline)
            .chain(
                self.credentials
                    .as_ref()
                    .map(|(_, credentials)| credentials.expires),
            )
            .min()
    }

    /// Starts one application ping with the caller's monotonic response deadline.
    pub fn ping(&mut self, deadline: Instant) -> Result<Outgoing, Error> {
        self.request(wire::PING, json!({}), Kind::Ping, deadline)
    }

    /// Requests TURN credentials unless a previous credential request is still outstanding.
    /// Check `credentials(now)` first to reuse the current response without an extra request.
    pub fn request_credentials(&mut self, deadline: Instant) -> Result<Outgoing, Error> {
        if self
            .pending
            .values()
            .any(|pending| matches!(pending.kind, Kind::Turn))
        {
            return Err(Error::Invalid("TURN request already pending"));
        }
        self.request(wire::TURN, json!({}), Kind::Turn, deadline)
    }

    /// Sends one opaque signal to a player messaging UUID, with an explicit delivery policy.
    /// Supply a fresh non-nil message ID. Only offers normally need a peer receipt.
    pub fn send_signal(
        &mut self,
        recipient: Uuid,
        message: Uuid,
        signal: &str,
        wait_delivery: bool,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        if signal.is_empty() || signal.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Invalid("signal size"));
        }
        self.send_inner(
            recipient,
            message,
            json!({"jsonrpc":"2.0", "method":wire::WEBRTC,
            "params":{"netherNetId":self.network_id,"message":signal}}),
            wait_delivery,
            deadline,
        )
    }

    /// Acknowledges only a message whose opaque signal the caller accepted.
    /// Retry local capacity failures before writing; never repeat an ambiguous socket write.
    pub fn acknowledge(
        &mut self,
        received: &ReceivedSignal,
        message: Uuid,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        self.send_inner(
            received.sender,
            message,
            json!({"jsonrpc":"2.0", "method":wire::RECEIPT,
                "params":{"messageId":received.message_id}}),
            false,
            deadline,
        )
    }

    /// Removes a canceled request, making any late service response or peer receipt harmless.
    pub fn cancel(&mut self, request: RequestId) -> bool {
        self.pending.remove(&request).is_some()
    }

    /// Retires only this owner's matching TURN wait or cached result, without affecting other requests.
    /// Returns false for an unknown, already moved/retired or non-TURN request.
    /// This is local retirement; an already written request can still receive a harmless late response.
    pub fn retire_credentials(&mut self, request: RequestId) -> bool {
        let pending = self
            .pending
            .get(&request)
            .is_some_and(|pending| matches!(pending.kind, Kind::Turn));
        let cached = self
            .credentials
            .as_ref()
            .is_some_and(|(owner, _)| *owner == request);
        if pending {
            self.cancel(request);
        }
        if cached {
            self.credentials = None;
        }
        pending || cached
    }

    /// Finishes all expired requests using caller time, without sleeping or sending retries.
    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        if self
            .credentials
            .as_ref()
            .is_some_and(|(_, credentials)| !credentials.valid(now))
        {
            self.credentials = None;
        }
        let ids: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .map(|id| self.complete(id, Err(Failure::TimedOut)))
            .collect()
    }

    /// Permanently closes this owner and resolves every pending request before dropping secrets.
    pub fn close(&mut self) -> Vec<Event> {
        self.closed = true;
        self.credentials = None;
        let ids: Vec<_> = self.pending.keys().copied().collect();
        ids.into_iter()
            .map(|id| self.complete(id, Err(Failure::Closed)))
            .collect()
    }

    /// Accepts one bounded text message, including bounded JSON-RPC batches and envelope arrays.
    /// Malformed framing is rejected with fixed errors. Unknown well-formed methods are ignored
    /// and server callbacks are answered with null, without retaining their diagnostics.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<Vec<Event>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| Error::Invalid("incoming JSON"))?;
        let batched = value.is_array();
        let frames = match value {
            Value::Array(values) if !values.is_empty() && values.len() <= MAX_BATCH_MESSAGES => {
                values
            }
            Value::Array(_) => return Err(Error::Limit),
            value => vec![value],
        };
        // Check the complete batch before consuming any correlation or producing events.
        for frame in &frames {
            validate_frame(frame)?;
        }
        let mut events = self.expire(now);
        let mut replies = Vec::new();
        for frame in frames {
            self.frame(frame, now, &mut events, &mut replies)?;
        }
        if !replies.is_empty() {
            let reply = if batched {
                Value::Array(replies)
            } else {
                replies.remove(0)
            };
            events.push(Event::Reply(Outgoing::encode(&reply, None)?));
        }
        Ok(events)
    }

    /// Materializes an inner peer message before admitting its outer request.
    fn send_inner(
        &mut self,
        recipient: Uuid,
        message: Uuid,
        inner: Value,
        wait_delivery: bool,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        if recipient.is_nil()
            || message.is_nil()
            || self.pending.values().any(|pending| {
                matches!(pending.kind, Kind::Send {message: current, ..} if current == message)
            })
        {
            return Err(Error::Invalid("recipient or message identity"));
        }
        let inner = serde_json::to_string(&inner).map_err(|_| Error::Invalid("inner JSON"))?;
        self.request(
            wire::SEND,
            json!({"toPlayerId":recipient,"messageId":message,"message":inner}),
            Kind::Send {
                message,
                recipient,
                wait_delivery,
                delivered: false,
            },
            deadline,
        )
    }

    /// Checks all admission bounds before publishing bytes or adding correlation state.
    fn request(
        &mut self,
        method: &str,
        params: Value,
        kind: Kind,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.pending.len() >= MAX_PENDING_REQUESTS
            || self.next_id >= (1_u64 << f64::MANTISSA_DIGITS)
        {
            return Err(Error::Limit);
        }
        let id = RequestId(self.next_id);
        let outgoing = Outgoing::encode(
            &json!({"jsonrpc":"2.0","id":id.0,
            "method":method,"params":params}),
            Some(id),
        )?;
        self.next_id += 1;
        self.pending.insert(
            id,
            Pending {
                kind,
                deadline,
                accepted: false,
            },
        );
        Ok(outgoing)
    }

    /// Removes correlation before publishing a completion, including failure and close paths.
    fn complete(&mut self, request: RequestId, result: Result<(), Failure>) -> Event {
        self.pending.remove(&request);
        Event::Completed { request, result }
    }

    /// Dispatches one JSON-RPC request or response without echoing any remote field.
    fn frame(
        &mut self,
        frame: Value,
        now: Instant,
        events: &mut Vec<Event>,
        replies: &mut Vec<Value>,
    ) -> Result<(), Error> {
        let Value::Object(mut frame) = frame else {
            return Err(Error::Invalid("JSON-RPC object"));
        };
        if frame.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(Error::Invalid("JSON-RPC version"));
        }
        if let Some(method) = frame.remove("method") {
            let method = method.as_str().ok_or(Error::Invalid("JSON-RPC method"))?;
            if frame.contains_key("result") || frame.contains_key("error") {
                return Err(Error::Invalid("JSON-RPC request framing"));
            }
            // Validate and build the response before any callback changes state.
            let reply = match frame.remove("id") {
                Some(id) => {
                    if !(id.is_null() || id.is_number() || id.is_string()) {
                        return Err(Error::Invalid("callback ID"));
                    }
                    Some(json!({"jsonrpc":"2.0","id":id,"result":null}))
                }
                _ => None,
            };
            let params = frame.remove("params").unwrap_or(Value::Null);
            // Callback-specific bad data is skipped, preserving the required reply and other callbacks.
            if self.callback(method, params, events).is_err() {
                events.push(Event::Ignored);
            }
            if let Some(reply) = reply {
                replies.push(reply);
            }
            return Ok(());
        }
        self.response(frame, now, events)
    }

    /// Correlates service acceptance separately from peer delivery; neither can spoof the other.
    fn response(
        &mut self,
        mut frame: Map<String, Value>,
        now: Instant,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if frame.contains_key("result") == frame.contains_key("error") {
            return Err(Error::Invalid("JSON-RPC response framing"));
        }
        let Some(id) = frame.get("id").and_then(Value::as_u64).map(RequestId) else {
            events.push(Event::Ignored);
            return Ok(());
        };
        let Some(pending) = self.pending.get_mut(&id) else {
            events.push(Event::Ignored);
            return Ok(());
        };
        if pending.accepted {
            events.push(Event::Ignored);
            return Ok(());
        }
        if let Some(error) = frame.remove("error") {
            let failure = error
                .get("code")
                .and_then(Value::as_i64)
                .map_or(Failure::InvalidResponse, Failure::ServiceCode);
            events.push(self.complete(id, Err(failure)));
            return Ok(());
        }
        match pending.kind {
            Kind::Turn => {
                match TurnCredentials::from_value(
                    frame.remove("result").unwrap_or(Value::Null),
                    now,
                ) {
                    Ok(credentials) => {
                        self.credentials = Some((id, credentials));
                        events.push(self.complete(id, Ok(())));
                    }
                    Err(_) => events.push(self.complete(id, Err(Failure::InvalidResponse))),
                }
            }
            Kind::Send {
                wait_delivery: true,
                delivered: false,
                ..
            } => pending.accepted = true,
            _ => events.push(self.complete(id, Ok(()))),
        }
        Ok(())
    }

    /// Handles known service callbacks while tolerating well-formed additions.
    fn callback(
        &mut self,
        method: &str,
        params: Value,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        match method {
            wire::PONG => {}
            wire::RECEIVE => {
                let envelopes = match params {
                    Value::Array(values) if values.len() <= MAX_BATCH_MESSAGES => values,
                    Value::Array(_) => return Err(Error::Limit),
                    value => vec![value],
                };
                for envelope in envelopes {
                    if self.envelope(envelope, events).is_err() {
                        events.push(Event::Ignored);
                    }
                }
            }
            wire::RECEIVE_ERROR => {
                let message = params
                    .get("messageId")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok());
                let code = params.get("code").and_then(Value::as_i64);
                if let (Some(message), Some(code)) = (message, code) {
                    self.delivery(message, None, Some(code), events);
                } else {
                    events.push(Event::Ignored);
                }
            }
            _ => events.push(Event::Ignored),
        }
        Ok(())
    }

    /// Decodes one peer envelope, keeping its actual sender independent of claimed network IDs.
    fn envelope(&mut self, value: Value, events: &mut Vec<Event>) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(rename = "From", alias = "from")]
            from: Uuid,
            #[serde(rename = "Id", alias = "id")]
            id: Uuid,
            #[serde(rename = "Message", alias = "message")]
            message: String,
        }
        let envelope: Envelope =
            serde_json::from_value(value).map_err(|_| Error::Invalid("peer envelope"))?;
        if envelope.from.is_nil() || envelope.id.is_nil() {
            return Err(Error::Invalid("peer identity"));
        }
        let message = Zeroizing::new(envelope.message);
        let mut inner: Value =
            serde_json::from_str(&message).map_err(|_| Error::Invalid("peer JSON"))?;
        if inner.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            // A plain delivery-error envelope does not contain an inner JSON-RPC request.
            if let Some(code) = inner.get("Code").and_then(Value::as_i64) {
                self.delivery(envelope.id, Some(envelope.from), Some(code), events);
                return Ok(());
            }
            return Err(Error::Invalid("peer JSON-RPC version"));
        }
        let params = inner
            .as_object_mut()
            .and_then(|inner| inner.remove("params"))
            .ok_or(Error::Invalid("peer parameters"))?;
        match inner.get("method").and_then(Value::as_str) {
            Some(wire::WEBRTC) => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Signal {
                    nether_net_id: String,
                    message: String,
                }
                let signal: Signal =
                    serde_json::from_value(params).map_err(|_| Error::Invalid("peer signal"))?;
                if signal.message.is_empty() {
                    return Err(Error::Invalid("peer signal size"));
                }
                events.push(Event::Signal(ReceivedSignal {
                    sender: envelope.from,
                    message_id: envelope.id,
                    network_id: signal.nether_net_id,
                    signal: Zeroizing::new(signal.message),
                }));
            }
            Some(wire::RECEIPT) => {
                let message = params
                    .get("messageId")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or(Error::Invalid("delivery identity"))?;
                self.delivery(message, Some(envelope.from), None, events);
            }
            _ => events.push(Event::Ignored),
        }
        Ok(())
    }

    /// Completes a delivery only for its pending message and expected recipient.
    fn delivery(
        &mut self,
        message: Uuid,
        sender: Option<Uuid>,
        code: Option<i64>,
        events: &mut Vec<Event>,
    ) {
        let found = self.pending.iter_mut().find(|(_, pending)| {
            matches!(pending.kind, Kind::Send { message: current, recipient, .. }
                if current == message && sender.is_none_or(|sender| sender == recipient))
        });
        let Some((id, pending)) = found else {
            events.push(Event::Ignored);
            return;
        };
        let id = *id;
        if let Some(code) = code {
            events.push(self.complete(id, Err(Failure::DeliveryCode(code))));
        } else if let Kind::Send {
            delivered,
            wait_delivery,
            ..
        } = &mut pending.kind
        {
            *delivered = true;
            if *wait_delivery && pending.accepted {
                events.push(self.complete(id, Ok(())));
            }
        }
    }
}

/// Rejects malformed batch framing before any earlier response can consume a pending request.
fn validate_frame(frame: &Value) -> Result<(), Error> {
    let frame = frame.as_object().ok_or(Error::Invalid("JSON-RPC object"))?;
    if frame.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(Error::Invalid("JSON-RPC version"));
    }
    if let Some(method) = frame.get("method") {
        if !method.is_string() || frame.contains_key("result") || frame.contains_key("error") {
            return Err(Error::Invalid("JSON-RPC request framing"));
        }
    } else if frame.contains_key("result") == frame.contains_key("error")
        || !frame.contains_key("id")
    {
        return Err(Error::Invalid("JSON-RPC response framing"));
    }
    if frame
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| id.len() > MAX_CALLBACK_ID_BYTES)
    {
        return Err(Error::Limit);
    }
    if frame
        .get("id")
        .is_some_and(|id| !(id.is_null() || id.is_string() || id.is_number()))
    {
        return Err(Error::Invalid("JSON-RPC ID"));
    }
    Ok(())
}
