//! Bounded legacy service envelopes; clocks, flush evidence and WebSocket IO belong to the caller.

use super::{
    Error, Event, Failure, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, Outgoing, RequestId,
    TurnCredentials,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, time::Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A legacy service envelope's actual network sender and opaque transport signal.
/// No messaging UUID, peer receipt or connection authority is manufactured from its routing text.
pub struct ReceivedLegacySignal {
    sender: String,
    signal: Zeroizing<String>,
}

impl ReceivedLegacySignal {
    /// Borrows the authenticated socket envelope's sender for the existing transport route check.
    pub fn sender(&self) -> &str {
        &self.sender
    }

    /// Borrows the original wire signal; the transport codec and subscription decide admission.
    pub fn signal(&self) -> &str {
        &self.signal
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Credentials,
    Ping,
    Signal {
        message: Uuid,
        wait_delivery: bool,
        flushed: bool,
        delivery: Option<Result<(), Failure>>,
    },
}

struct Pending {
    kind: Kind,
    deadline: Instant,
}

/// Legacy signaling with caller-owned time and write completion, no IO or internal output queue.
/// Server credentials are pushed. Offer delivery and local write completion remain separate evidence.
pub struct Legacy {
    pending: HashMap<RequestId, Pending>,
    next_id: u64,
    credentials: Option<TurnCredentials>,
    closed: bool,
}

impl Default for Legacy {
    fn default() -> Self {
        Self::new()
    }
}

impl Legacy {
    /// Starts a fresh correlation space and empty credential cache without reading a clock.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            next_id: 1,
            credentials: None,
            closed: false,
        }
    }

    /// Borrows only actual pushed credentials while their original receipt-anchored lifetime remains valid.
    pub fn credentials(&self, now: Instant) -> Option<&TurnCredentials> {
        self.credentials
            .as_ref()
            .filter(|credentials| credentials.valid(now))
    }

    /// Counts all retained waits, including credentials that require no outbound message.
    #[cfg(feature = "signaling-tokio")]
    pub(super) fn pending_requests(&self) -> usize {
        self.pending.len()
    }

    /// Returns the earliest original wait cutoff for the caller's timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .map(|pending| pending.deadline)
            .chain(self.credentials.as_ref().map(TurnCredentials::expires_at))
            .min()
    }

    /// Waits for pushed credentials; emits no invented service command.
    /// Call receive or expire to obtain the completion, including an already cached result.
    ///
    /// # Errors
    /// Rejects closed state or exhausted wait capacity before admitting a handle.
    pub fn request_credentials(&mut self, deadline: Instant) -> Result<RequestId, Error> {
        let id = self.available_id()?;
        self.insert(id, Kind::Credentials, deadline);
        Ok(id)
    }

    /// Produces the baseline application ping. Complete it only after its actual WebSocket flush.
    ///
    /// # Errors
    /// Rejects closed state, exhausted wait capacity or oversized wire output.
    pub fn ping(&mut self, deadline: Instant) -> Result<Outgoing, Error> {
        let id = self.available_id()?;
        let outgoing = Outgoing::encode(&json!({"Type":0,"MessageId":Uuid::nil()}), Some(id))?;
        self.insert(id, Kind::Ping, deadline);
        Ok(outgoing)
    }

    /// Admits one signal UUID once, retaining the original deadline and optional service delivery wait.
    /// Capacity/encoding errors mutate no correlation state and produce no wire write.
    ///
    /// # Errors
    /// Rejects empty routes/signals, nil/reused IDs, closed state and exceeded bounds.
    pub fn send_signal(
        &mut self,
        recipient: &str,
        message: Uuid,
        signal: &str,
        wait_delivery: bool,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        if recipient.is_empty()
            || signal.is_empty()
            || message.is_nil()
            || self.pending.values().any(|pending| {
                matches!(pending.kind,
                Kind::Signal { message: current, .. } if current == message)
            })
        {
            return Err(Error::Invalid("legacy recipient or message identity"));
        }
        let id = self.available_id()?;
        let outgoing = Outgoing::encode(
            &json!({"Type":1,"To":recipient,"Message":signal,"MessageId":message}),
            Some(id),
        )?;
        self.insert(
            id,
            Kind::Signal {
                message,
                wait_delivery,
                flushed: false,
                delivery: None,
            },
            deadline,
        );
        Ok(outgoing)
    }

    /// Supplies actual successful sink-flush evidence; admission or a canceled wait is insufficient.
    /// Offer waits require both the original flush and correlated outcome, in either arrival order.
    pub fn flushed(&mut self, request: RequestId, now: Instant) -> Vec<Event> {
        let mut events = self.expire(now);
        let result = self
            .pending
            .get_mut(&request)
            .and_then(|pending| match &mut pending.kind {
                Kind::Ping
                | Kind::Signal {
                    wait_delivery: false,
                    ..
                } => Some(Ok(())),
                Kind::Signal {
                    flushed, delivery, ..
                } => {
                    *flushed = true;
                    delivery.take()
                }
                Kind::Credentials => None,
            });
        if let Some(result) = result {
            events.push(self.complete(request, result));
        }
        events
    }

    /// Cancels correlation only; already written bytes cannot be retracted or retried automatically.
    pub fn cancel(&mut self, request: RequestId) -> bool {
        self.pending.remove(&request).is_some()
    }

    /// Expires original cutoffs before completing waits from valid actual cached credentials.
    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        if self
            .credentials
            .as_ref()
            .is_some_and(|credentials| !credentials.valid(now))
        {
            self.credentials = None;
        }
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| now >= pending.deadline)
            .map(|(id, _)| *id)
            .collect();
        let mut events: Vec<_> = expired
            .into_iter()
            .map(|id| self.complete(id, Err(Failure::TimedOut)))
            .collect();
        if self.credentials(now).is_some() {
            self.complete_credentials(&mut events);
        }
        events
    }

    /// Ends admission and every original wait without replacing accepted service outcomes.
    pub fn close(&mut self) -> Vec<Event> {
        self.closed = true;
        self.credentials = None;
        self.pending
            .drain()
            .map(|(request, _)| Event::Completed {
                request,
                result: Err(Failure::Closed),
            })
            .collect()
    }

    /// Applies one bounded envelope received on this owner's original authenticated socket.
    /// Invalid framing rejects; well-formed unknown, malformed inner or unrelated control data is ignored.
    ///
    /// # Errors
    /// Rejects closed state, oversized input and malformed outer JSON/envelope fields.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<Vec<Event>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| Error::Invalid("legacy JSON"))?;
        if !value.is_object() && !value.is_null() {
            return Err(Error::Invalid("legacy envelope"));
        }
        let envelope: Envelope = serde_json::from_value::<Option<Envelope>>(value)
            .map_err(|_| Error::Invalid("legacy envelope"))?
            .unwrap_or_default();
        let mut events = self.expire(now);
        match envelope.kind {
            1 if !envelope.from.is_empty() && !envelope.message.is_empty() => {
                events.push(Event::LegacySignal(ReceivedLegacySignal {
                    sender: envelope.from,
                    signal: Zeroizing::new(envelope.message),
                }));
            }
            2 if envelope.from == "Server" => {
                let credentials = serde_json::from_str::<Value>(&envelope.message)
                    .ok()
                    .filter(Value::is_object)
                    .and_then(|value| TurnCredentials::from_value(value, now).ok());
                if let Some(credentials) = credentials {
                    self.credentials = Some(credentials);
                    self.complete_credentials(&mut events);
                } else {
                    events.push(Event::Ignored);
                }
            }
            0 | 4 => {
                let Some(id) = self.find_message(envelope.id) else {
                    events.push(Event::Ignored);
                    return Ok(events);
                };
                let result = if envelope.kind == 4 {
                    validate_status(&envelope.message)
                } else {
                    object_or_null(&envelope.message)
                        .and_then(|value| serde_json::from_value::<Option<RemoteError>>(value).ok())
                        .map(|error| Err(Failure::DeliveryCode(error.unwrap_or_default().code)))
                };
                if let Some(result) = result {
                    if let Some(Pending {
                        kind:
                            Kind::Signal {
                                flushed, delivery, ..
                            },
                        ..
                    }) = self.pending.get_mut(&id)
                    {
                        if delivery.is_some() {
                            events.push(Event::Ignored);
                        } else if *flushed {
                            events.push(self.complete(id, result));
                        } else {
                            *delivery = Some(result);
                        }
                    }
                } else {
                    events.push(Event::Ignored);
                }
            }
            _ => events.push(Event::Ignored),
        }
        Ok(events)
    }

    /// Reserves capacity and a fresh local handle only after validating the bounded owner state.
    fn available_id(&self) -> Result<RequestId, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.pending.len() >= MAX_PENDING_REQUESTS || self.next_id == u64::MAX {
            return Err(Error::Limit);
        }
        Ok(RequestId(self.next_id))
    }

    /// Commits only an already encoded frame or a local credential wait.
    fn insert(&mut self, id: RequestId, kind: Kind, deadline: Instant) {
        self.next_id += 1;
        self.pending.insert(id, Pending { kind, deadline });
    }

    /// Completes pushed-credential waits without altering signal or heartbeat correlation.
    fn complete_credentials(&mut self, events: &mut Vec<Event>) {
        let requests: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| matches!(pending.kind, Kind::Credentials))
            .map(|(id, _)| *id)
            .collect();
        events.extend(requests.into_iter().map(|id| self.complete(id, Ok(()))));
    }

    /// Finds only a live delivery wait; local writes, nil and canceled/late IDs have no effect.
    fn find_message(&self, message: Uuid) -> Option<RequestId> {
        if message.is_nil() {
            return None;
        }
        self.pending
            .iter()
            .find(|(_, pending)| {
                matches!(pending.kind,
            Kind::Signal { message: current, wait_delivery: true, .. } if current == message)
            })
            .map(|(id, _)| *id)
    }

    /// Removes correlation before exposing its sole terminal result.
    fn complete(&mut self, request: RequestId, result: Result<(), Failure>) -> Event {
        self.pending.remove(&request);
        Event::Completed { request, result }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Envelope {
    #[serde(rename = "Type", alias = "type", deserialize_with = "null_default")]
    kind: i64,
    #[serde(rename = "From", alias = "from", deserialize_with = "null_default")]
    from: String,
    #[serde(rename = "To", alias = "to", deserialize_with = "null_default")]
    _to: String,
    #[serde(
        rename = "Message",
        alias = "message",
        deserialize_with = "null_default"
    )]
    message: String,
    #[serde(
        rename = "MessageId",
        alias = "messageId",
        deserialize_with = "null_default"
    )]
    id: Uuid,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RemoteError {
    #[serde(rename = "Code", alias = "code", deserialize_with = "null_default")]
    code: i64,
    #[serde(
        rename = "Message",
        alias = "message",
        deserialize_with = "null_default"
    )]
    _message: String,
}

/// Keeps optional null fields compatible with the original scalar/UUID zero values.
fn null_default<'de, D: serde::Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Validates the baseline delivery metadata while keeping telemetry and remote text out of outputs.
fn validate_status(raw: &str) -> Option<Result<(), Failure>> {
    #[derive(Deserialize)]
    struct Status {
        #[serde(default, rename = "MessageId")]
        _message: Option<Uuid>,
        #[serde(default, rename = "ToPlayerId")]
        _sender: Option<String>,
        #[serde(default, rename = "DeliveredOn")]
        delivered: Option<String>,
        #[serde(default, rename = "AcceptedOn")]
        accepted: Option<String>,
    }
    let status: Option<Status> = serde_json::from_value(object_or_null(raw)?).ok()?;
    if let Some(status) = status {
        for stamp in [status.delivered, status.accepted].into_iter().flatten() {
            time::OffsetDateTime::parse(&stamp, &time::format_description::well_known::Rfc3339)
                .ok()?;
        }
    }
    Some(Ok(()))
}

/// Preserves null metadata while preventing positional array decoding of inner Go record objects.
fn object_or_null(raw: &str) -> Option<Value> {
    serde_json::from_str::<Value>(raw)
        .ok()
        .filter(|value| value.is_object() || value.is_null())
}

#[cfg(test)]
mod tests;
