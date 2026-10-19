use super::{Error, MAX_MESSAGE_BYTES, MAX_RESOURCE_BYTES, MAX_SESSION_CHANGES, SESSION_RESOURCE};
use crate::xbox::mpsd;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) const SUBSCRIBE: u32 = 1;
pub(super) const UNSUBSCRIBE: u32 = 2;
const CHANGE: u32 = 3;
pub(super) const RESYNC: u32 = 4;

/// Caller-owned account generation. Retire it on sign-out or account replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation(u64);

impl Generation {
    /// Rejects zero, reserving it for callers' uninitialized account state.
    pub fn new(value: u64) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::Invalid("account generation"));
        }
        Ok(Self(value))
    }
}

/// Opaque socket identity, checked before processing messages from a transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub(super) Uuid);

/// Stable local subscription identity, retained through same-account reconnects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SubscriptionId {
    pub(super) owner: Epoch,
    pub(super) sequence: u64,
}

/// One correlated request on one specific socket; never reused after cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId {
    pub(super) epoch: Epoch,
    pub(super) sequence: u32,
}

/// A validated opaque resource URI. It has no Debug/Display or implicit serialization.
pub struct Resource(pub(super) String);

impl Resource {
    /// Accepts a bounded HTTPS Xbox service resource without credentials, query or fragment.
    pub fn new(value: String) -> Result<Self, Error> {
        if value.len() > MAX_RESOURCE_BYTES {
            return Err(Error::Limit);
        }
        let url = url::Url::parse(&value).map_err(|_| Error::Invalid("resource URI"))?;
        if url.scheme() != "https"
            || !url
                .host_str()
                .is_some_and(|host| host.ends_with(".xboxlive.com"))
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || value.chars().any(char::is_control)
        {
            return Err(Error::Invalid("resource URI policy"));
        }
        Ok(Self(url.into()))
    }

    /// Subscribes to MPSD connection allocation and session shoulder taps.
    pub fn session_directory() -> Self {
        Self(SESSION_RESOURCE.into())
    }

    /// Explicitly exposes the subscription URI; it can contain private account/session material.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Identifies the concrete MPSD payload contract without a separate mapping table.
    pub(super) fn is_directory(&self) -> bool {
        self.0 == SESSION_RESOURCE
    }
}

/// One complete outgoing text frame; no Debug/Display because resource URIs are private.
pub struct Outgoing {
    pub(super) request: RequestId,
    pub(super) text: Zeroizing<String>,
}

impl Outgoing {
    /// Returns the request handle for explicit cancellation.
    pub fn request_id(&self) -> RequestId {
        self.request
    }
    /// Returns the socket that alone may transmit this frame.
    pub fn epoch(&self) -> Epoch {
        self.request.epoch
    }
    /// Explicitly exposes the complete text message for the caller's WebSocket sink.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// A correlated failure containing only local causes or the service's numeric status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// Subscribe/unsubscribe was explicitly rejected; no server diagnostic is retained.
    Status(i32),
    /// The caller canceled this request and must close the socket.
    Cancelled,
    /// Its caller-supplied monotonic deadline elapsed; the socket must close.
    TimedOut,
    /// Another operation or transport failure retired the socket.
    Disconnected,
}

/// Ordered application results. Payloads intentionally have no Debug implementation.
#[non_exhaustive]
pub enum Event {
    /// Install this initial snapshot before applying subsequent changes for the subscription.
    Subscribed {
        /// Completed subscribe request on this socket.
        request: RequestId,
        /// Stable local resource handle.
        subscription: SubscriptionId,
        /// Service initial state; it may contain private identity or session data.
        initial: Value,
    },
    /// Opaque non-MPSD resource change, delivered only after its successful initial snapshot.
    Changed {
        /// Resource whose initial snapshot was already delivered.
        subscription: SubscriptionId,
        /// Opaque service change; interpretation belongs to the concrete API caller.
        data: Value,
    },
    /// MPSD notifications; refresh matching directory sessions explicitly, rather than merging taps.
    SessionsChanged {
        /// Active MPSD connection resource.
        subscription: SubscriptionId,
        /// Validated references and branch/revision hints, in wire order.
        changes: Vec<SessionChange>,
    },
    /// The remote subscription was explicitly removed.
    Unsubscribed {
        /// Completed removal request.
        request: RequestId,
        /// Removed local resource handle.
        subscription: SubscriptionId,
    },
    /// One pending operation ended once with a redacted cause.
    Failed {
        /// Completed request, never completed again.
        request: RequestId,
        /// Resource affected by this failure.
        subscription: SubscriptionId,
        /// Redacted service status or local cancellation/transport cause.
        cause: Failure,
    },
    /// All currently active snapshots need explicit reconciliation; no service reads are performed.
    Resync {
        /// Active resources whose current snapshots must be refreshed explicitly.
        subscriptions: Vec<SubscriptionId>,
    },
    /// Close the socket and discard all its queued frames before explicit reconnect/resubscribe.
    Disconnected,
}

/// A directory shoulder tap retaining its existing validated MPSD reference and revision hints.
pub struct SessionChange {
    /// Session to refresh through the borrowed MPSD directory.
    pub reference: mpsd::Reference,
    /// Service branch; change numbers from different branches must not be compared.
    pub branch: Uuid,
    /// Revision hint on this branch; the HTTP snapshot remains authoritative.
    pub change_number: u64,
}

impl SessionChange {
    /// Uses the directory owner's case-insensitive template/session matching policy.
    pub fn is_for(&self, reference: &mpsd::Reference) -> bool {
        self.reference.same(reference)
    }
}

/// Decodes all taps transactionally before delivering any notification.
pub(super) fn session_changes(data: &Value) -> Result<Vec<SessionChange>, Error> {
    let taps = data
        .get("shoulderTaps")
        .and_then(Value::as_array)
        .ok_or(Error::Invalid("session changes"))?;
    if taps.len() > MAX_SESSION_CHANGES {
        return Err(Error::Limit);
    }
    taps.iter()
        .map(|tap| {
            let resource = tap
                .get("resource")
                .and_then(Value::as_str)
                .ok_or(Error::Invalid("session change reference"))?;
            let mut parts = resource.split('~');
            let scid = parts
                .next()
                .and_then(|part| Uuid::parse_str(part).ok())
                .ok_or(Error::Invalid("session change SCID"))?;
            let template = parts
                .next()
                .ok_or(Error::Invalid("session change template"))?;
            let name = parts.next().ok_or(Error::Invalid("session change name"))?;
            if parts.next().is_some() {
                return Err(Error::Invalid("session change reference"));
            }
            let reference = mpsd::Reference::new(scid, template.into(), name.into())
                .map_err(|_| Error::Invalid("session change reference"))?;
            let branch = tap
                .get("branch")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .filter(|id| !id.is_nil())
                .ok_or(Error::Invalid("session change branch"))?;
            let change_number = tap
                .get("changeNumber")
                .and_then(Value::as_u64)
                .ok_or(Error::Invalid("session change number"))?;
            Ok(SessionChange {
                reference,
                branch,
                change_number,
            })
        })
        .collect()
}

pub(super) enum Message {
    Response {
        operation: u32,
        sequence: u32,
        status: i32,
        body: Vec<Value>,
    },
    Change {
        server: u32,
        data: Value,
    },
    Resync,
}

/// Parses bounded complete array messages without retaining service diagnostics in errors.
pub(super) fn decode(bytes: &[u8]) -> Result<Message, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let mut fields: Vec<Value> =
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid("message JSON"))?;
    if fields.is_empty() || fields.len() > 8 {
        return Err(Error::Invalid("message fields"));
    }
    let operation = number(&fields[0])?;
    match operation {
        SUBSCRIBE | UNSUBSCRIBE if fields.len() >= 3 => {
            let sequence = number(&fields[1])?;
            let status = fields[2]
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or(Error::Invalid("response status"))?;
            Ok(Message::Response {
                operation,
                sequence,
                status,
                body: fields.drain(3..).collect(),
            })
        }
        CHANGE if fields.len() == 3 => Ok(Message::Change {
            server: number(&fields[1])?,
            data: fields.swap_remove(2),
        }),
        RESYNC if fields.len() == 1 => Ok(Message::Resync),
        _ => Err(Error::Invalid("message type or fields")),
    }
}

/// Rejects negative, fractional or overflowing wire identifiers.
pub(super) fn number(value: &Value) -> Result<u32, Error> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(Error::Invalid("wire identifier"))
}
