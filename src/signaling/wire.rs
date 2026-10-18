use super::{Error, MAX_BATCH_MESSAGES, MAX_CALLBACK_ID_BYTES, MAX_MESSAGE_BYTES};
use serde_json::Value;
use zeroize::Zeroizing;

pub(super) const PING: &str = "System_Ping_v1_0";
pub(super) const PONG: &str = "System_Pong_v1_0";
pub(super) const TURN: &str = "Signaling_TurnAuth_v1_0";
pub(super) const RECEIVE: &str = "Signaling_ReceiveMessage_v1_0";
pub(super) const RECEIVE_ERROR: &str = "Signaling_ReceiveError_v1_0";
pub(super) const SEND: &str = "Signaling_SendClientMessage_v1_0";
pub(super) const RECEIPT: &str = "Signaling_DeliveryNotification_V1_0";
pub(super) const WEBRTC: &str = "Signaling_WebRtc_v1_0";

// A complete batch of worst-case escaped callback identifiers always fits one response frame.
const _: () = assert!(MAX_BATCH_MESSAGES * (MAX_CALLBACK_ID_BYTES * 6 + 64) <= MAX_MESSAGE_BYTES);

/// Identifies one request within a single messaging state owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId(pub(super) u64);

/// A correlated failure that never retains server diagnostics or payload text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// The JSON-RPC service rejected the request with this numeric code.
    ServiceCode(i64),
    /// The service or peer reported delivery failure with this numeric code.
    DeliveryCode(i64),
    /// A successful response had invalid metadata for the requested operation.
    InvalidResponse,
    /// The caller-supplied deadline expired.
    TimedOut,
    /// The state owner was explicitly closed.
    Closed,
}

/// A complete text message for the caller's WebSocket. No internal send queue exists.
/// Bytes can include SDP identities or TURN credentials and must never be logged.
pub struct Outgoing {
    pub(super) request: Option<RequestId>,
    bytes: Zeroizing<Vec<u8>>,
}

impl Outgoing {
    /// Returns the request handle, or None for a response to a server callback.
    pub fn request_id(&self) -> Option<RequestId> {
        self.request
    }

    /// Explicitly borrows the message bytes for one complete WebSocket text write.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Serializes a complete bounded frame before state admission or publication.
    pub(super) fn encode(value: &Value, request: Option<RequestId>) -> Result<Self, Error> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Invalid("outgoing JSON"))?);
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        Ok(Self { request, bytes })
    }
}
