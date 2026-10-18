//! Authenticated Player Messaging acquisition and bounded, caller-driven JSON-RPC.
//!
//! [`crate::minecraft::Minecraft::messaging_connection`] prepares a protected
//! WebSocket upgrade. [`Messaging`] operates on complete text messages without
//! sockets, tasks, clocks or internal output queues. The caller drives WebSocket
//! I/O, ping scheduling, deadlines, cancellation and reconnects. Feed messages
//! only from the authenticated socket associated with this state owner.

pub(crate) mod connection;
mod credentials;
mod messaging;
mod wire;

pub use connection::ConnectionRequest;
pub use credentials::{IceServer, TurnCredentials};
pub use messaging::{Event, Messaging, ReceivedSignal};
pub use wire::{Failure, Outgoing, RequestId};

/// Maximum complete incoming or outgoing JSON-RPC message size.
pub const MAX_MESSAGE_BYTES: usize = crate::http::RESPONSE_LIMIT;
/// Maximum simultaneously outstanding requests, including delivery waits.
pub const MAX_PENDING_REQUESTS: usize = 128;
/// Maximum messages in one JSON-RPC batch or one incoming envelope array.
pub const MAX_BATCH_MESSAGES: usize = 32;
/// Maximum UTF-8 bytes in a service callback's opaque JSON-RPC identifier.
pub const MAX_CALLBACK_ID_BYTES: usize = 256;

pub(crate) const MAX_SERVICE_SECONDS: u64 = (i64::MAX as u64) / 1_000_000_000;

/// A redacted acquisition, framing or state failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Discovery, authentication or configuration HTTP failed.
    #[error(transparent)]
    Service(#[from] crate::Error),
    /// Framing or metadata violates the service contract.
    #[error("invalid signaling data: {0}")]
    Invalid(&'static str),
    /// A message, batch or outstanding request exceeds its bound.
    #[error("signaling capacity exceeded")]
    Limit,
    /// The state owner has been closed and cannot be reused.
    #[error("signaling connection is closed")]
    Closed,
}

#[cfg(test)]
mod tests;
