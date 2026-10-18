//! Bounded Xbox Real-Time Activity subscriptions driven by a caller-owned WebSocket.
//!
//! Acquire [`ConnectionRequest`] through the existing Account or Minecraft owner.
//! Use only its protected WSS destination, negotiate its subprotocol and follow no
//! redirects. Create one [`Connection`] after the upgrade succeeds. Send each
//! [`Outgoing`] as one text message and feed complete messages in socket order.
//! Apply each initial snapshot before processing the next message's changes.
//!
//! The pure owner creates no socket, runtime, task, retry loop or output queue.
//! The optional `rta-tokio` feature provides a separate caller-driven socket edge.
//! Other callers supply monotonic time, drive deadlines and explicitly resubscribe
//! after reconnect. On disconnection, cancellation, timeout or receive error,
//! close the old socket and discard its queued frames before reconnecting. This
//! conservative cancellation rule prevents an unacknowledged remote subscription
//! from being orphaned on a socket that the caller continues to use.

mod connection;
mod state;
#[cfg(feature = "rta-tokio")]
pub mod websocket;
mod wire;

pub use connection::ConnectionRequest;
pub use state::Connection;
pub use wire::{
    Epoch, Event, Failure, Generation, Outgoing, RequestId, Resource, SessionChange, SubscriptionId,
};

/// Largest complete incoming or outgoing RTA message.
pub const MAX_MESSAGE_BYTES: usize = crate::http::RESPONSE_LIMIT;
/// Largest individual subscription resource URI.
pub const MAX_RESOURCE_BYTES: usize = 4096;
/// Maximum desired subscriptions, including requests awaiting acknowledgement.
pub const MAX_SUBSCRIPTIONS: usize = 128;
/// Maximum concurrent subscribe/unsubscribe handshakes.
pub const MAX_PENDING_REQUESTS: usize = 128;
/// Maximum MPSD shoulder taps in one message.
pub const MAX_SESSION_CHANGES: usize = 128;

const SESSION_RESOURCE: &str = "https://sessiondirectory.xboxlive.com/connections/";

/// Redacted acquisition, framing or lifecycle failure; no remote diagnostics survive.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Authentication or service-policy acquisition failed.
    #[error(transparent)]
    Service(#[from] crate::Error),
    /// A supplied or received value violates the local wire contract.
    #[error("invalid RTA data: {0}")]
    Invalid(&'static str),
    /// A message, resource or state collection exceeds its bound.
    #[error("RTA capacity exceeded")]
    Limit,
    /// The socket must be closed and explicitly replaced before further use.
    #[error("RTA connection is disconnected")]
    Disconnected,
    /// This owner was permanently closed.
    #[error("RTA connection is closed")]
    Closed,
    /// A request or subscription handle belongs to another owner/socket.
    #[error("RTA handle belongs to another connection")]
    WrongHandle,
    /// Reconnect would change account, proof key or caller generation.
    #[error("RTA account generation mismatch")]
    WrongAccount,
    /// The requested subscription is not in the required lifecycle phase.
    #[error("RTA subscription operation is already pending or inactive")]
    State,
}

#[cfg(test)]
mod tests;
