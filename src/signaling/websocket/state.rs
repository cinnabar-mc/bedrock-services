//! Concrete wire dialects sharing one WebSocket, queue, timer and lifecycle owner.

use super::*;
use crate::signaling::Legacy;

pub(super) enum State {
    Messaging(Messaging),
    Legacy(Legacy),
}

pub(super) enum CredentialRequest {
    Write(Outgoing),
    Wait(RequestId),
}

impl State {
    /// Borrows original credentials from the selected concrete state owner.
    pub(super) fn credentials(&self, now: Instant) -> Option<&TurnCredentials> {
        match self {
            Self::Messaging(state) => state.credentials(now),
            Self::Legacy(state) => state.credentials(now),
        }
    }

    /// Reserves a correlated TURN command or an actual legacy pushed-credential wait.
    pub(super) fn request_credentials(
        &mut self,
        deadline: Instant,
    ) -> Result<CredentialRequest, Error> {
        match self {
            Self::Messaging(state) => state
                .request_credentials(deadline)
                .map(CredentialRequest::Write),
            Self::Legacy(state) => state
                .request_credentials(deadline)
                .map(CredentialRequest::Wait),
        }
    }

    /// Refuses a UUID envelope operation on the legacy wire before changing state.
    pub(super) fn messaging(&mut self) -> Result<&mut Messaging, Error> {
        match self {
            Self::Messaging(state) => Ok(state),
            Self::Legacy(_) => Err(Error::Invalid("messaging socket dialect")),
        }
    }

    /// Refuses a string-routed legacy operation on the JSON-RPC wire before changing state.
    pub(super) fn legacy(&mut self) -> Result<&mut Legacy, Error> {
        match self {
            Self::Legacy(state) => Ok(state),
            Self::Messaging(_) => Err(Error::Invalid("legacy socket dialect")),
        }
    }

    /// Counts the actual core waits for the existing edge event reservation.
    pub(super) fn pending_requests(&self) -> usize {
        match self {
            Self::Messaging(state) => state.pending_requests(),
            Self::Legacy(state) => state.pending_requests(),
        }
    }

    /// Preserves the original state owner's first absolute request and credential deadlines.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        match self {
            Self::Messaging(state) => state.next_deadline(),
            Self::Legacy(state) => state.next_deadline(),
        }
    }

    /// Cancels only one original handle without recreating or retransmitting its frame.
    pub(super) fn cancel(&mut self, request: RequestId) -> bool {
        match self {
            Self::Messaging(state) => state.cancel(request),
            Self::Legacy(state) => state.cancel(request),
        }
    }

    /// Advances pure state with time sampled at the sole socket edge.
    pub(super) fn expire(&mut self, now: Instant) -> Vec<Event> {
        match self {
            Self::Messaging(state) => state.expire(now),
            Self::Legacy(state) => state.expire(now),
        }
    }

    /// Decodes only the selected explicit wire dialect; an incoming frame cannot switch it.
    pub(super) fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<Vec<Event>, Error> {
        match self {
            Self::Messaging(state) => state.receive(bytes, now),
            Self::Legacy(state) => state.receive(bytes, now),
        }
    }

    /// Resolves all bounded waits through the original core's terminal behavior.
    pub(super) fn close(&mut self) -> Vec<Event> {
        match self {
            Self::Messaging(state) => state.close(),
            Self::Legacy(state) => state.close(),
        }
    }

    /// Produces the actual protocol's heartbeat while retaining the existing single edge deadline.
    pub(super) fn ping(&mut self, deadline: Instant) -> Result<Outgoing, Error> {
        match self {
            Self::Messaging(state) => state.ping(deadline),
            Self::Legacy(state) => state.ping(deadline),
        }
    }

    /// Supplies actual flush evidence only to a dialect whose writes complete locally.
    pub(super) fn flushed(&mut self, request: RequestId, now: Instant) -> Vec<Event> {
        match self {
            Self::Messaging(_) => Vec::new(),
            Self::Legacy(state) => state.flushed(request, now),
        }
    }
}
