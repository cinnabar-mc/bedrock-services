use super::{
    Epoch, Error, Event, Failure, Generation, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS,
    MAX_SUBSCRIPTIONS, Outgoing, RequestId, Resource, SubscriptionId,
    wire::{self, Message},
};
use crate::xbox::mpsd;
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Non-credential identity retained by the pure owner, with no HTTP/runtime dependency.
#[derive(Clone)]
pub(super) struct Scope {
    pub(super) xuid: String,
    pub(super) proof: p256::ecdsa::VerifyingKey,
    pub(super) generation: Generation,
    pub(super) epoch: Epoch,
}

impl Scope {
    /// Requires the same validated account, proof owner and caller generation on reconnect.
    pub(super) fn same_account(&self, other: &Self) -> bool {
        self.xuid == other.xuid && self.proof == other.proof && self.generation == other.generation
    }
}

/// One bounded subscription set and socket generation; no credentials, I/O, clock reads or tasks.
/// No Debug: resource URLs and event bodies can contain private identity/session information.
pub struct Connection {
    pub(super) scope: Scope,
    pub(super) connected: bool,
    pub(super) closed: bool,
    owner: Epoch,
    next_subscription: u64,
    next_request: u32,
    subscriptions: BTreeMap<SubscriptionId, Subscription>,
    pending: BTreeMap<u32, Pending>,
}

struct Subscription {
    resource: Resource,
    phase: Phase,
}
#[derive(Clone, Copy)]
enum Phase {
    Idle,
    Subscribing,
    Active {
        server: u32,
        directory: Option<Uuid>,
    },
    Removing {
        server: u32,
        directory: Option<Uuid>,
    },
}
struct Pending {
    id: RequestId,
    subscription: SubscriptionId,
    operation: u32,
    deadline: Instant,
}

impl Connection {
    /// Initializes state solely from the acquired non-credential identity scope.
    pub(super) fn new(scope: Scope) -> Self {
        Self {
            owner: scope.epoch,
            scope,
            connected: true,
            closed: false,
            next_subscription: 1,
            next_request: 1,
            subscriptions: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Returns the caller account generation retained by this owner.
    pub fn generation(&self) -> Generation {
        self.scope.generation
    }
    /// Returns the sole socket epoch currently associated with this owner.
    pub fn epoch(&self) -> Epoch {
        self.scope.epoch
    }
    /// Reports whether the socket may still carry requests and events.
    pub fn is_connected(&self) -> bool {
        self.connected && !self.closed
    }
    /// Iterates desired handles in admission order; removing subscriptions are omitted.
    pub fn subscriptions(&self) -> impl Iterator<Item = SubscriptionId> + '_ {
        self.subscriptions
            .iter()
            .filter(|(_, sub)| !matches!(sub.phase, Phase::Removing { .. }))
            .map(|(id, _)| *id)
    }
    /// Whether a frame still belongs to a pending request on the currently usable socket.
    pub fn is_current(&self, outgoing: &Outgoing) -> bool {
        self.is_connected()
            && outgoing.epoch() == self.scope.epoch
            && self
                .pending
                .get(&outgoing.request.sequence)
                .is_some_and(|p| p.id == outgoing.request)
    }

    /// Builds the authenticated account's social friend-list resource without another lookup.
    pub fn social_resource(&self) -> Resource {
        Resource(format!(
            "https://social.xboxlive.com/users/xuid({})/friends",
            self.scope.xuid
        ))
    }

    /// Registers one desired resource and returns its first subscribe frame transactionally.
    /// Capacity/invalid deadline errors publish neither a handle nor a pending request.
    pub fn subscribe(
        &mut self,
        resource: Resource,
        now: Instant,
        deadline: Instant,
    ) -> Result<(SubscriptionId, Outgoing), Error> {
        self.ready(now, deadline)?;
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return Err(Error::Limit);
        }
        let next = self.next_subscription.checked_add(1).ok_or(Error::Limit)?;
        let id = SubscriptionId {
            owner: self.owner,
            sequence: self.next_subscription,
        };
        let outgoing = self.prepare(wire::SUBSCRIBE, json!(resource.as_str()), id, deadline)?;
        self.next_subscription = next;
        self.subscriptions.insert(
            id,
            Subscription {
                resource,
                phase: Phase::Subscribing,
            },
        );
        Ok((id, outgoing))
    }

    /// Explicitly restores one idle desired resource on the current replacement socket.
    pub fn resubscribe(
        &mut self,
        id: SubscriptionId,
        now: Instant,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        self.ready(now, deadline)?;
        let sub = self.subscription(id)?;
        if !matches!(sub.phase, Phase::Idle) {
            return Err(Error::State);
        }
        let payload = json!(sub.resource.as_str());
        let outgoing = self.prepare(wire::SUBSCRIBE, payload, id, deadline)?;
        self.subscriptions
            .get_mut(&id)
            .ok_or(Error::WrongHandle)?
            .phase = Phase::Subscribing;
        Ok(outgoing)
    }

    /// Removes an idle desired resource locally, or begins one active unsubscribe handshake.
    /// Changes remain ordered until removal succeeds, so a rejected unsubscribe cannot lose
    /// updates. Cancellation/timeout instead retires the socket to remove ambiguity.
    pub fn unsubscribe(
        &mut self,
        id: SubscriptionId,
        now: Instant,
        deadline: Instant,
    ) -> Result<Option<Outgoing>, Error> {
        self.ready(now, deadline)?;
        match self.subscription(id)?.phase {
            Phase::Idle => {
                self.remove_idle(id)?;
                Ok(None)
            }
            Phase::Active { server, directory } => {
                let outgoing = self.prepare(wire::UNSUBSCRIBE, json!(server), id, deadline)?;
                self.subscriptions
                    .get_mut(&id)
                    .ok_or(Error::WrongHandle)?
                    .phase = Phase::Removing { server, directory };
                Ok(Some(outgoing))
            }
            _ => Err(Error::State),
        }
    }

    /// Retires only an idle desired handle without a clock read or a remote unsubscribe.
    pub(super) fn remove_idle(&mut self, id: SubscriptionId) -> Result<(), Error> {
        if !matches!(self.subscription(id)?.phase, Phase::Idle) {
            return Err(Error::State);
        }
        self.subscriptions.remove(&id);
        Ok(())
    }

    /// Returns the current MPSD connection UUID plus the caller's stable per-session subscription
    /// UUID. Bind only while this connection is current; reconnect requires explicit rebinding.
    pub fn directory_binding(
        &self,
        id: SubscriptionId,
        session_subscription: Uuid,
    ) -> Result<mpsd::Binding, Error> {
        self.check_connected()?;
        match self.subscription(id)?.phase {
            Phase::Active {
                directory: Some(connection),
                ..
            } => mpsd::Binding::new(connection, session_subscription)
                .map_err(|_| Error::Invalid("session binding")),
            _ => Err(Error::State),
        }
    }

    /// Accepts one complete message from the matching socket, returning ordered application work.
    /// Late/duplicate responses and unknown subscription events are ignored. Changes preceding
    /// their subscribe acknowledgement are not buffered or delivered. A receive error retires
    /// the socket immediately; call disconnect() to collect failed requests, then close it.
    pub fn receive(
        &mut self,
        epoch: Epoch,
        bytes: &[u8],
        now: Instant,
    ) -> Result<Vec<Event>, Error> {
        if epoch != self.scope.epoch {
            return Err(Error::WrongHandle);
        }
        self.check_connected()?;
        let expired = self.expire(now);
        if !expired.is_empty() {
            return Ok(expired);
        }
        let result = wire::decode(bytes).and_then(|message| self.apply(message));
        if result.is_err() {
            self.connected = false;
        }
        result
    }

    /// Returns the nearest deadline; scheduling and monotonic time belong to the caller.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|p| p.deadline).min()
    }

    /// Ends a due request and the ambiguous socket once; all other requests fail disconnected.
    /// The caller must close the old socket even if it has buffered output or a late response.
    pub fn expire(&mut self, now: Instant) -> Vec<Event> {
        if !self.pending.values().any(|p| now >= p.deadline) {
            return Vec::new();
        }
        self.interrupt(|p| {
            if now >= p.deadline {
                Failure::TimedOut
            } else {
                Failure::Disconnected
            }
        })
    }

    /// Cancels one pending request and retires its socket so an unknown remote subscription cannot
    /// survive silently. A canceled subscribe is removed from desired state; no automatic retry.
    pub fn cancel(&mut self, id: RequestId) -> Vec<Event> {
        if id.epoch != self.scope.epoch {
            return Vec::new();
        }
        let Some(pending) = self.pending.get(&id.sequence).filter(|p| p.id == id) else {
            return Vec::new();
        };
        let subscription = pending.subscription;
        let events = self.interrupt(|p| {
            if p.id == id {
                Failure::Cancelled
            } else {
                Failure::Disconnected
            }
        });
        self.subscriptions.remove(&subscription);
        events
    }

    /// Retires the socket, preserving only desired resources for explicit resubscription.
    /// Pending removals are forgotten; a lost unsubscribe must not be resubscribed.
    pub fn disconnect(&mut self) -> Vec<Event> {
        self.interrupt(|_| Failure::Disconnected)
    }

    /// Permanently closes local state without I/O. The caller must also close its WebSocket.
    pub fn close(&mut self) -> Vec<Event> {
        let events = self.disconnect();
        self.closed = true;
        self.subscriptions.clear();
        events
    }

    /// Applies a decoded message synchronously so a successful initial snapshot precedes changes.
    fn apply(&mut self, message: Message) -> Result<Vec<Event>, Error> {
        match message {
            Message::Resync => Ok(vec![Event::Resync {
                subscriptions: self
                    .subscriptions
                    .iter()
                    .filter(|(_, s)| {
                        matches!(s.phase, Phase::Active { .. } | Phase::Removing { .. })
                    })
                    .map(|(id, _)| *id)
                    .collect(),
            }]),
            Message::Change { server, data } => {
                let Some((id, sub)) = self.subscriptions.iter().find(|(_, s)| matches!(s.phase, Phase::Active { server: active, .. } | Phase::Removing { server: active, .. } if active == server)) else { return Ok(Vec::new()); };
                if sub.resource.is_directory() {
                    Ok(vec![Event::SessionsChanged {
                        subscription: *id,
                        changes: wire::session_changes(&data)?,
                    }])
                } else {
                    Ok(vec![Event::Changed {
                        subscription: *id,
                        data,
                    }])
                }
            }
            Message::Response {
                operation,
                sequence,
                status,
                mut body,
            } => {
                let Some(pending) = self.pending.get(&sequence) else {
                    return Ok(Vec::new());
                };
                if pending.operation != operation {
                    return Ok(Vec::new());
                }
                let id = pending.subscription;
                let request = pending.id;
                if status != 0 {
                    self.pending.remove(&sequence);
                    let sub = self.subscriptions.get_mut(&id).ok_or(Error::State)?;
                    sub.phase = match sub.phase {
                        Phase::Removing { server, directory } => {
                            Phase::Active { server, directory }
                        }
                        _ => Phase::Idle,
                    };
                    return Ok(vec![Event::Failed {
                        request,
                        subscription: id,
                        cause: Failure::Status(status),
                    }]);
                }
                if operation == wire::UNSUBSCRIBE {
                    self.pending.remove(&sequence);
                    self.subscriptions.remove(&id);
                    return Ok(vec![Event::Unsubscribed {
                        request,
                        subscription: id,
                    }]);
                }
                if body.len() < 2 {
                    return Err(Error::Invalid("subscribe snapshot"));
                }
                let server = wire::number(&body[0])?;
                if self.subscriptions.values().any(|s| matches!(s.phase, Phase::Active { server: n, .. } | Phase::Removing { server: n, .. } if n == server)) { return Err(Error::Invalid("duplicate subscription ID")); }
                let initial = body.swap_remove(1);
                let directory = if self.subscription(id)?.resource.is_directory() {
                    Some(
                        initial
                            .get("ConnectionId")
                            .and_then(Value::as_str)
                            .and_then(|s| Uuid::parse_str(s).ok())
                            .filter(|id| !id.is_nil())
                            .ok_or(Error::Invalid("directory connection ID"))?,
                    )
                } else {
                    None
                };
                self.pending.remove(&sequence);
                self.subscriptions.get_mut(&id).ok_or(Error::State)?.phase =
                    Phase::Active { server, directory };
                Ok(vec![Event::Subscribed {
                    request,
                    subscription: id,
                    initial,
                }])
            }
        }
    }

    /// Builds a bounded frame before changing counters or publishing correlation state.
    fn prepare(
        &mut self,
        operation: u32,
        payload: Value,
        subscription: SubscriptionId,
        deadline: Instant,
    ) -> Result<Outgoing, Error> {
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(Error::Limit);
        }
        let next = self.next_request.checked_add(1).ok_or(Error::Limit)?;
        let request = RequestId {
            epoch: self.scope.epoch,
            sequence: self.next_request,
        };
        let text = Zeroizing::new(
            serde_json::to_string(&json!([operation, request.sequence, payload]))
                .map_err(|_| Error::Invalid("request JSON"))?,
        );
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        self.pending.insert(
            request.sequence,
            Pending {
                id: request,
                subscription,
                operation,
                deadline,
            },
        );
        self.next_request = next;
        Ok(Outgoing { request, text })
    }

    /// Returns one local handle only if it belongs to this stable owner.
    fn subscription(&self, id: SubscriptionId) -> Result<&Subscription, Error> {
        if id.owner != self.owner {
            return Err(Error::WrongHandle);
        }
        self.subscriptions.get(&id).ok_or(Error::WrongHandle)
    }
    /// Rejects expired admission without implicitly expiring unrelated existing requests.
    fn ready(&self, now: Instant, deadline: Instant) -> Result<(), Error> {
        self.check_connected()?;
        if deadline <= now {
            return Err(Error::Invalid("request deadline"));
        }
        Ok(())
    }
    /// Gates bindings, request admission and receive after terminal transport ambiguity.
    fn check_connected(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else if !self.connected {
            Err(Error::Disconnected)
        } else {
            Ok(())
        }
    }
    /// Drains every pending request once and invalidates old server IDs before reconnect.
    fn interrupt(&mut self, cause: impl Fn(&Pending) -> Failure) -> Vec<Event> {
        let was_connected = self.connected;
        self.connected = false;
        let pending = std::mem::take(&mut self.pending);
        let mut events: Vec<_> = pending
            .into_values()
            .map(|p| Event::Failed {
                request: p.id,
                subscription: p.subscription,
                cause: cause(&p),
            })
            .collect();
        self.subscriptions
            .retain(|_, sub| !matches!(sub.phase, Phase::Removing { .. }));
        for sub in self.subscriptions.values_mut() {
            sub.phase = Phase::Idle;
        }
        if was_connected || !events.is_empty() {
            events.push(Event::Disconnected);
        }
        events
    }
}
