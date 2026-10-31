# Open messaging and realtime connections

Use service acquisition to prepare authenticated connections, then choose a
caller-driven Tokio socket or your own WebSocket driver. HTTP acquisition still
requires your Tokio runtime. The optional socket drivers do not spawn background
tasks: keep calling `drive().await` for I/O, deadlines, and shutdown to progress.

## Try NetherNet signaling

The included example signs in, uses your game/device policy, obtains TURN server
entries, and closes its socket. Run it from this checkout:

```sh
cargo run --locked --features signaling-tokio --example messaging -- <game-version> <protocol> <persistent-device-uuid> <network-id>
```

Use actual version/protocol values and a persisted device UUID. The network ID
identifies your local NetherNet peer. The example does not connect to a game
peer or save account state; [account persistence](accounts.md) belongs to your app.

In your own project, enable the driver:

```sh
cargo add bedrock-services --git https://github.com/cinnabar-mc/bedrock-services --branch dev --features signaling-tokio
```

Given a live `Minecraft` owner, this acquires and opens its messaging connection:

```rust,no_run
use bedrock_services::{
    minecraft::Minecraft,
    signaling::websocket::{MessagingSocket, Options, SocketError},
};

async fn open_messaging(
    services: &mut Minecraft,
    local_network_id: u64,
) -> Result<MessagingSocket, Box<dyn std::error::Error>> {
    let request = services.messaging_connection().await?;
    match MessagingSocket::connect(&request, local_network_id, Options::default()).await {
        Ok(socket) => Ok(socket),
        Err(error) => {
            if error == SocketError::UpgradeStatus(401) {
                services.reject_messaging(&request);
            }
            Err(error.into())
        }
    }
}
```

The protected request supplies its WSS destination, authorization, messaging UUID,
and ping interval. Reacquire explicitly after an upgrade rejection; stale
rejections cannot evict a newer credential.

## Exchange signals and get ICE credentials

1. Call `request_credentials(deadline)` when fresh TURN credentials are needed.
   Drive until its `Event::Completed` arrives, then use `credentials()` or
   `take_credentials()`. Preserve `TurnCredentials::expires_at()` when configuring
   ICE; copying it does not renew its lifetime.
2. Call `send_signal(peer_uuid, message_uuid, text, wait_delivery, deadline)`
   with your encoded NetherNet signal. A delivery wait distinguishes service
   acceptance from a receipt from that intended peer.
3. On `Event::Signal(signal)`, pass `sender()` and `signal()` to your transport's
   admission path. Call `acknowledge` only after that transport accepts it.
4. Keep driving while requests are pending and when idle. The driver progresses
   application pings, WebSocket control frames, and original request deadlines.

The library does not include a NetherNet codec or decide game admission. Route
with the authenticated envelope's sender UUID; a separately advertised network ID
is not a substitute. See the
[NetherNet messaging guide](https://github.com/cinnabar-mc/nethernet/blob/main/docs/xbox-messaging.md)
for the transport side.

`Error::Limit` means local admission failed without a new handle or frame; drive
and retry admission. Canceling `drive` retains partially written frames on the
socket owner. Canceling a request can retract a frame that has not entered the
sink, but it cannot undo bytes already sent. Do not automatically resend an
ambiguous operation.

For immediate shutdown, drop or `abort` the socket. For a close handshake, call
`close()` and keep driving through queued completions until `SocketError::Closed`.
A newly connected socket starts with fresh request IDs and no old TURN cache.

## Subscribe to Xbox RTA

Enable the independent `rta-tokio` feature. Generate upgrade headers before
asking the account to sign the request, then open that exact protected request:

```rust,no_run
use bedrock_services::xbox::{
    Account,
    rta::{Generation, websocket::{self, Options, RtaSocket, SocketError}},
};

async fn open_rta(
    account: &mut Account,
    generation: Generation,
) -> Result<RtaSocket, Box<dyn std::error::Error>> {
    let mut request = account.rta_connection(generation, websocket::upgrade_headers()?).await?;
    match RtaSocket::connect(&mut request, Options::default()).await {
        Ok(socket) => Ok(socket),
        Err(error) => {
            if error == SocketError::UpgradeStatus(401) {
                account.reject_rta(&request);
            }
            Err(error.into())
        }
    }
}
```

Your account selection owns a nonzero `Generation::new(value)`; retire it on
sign-out/account replacement. `Minecraft` offers the same RTA acquisition methods.
Call `socket.subscribe(resource, deadline)` and retain the returned subscription
and request handles. Use `socket.connection().social_resource()` for the signed-in
friend resource, or `Resource::session_directory()` for directory connection and
session notifications. Apply `Event::Subscribed`'s initial snapshot before later
changes. Directory notifications request an HTTP refresh; they do not update an
MPSD snapshot or grant permission to join.

## Recover or stop RTA

An admitted request cancellation or expiry retires the entire physical socket:
a remote subscription may already have changed. Drain old failure/disconnection
completions before replacement. Close the old socket and discard its queued
frames/events; retain desired local subscription handles.

For one explicit reconnect, acquire a fresh protected request and call
`socket.reconnect`. It checks account XUID, proof, and generation. On success,
resubscribe each desired handle, install each initial snapshot, then rebind and
refresh affected directory memberships. Failure or cancellation keeps desired
state disconnected.

`socket.recover(account, deadline)` or `services.recover_rta(socket, deadline)`
also reacquires and restores desired subscriptions. Recovery retries transient
failures with bounded backoff/jitter under that deadline. Cancellation drops
partial I/O while retaining desired handles, scheduled waits, and resource
failures. Apply returned snapshots in order; a rejected resource fails separately
while other desired resources can restore. Keep driving afterward.

`abort` drops I/O while retaining desired resources. `close` permanently stops
admission and starts a bounded close handshake; keep driving to finish it.
`into_connection` transfers disconnected pure state after dropping socket work.

## Supply your own WebSocket

For signaling, `signaling::Messaging` accepts complete messages and
caller monotonic time. Send each returned `Outgoing` once, feed incoming messages
in order, route callback replies, and call `expire(now)` at `next_deadline()`.
Close the state when its physical socket closes.

For RTA, supply your transport's final upgrade headers to `rta_connection`, send
all returned signed headers unchanged over verified TLS, validate the challenge
and subprotocol, and follow no redirects. Call `request.start()` only after the
upgrade succeeds. Send each `Outgoing` as one text message after `is_current`,
and feed complete messages with the socket's epoch and caller time. On receive
error, request cancellation, or timeout, close/discard that socket before explicit
reconnect and resubscription.

Protected headers, signals, resource URIs, tokens, and TURN credentials must not
be logged. Pure message state owns no socket, output queue, or retry task; your
driver owns buffering, deadlines, and shutdown.
