# bedrock-services

Native Rust account authentication for Bedrock clients. This crate owns Microsoft
device-code sign-in and refresh, Xbox proof keys, XASD/SISU acquisition, default
NSAL policy and per-relying-party XSTS credentials. Minecraft services add
version-specific discovery, title-scoped NSAL, PlayFab login and service credentials,
multiplayer tokens minted for the caller's P-384 connection key, and account-borrowed
Realms browsing and join resolution. Xbox social reads share that account's proof
and authorization state.

```rust,no_run
use bedrock_services::{oauth::{MicrosoftAuth, Poll}, xbox::Config};
use std::time::SystemTime;

# async fn example() -> Result<(), bedrock_services::Error> {
let mut microsoft = MicrosoftAuth::new(Config::default())?;
let mut attempt = microsoft.start(SystemTime::now()).await?;
// Display attempt.user_code() and attempt.verification_uri() in the sign-in UI.
// Call poll when attempt.next_poll() is due; Pending also covers slow-down replies.
if let Poll::Authorized(credentials) = microsoft.poll(&mut attempt, SystemTime::now()).await? {
    let mut account = microsoft.into_account(credentials)?;
    let authorization = account.authorize("http://xboxlive.com").await?;
    // Reuse the returned Arc for service requests. Pass a rejected issuance to
    // account.reject() before retrying; stale failures cannot evict its replacement.
    let _header = authorization.header_value()?;
}
# Ok(())
# }
```

Account methods take exclusive mutable ownership during credential acquisition.
Returned authorizations are immutable and shareable. Acquisition uses a separate
plain HTTP client with HTTPS, finite deadlines, disabled redirects and bounded
responses. There are no account background tasks or locks held across HTTP.

The crate provides a default Android Minecraft authentication policy, independent
of the game's platform metadata. Request signing
accepts caller time and a borrowed P-256 key; Bedrock session P-384 keys belong to
the session layer. The HTTP edge corrects signed request time from server Date.

Credentials have no Debug or implicit serialization implementation. Their owners
zeroize stored token strings. Standard HTTP and JSON libraries can retain temporary
copies; this is not a guarantee that all credential copies are erased. Secure
storage belongs to the caller; `credentials().refresh_token()` exposes the current
rotated refresh token explicitly.

`Account::checkpoint()` exports the current refresh credential and P-256 proof key
as a bounded, zeroizing `Checkpoint` without Debug or implicit serialization.
Store its explicitly exposed `as_bytes()` through your secure storage layer;
`Checkpoint::from_bytes()` takes ownership of zeroizing bytes for
`MicrosoftAuth::restore_account()`. The format checks the complete Xbox policy
and OAuth scope. It does not provide encryption, integrity protection or account
generation fencing: the caller must serialize refresh and persistence, reject
stale revisions and prevent signed-out accounts from being restored.

Version-two checkpoints can also retain the exact OAuth material and Xbox device,
SISU and XSTS issuances with their original absolute expiries. A restored cache is
dormant until a fresh successful public title-policy request supplies a valid
HTTP Date. Saved OAuth access remains operationally dormant under the same admission:
failed time qualification forces refresh before SISU, even when its original bytes
and expiry are retained for persistence. Importing identical material cannot change
this state. Missing time, clock rollback or expired entries cause reacquisition;
response-clock anchors and title policies are never restored. Cancellation keeps
the dormant snapshot for a later attempt. Older version-one checkpoints remain
readable, and optional cache bytes are omitted if they cannot fit the existing
64 KiB bound, preserving refresh and proof durability.

At least one public policy request is required after restart. Minecraft and PlayFab
credentials are not persisted. A caller must prevent restoration of stale
checkpoints after rejection or account changes; this SDK does not reconcile
snapshots across processes. `Account::replace_credentials()` preserves caches only
when every OAuth field is identical. Changed material invalidates all Xbox stages.

A running `Minecraft` owner can export `checkpoint()` without being consumed.
After a caller validates a same-account rotation under its storage lease,
`replace_credentials()` retains the proof and game-session IDs and discards derived
authorizations. Credentials expose access, refresh and expiry only through explicit
persistence getters. These APIs supply no account-generation or storage coordination.
Use `Minecraft::xbox_authorization()` to recheck the XUID after adopting external
OAuth credentials, before publishing them to a saved account. This reuses the same
proof-key and game-session owner.

```rust,no_run
use bedrock_services::minecraft::{Minecraft, Config};

# async fn mint(account: bedrock_services::xbox::Account,
#     game_version: &str, protocol: u32, device_id: uuid::Uuid,
#     connection_key: &p384::ecdsa::VerifyingKey) -> Result<(), bedrock_services::Error> {
let config = Config::desktop(game_version, protocol, device_id);
let mut services = Minecraft::new(account, config)?;
let credential = services.multiplayer_token(connection_key).await?;
// Use credential.as_str() in Login and retain the matching private connection key
// through client-data signing and server key exchange.
# Ok(())
# }
```

The caller supplies its generated game/protocol version and a persistent device
UUID. `Config::desktop` accepts a UUID in its standard hyphenated representation,
or `DeviceId::compact(uuid)` to preserve an existing lowercase, unhyphenated ID.
The Minecraft owner keeps one fresh game-session UUID across service exchanges
and multiplayer mints. It reuses current credentials, starts a fresh service session
when replacement is due, and invalidates an unauthorized mint's exact issuance
before retrying once. Service metadata comes from a bounded HTTPS response; decoding
those claims does not verify a multiplayer peer's identity.

`Minecraft::entity` acquires title or master-player credentials for PlayFab
services, reuses immutable authorizations and renews them on demand within the
expiry margin. Returned identity and expiry must match the request. An expired
or once-rejected source causes one fresh PlayFab login.

`Minecraft::realms` borrows the same account's XSTS cache and validates the Realms
endpoint from discovery before sending credentials. Its service view lists Realms,
reads details and invitation previews, accepts an invitation only through a separate
explicit call, counts pending invitations, and resolves join requests. Negotiated
`Client-Version` state survives between views; specific version rejections trigger
a bounded patch search, with a cooldown after failed searches.

```rust,no_run
use bedrock_services::realms::{Join, NetworkProtocol};

# async fn browse(services: &mut bedrock_services::minecraft::Minecraft)
#     -> Result<(), bedrock_services::realms::Error> {
let mut realms = services.realms().await?;
for realm in realms.list().await? {
    match realms.join(realm.id, &[]).await? {
        Join::Ready(address) => match address.network_protocol {
            NetworkProtocol::Default => { /* pass address.address to RakNet */ }
            NetworkProtocol::NetherNet => { /* use WebSocket signaling */ }
            NetworkProtocol::NetherNetJsonRpc => { /* use JSON-RPC signaling */ }
            _ => { /* report the unsupported protocol without connecting */ }
        },
        Join::Pending { retry_after } => {
            // Schedule another join attempt after this delay, within your own deadline.
            let _ = retry_after;
        }
        _ => {}
    }
}
# Ok(())
# }
```

Join calls perform one attempt and return a typed `Pending` delay for retryable
service replies. The caller owns retry scheduling, cancellation and the overall
join deadline; the SDK never sleeps or spawns a background retry task. Successful
results retain IPv6 address text, pending updates, region metadata and unsupported
transport names. Optional missing or malformed Realms discovery affects Realms
requests without changing authentication-only behavior. QoS measurement, Stories
and Realm administration remain outside this API.

`Minecraft::gatherings()` borrows the same account and optional discovery for
featured-server and creator-experience catalogs. `search_items` returns one page
in service order, preserving raw title properties; callers choose localization,
visibility, sorting, artwork and pagination. `CatalogItem::properties` decodes the
consumed connection/display fields while leaving unrelated metadata opaque.
Listing and player-count reads never allocate a server or open a game connection.

`player_counts` retains its account-owned snapshot and throttles completed attempts
for five minutes. Malformed or nil-ID rows are skipped; missing and negative counts
stay distinct from zero. Envelope/HTTP failures preserve the previous snapshot,
available through `cached_player_counts`; cancellation leaves the throttle unchanged.
`join_experience` makes one explicit allocation request for a nonnil UUID and returns
only the transport and destination supplied by that response. It never retries a
possible allocation. The caller owns the deadline and observation of uncertain
results, validates supported transports and establishes the actual game connection.

These concrete HTTP clients use the caller's async runtime. Transport state machines
belong to the separate networking libraries; service credentials do not create an
internal runtime or per-account background tasks.

`Minecraft::messaging_connection()` uses the same Minecraft service credential and
player messaging identity to resolve `signaling-afd` configuration. It returns a
validated WSS destination, a sensitive Authorization header and the advertised ping
interval. Missing or malformed optional signaling discovery affects this operation
without changing auth-only discovery. Configuration 401s and explicit
`reject_messaging(&request)` invalidate only the exact rejected issuance.

`signaling::Messaging` provides bounded JSON-RPC correlation and TURN credential
caching for that connection. The caller sends each returned `Outgoing` as one text
message, feeds received text into `receive(bytes, now)`, sends callback replies and
routes opaque `ReceivedSignal` payloads through its NetherNet codec. Call
`acknowledge` only after the transport accepts a signal. Delivery waits require both
service acceptance and a receipt from the expected peer; numeric service failures
contain no remote diagnostics. Cancel requests explicitly, drive `expire(now)` at
`next_deadline()` and close the state when its socket closes. All time is supplied
by the caller; the state owns no output queue, tasks, sockets or automatic retries.

For a service route that explicitly selects legacy signaling, call
`Minecraft::legacy_signaling_connection(local_network_id)`. Its `signaling`
discovery endpoint is separate from Player Messaging's `signaling-afd` endpoint.
`signaling::Legacy` accepts string recipients and the legacy envelope format;
pass actual sink-flush completion to `flushed` and received messages to `receive`.
A delivery wait completes only after both that flush and its correlated service
outcome. The service outcome does not prove that a game peer received the signal.
The same cancellation, caller-clock and bounded-state rules apply.

The optional `signaling-tokio` feature adds `signaling::websocket::MessagingSocket`.
It selects the acquired connection’s explicit wire dialect and opens only its WSS
destination using verified Rustls, follows no redirects, and owns the socket,
bounded wire/event queues and partial writes. Use `send_signal` for Player
Messaging or `send_legacy_signal` for legacy string recipients; a mismatched call
fails before changing the socket state.
Call `drive().await` continuously to progress messages, application pings,
deadlines and control/close frames. It creates no runtime, tasks or automatic
reconnect loop. Canceling a drive future retains pending wire writes on the owner;
canceling a request retracts only frames that have not entered the socket sink.
Drop or `abort()` for immediate shutdown, or call `close()` and keep driving to
drain pending completions and finish the bounded close handshake.

With `test-support` and `signaling-tokio`, the hidden
`signaling::websocket::test_support::pair` supplies a real loopback socket and
caller-owned text peer for integration tests. It supplies no account authority.
The fixed `test_support::HostedAuthority::acquire_activation_visitors` scenario
adds two such guest sockets to the original protected host fixture, retaining its
three service tasks and checking four conditional occupancy writes. Guest service
headers are synthetic; callers must supply independently verified signed game
identities. `finish_activation_visitors` joins the original tasks and returns their
actual socket and request observations, without creating session authority.

Request admission returns `Error::Limit` without publishing a handle or frame when
a queue is full; retry local admission after driving. A reserved callback-response
slot prevents receipt/control replies from being silently lost under backpressure.
The driver accepts bounded JSON in text or binary messages, sends text, consumes
JSON-RPC callback replies internally and returns application
`Event`s, preserving explicit `acknowledge` after transport acceptance. Reuse current
TURN credentials through `credentials()`; reconnect starts a fresh cache. Upgrade
failures retain only numeric HTTP status or static causes. On `UpgradeStatus(401)`,
pass the retained `ConnectionRequest` to `Minecraft::reject_messaging` before
explicitly reacquiring and reconnecting.

The runtime edge uses `tokio-websockets` and an explicit AWS-LC Rustls provider
with WebPKI roots. Neither the SDK nor the selected WebSocket implementation logs
raw upgrades or frames. Explicit exports, temporary HTTP/JSON and socket/TLS buffers
can still retain credential copies and are not guaranteed erased on drop. Opaque
SDP identities and ICE credentials must never be logged. The SDK does not import a
NetherNet codec or decide whether an incoming signal is safe to acknowledge.

The interactive example uses caller-supplied game/protocol policy and persistent
device identity, then acquires configuration, opens the socket, obtains TURN
credentials and closes it. It displays only the device code intended for sign-in
and the number of TURN entries; account storage remains application-owned:

```sh
cargo run --features signaling-tokio --example messaging -- <game-version> <protocol> <persistent-device-uuid> <network-id>
```

`Account::social()` and `Minecraft::social()` borrow PeopleHub profiles and
relationship lists, full user/device/title presence, and multiplayer activity
handles through `xbox::social::Social`. Read calls reuse the account's NSAL policy,
proof key and per-relying-party authorization cache. Language preferences are
explicit; basic lists omit decorations. Activity handles preserve their session
references and title-defined metadata without inferring join permission from
missing or unknown restrictions. Unknown presence states remain available.

Each read sends one social request after credential acquisition. An explicit `token_expired`
challenge invalidates the exact issuance for the next caller-driven attempt;
unrelated authorization failures do not silently discard it. Social read APIs do
not publish presence, send invitations, modify multiplayer sessions or subscribe
to realtime updates.

`Account::statistics()` and `Minecraft::statistics()` read explicit bounded user/
SCID/statistic batches through that same signed Xbox owner. Raw numeric digits
and missing values are preserved; retail selections and aggregation belong to the
caller. `achievements()` reads the authenticated account's title progress, either
one page or a complete collection with page, entry and aggregate-byte bounds.
Repeated continuations fail instead of returning incomplete success. Malformed
rows are counted, unknown progress/reward data stays uninterpreted, and missing
or invalid scores are never synthesized as zero. Neither API downloads artwork.

`Minecraft::profile()` borrows persona image bytes and showcase metadata from the
optional discovered persona service, using the existing Minecraft credential.
Missing/malformed persona discovery leaves auth-only services available. Image
bytes must pass the caller's image decoder/cache admission; Content-Type alone
does not prove valid artwork. Showcase metadata is not a local screenshot count,
and response URLs are never followed with credentials. These independent reads
do not start a worker, refresh loop, runtime, upload or delete operation. Account
generation, per-facet deadlines/errors, image policy and menu projection remain
caller-owned.

`Minecraft::player_messaging()` borrows the discovered marketing/inbox service.
It retains a distinct messaging session and continuation across `refresh(language)`
and `report_events(language, events)`. Only a completely decoded refresh replaces
a nonempty continuation. Reports preserve original instance/report/button IDs,
with explicit interaction times or the HTTP edge's UTC millisecond clock. Reads
do not mark or delete messages; the application owns interaction ordering,
uncertain-write retries and account retirement. This service uses the existing
Minecraft credential and client, with no polling task, image fetch or link launch.
It is separate from Xbox game invitations and NetherNet signaling.

`Account::notifications()` and `Minecraft::notifications()` borrow explicit Xbox
game invitation inbox reads. `game_invites` addresses the authenticated account,
preserves invitation actions, original expiries and per-platform title metadata,
and counts malformed or unsupported neighboring items. The response retains its
authenticated recipient and paired service UTC/monotonic observation for caller
expiry checks. Refreshing never marks, dismisses or accepts a notification and
does not subscribe to push updates. Invitation actors and handles are untrusted
metadata; title policy and generation fencing belong to the caller.

`Account::title_presence()` and `Minecraft::title_presence()` borrow one-shot title
presence writes through the same account, proof, NSAL policy and XSTS cache.
`update` publishes a typed state with optional bounded rich-presence ID, service
configuration and substitution parameters. It always addresses the authenticated
title; application activity IDs and title policy stay with the caller. Repeat
`update` explicitly for a heartbeat, using `UpdateResult::heartbeat_after` when
present and a caller-selected fallback otherwise. The API owns no scheduling,
background task or automatic retry, including for throttled service responses.

`update_with_dispatch` invokes a caller callback after final signing, immediately
before HTTP. Retain that local dispatch state across cancellation; it establishes
possible remote mutation, not receipt or success. Acquisition and preparation
errors do not invoke it, and ordinary `update` uses the same path with no callback.

Call `remove` explicitly on shutdown, even after a failed or canceled update:
the earlier write may have applied. Removal sends once without consulting a local
success flag. Dropping the borrowed view performs no network cleanup. Callers own
their account-generation checks, refresh persistence and operation deadlines.

`Account::mpsd()` and `Minecraft::mpsd()` borrow the session directory through the
same account/proof/XSTS owner. `xbox::mpsd::Reference` validates a complete locator
and converts existing social session observations without duplicating activity
search. `publish` creates one membership with `If-None-Match: *`; activity
publication and invitations are separate explicit calls. Retain the returned
`Session` if a later operation fails, and reconcile or leave it explicitly.

`read_handle` resolves an invitation or activity handle through a read-only GET
and validates the returned complete reference against the fixed service origin.
Neither that preview nor an inbox action creates membership or title admission.
Retain the original handle, recipient, expiry and selected reference when later
joining; validate the actual joined snapshot and own cleanup separately.

For cancellation-sensitive hosting, retain a `PublishAttempt` before awaiting
`publish_retained`. It fixes the original reference, RTA binding and account proof.
Only final signed HTTP dispatch seals the one creation write; an observed 412 is
known rejection. A canceled or failed dispatch stays uncertain until
`reconcile_publish` reads the exact original active membership and a concrete
validator. A 404, replaced binding or invalid response preserves the recovery
obligation. Callers own deadlines and guarded cleanup; the SDK starts no worker.
`set_properties_bound` also requires that original active binding and a concrete
validator for conditional title admission updates; a conflict requires refresh.

Session snapshots retain unknown system/title metadata without inventing join
permission. Conditional refresh and partial writes retain exact ETags and known
branch/change metadata; fresh responses replace the whole member map. Change
numbers are compared only on the same branch; valid branch rotations reset their
sequence within a running session. Session operations reject another proof/account
owner. A canceled or failed write marks
the owner as requiring synchronization before another mutation; successful leave
or remote deletion closes it. Session Drop performs no remote I/O. Title-owned
custom data can contain admission nonces and must not be logged; ordinary JSON and
HTTP temporary buffers are not guaranteed erased on drop.

A caller-supplied `Binding` contains the actual RTA connection and stable session
subscription ID. The core does not create an RTA socket or background subscription;
the application orders connection generations and explicitly rebinds/refreshes.
A `JoinAttempt` keeps one stable membership body and IDs. `join` performs one PUT:
only an explicit HTTP 412 permits another attempt, up to three, with a returned
suggested delay. Other errors and canceled writes seal the intent because they
may have applied remotely. The caller owns waiting, deadlines, reconciliation and
cleanup. Response Content-Location is validated as a fixed-service session path
and is never followed as a credential destination. Invitation creation returns a
typed handle; notification receipt and application acceptance remain separate.

`Account::rta_connection()` and `Minecraft::rta_connection()` prepare one protected
Xbox RTA upgrade through the existing account, proof and title-selected XSTS cache.
Supply a nonzero account `Generation` and the caller transport's complete upgrade
headers, including its generated WebSocket key, fixed Host and
`rta.xboxlive.com.V2` subprotocol. Acquisition signs those final fields, returns
only the fixed WSS destination and sensitive headers, and opens no socket. Send
the returned headers unchanged over verified TLS, validate the upgrade and
negotiated subprotocol, and follow no redirects. Reacquire on each new socket.
Explicit rejected upgrades can invalidate only their exact issuance through
`reject_rta`; stale failures cannot evict its replacement.

After that upgrade succeeds, `ConnectionRequest::start()` creates one bounded
pure `xbox::rta::Connection`. Send each returned `Outgoing` once as a complete
text message; check `is_current` before admitting queued frames to the sink.
Feed complete received messages in socket order with the request's `epoch` and
caller monotonic time. Apply `Event::Subscribed`'s initial snapshot before the
next message's changes. Early unknown events and late/duplicate responses are
ignored. Service resync returns the active resources for explicit refresh.
The owner stores no credentials, socket, runtime, clock, event queue or retry task.

Canceling an admitted request or reaching its deadline retires the whole socket:
a pending subscribe may already exist remotely, and a pending unsubscribe may
already have applied. Close that socket, discard its queued frames and events,
then explicitly reacquire and `reconnect`. Account XUID, proof key and generation
must all match. Desired local handles survive; pending removals do not. Call
`resubscribe` for each desired handle, install each new initial snapshot, then
resume changes. Drive `expire(now)` at `next_deadline()`; socket/receive errors
require `disconnect()` and the same explicit cleanup. Retire the whole owner and
its generation on sign-out or account replacement. Dropping it performs no I/O.

`Resource::session_directory()` uses the MPSD connection subscription. After its
validated initial connection UUID arrives, `directory_binding` combines that UUID
with the caller's stable per-session subscription UUID for existing MPSD writes.
Bindings are usable only while their socket is current; reconnect requires an
explicit directory rebind and refresh. Typed session changes preserve validated
MPSD references, branches and change-number hints. `SessionChange::is_for` uses
the same case-insensitive reference matching as MPSD. A shoulder tap requests
refresh; it does not update a session snapshot or establish join permission.
`social_resource()` subscribes to the authenticated user's friend-list resource;
its change payload remains opaque for caller interpretation.

The RTA request, resource URI and payload owners have no Debug or implicit
serialization. Standard JSON/HTTP and caller socket buffers can retain temporary
copies and are not guaranteed erased. Application social/notification adapters
and real-account acceptance remain open work.

The independent optional `rta-tokio` feature adds `xbox::rta::websocket::RtaSocket`.
Call `websocket::upgrade_headers()` first, pass those fields to the account's
`rta_connection`, then pass the protected request to `RtaSocket::connect`. The edge
uses verified TLS, transmits every final signed header unchanged, validates the
exact accept challenge and V2 subprotocol, and follows no redirects. It exposes
no production plaintext or trust override.

One owner holds the socket, pure connection, bounded output/events and partial
write progress. `subscribe` returns a desired handle and cancelable request;
`unsubscribe` and `resubscribe` are explicit. `connection()` borrows current
identity, desired handles and MPSD bindings. Keep calling `drive().await` even
when idle so ordered messages, automatic Pongs, request deadlines and close
handshakes progress. The edge has no runtime, spawned task, active heartbeat,
automatic retry or reconnect loop. Canceling a drive future retains admitted
frame progress without replay. Canceling a request or reaching its deadline
immediately drops the entire ambiguous physical socket and drains completions.

`abort` drops I/O while retaining desired resources; `close` permanently stops
admission and starts a bounded close handshake. Explicit `reconnect` checks
XUID/proof/generation before touching current I/O, drops the old socket and
queued work, then attempts one freshly acquired upgrade. Failure or cancellation
keeps disconnected desired state. After success, explicitly `resubscribe` and
install initial snapshots before applying changes or rebinding MPSD sessions.
`into_connection` drops I/O/queued work and transfers disconnected pure state
to another caller driver. Sign-out retires the owner and its account generation.

Persistent derived-token caching, account sign-up,
friends-world application joining/hosting, live invitation push, applied realtime social updates,
shared acquisition flights, transient service retries and
cross-process cache coordination remain migration work. Native Cinnabar account
integration, real-account acceptance and source-based vanilla parity are unverified.

## Validation

```sh
cd tools/go-oracle
go build -o ../../target/go-signature-oracle .
cd ../..
BEDROCK_SERVICES_GO_ORACLE="$PWD/target/go-signature-oracle" cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

The Go oracle checks signing boundaries on original synthetic requests. Local
HTTP fixtures cover the complete device-code/XASD/SISU/XSTS chain, pacing, refresh
rotation, reuse and rejection without contacting an account service. A further
local chain covers discovery, title policy, PlayFab, service reuse and rejected
multiplayer mint recovery with the same connection key and game-session ID. A Realms
HTTP chain covers version negotiation and reuse, shared XSTS replacement, invitations,
transport selection, join retry information and credential destination checks. The oracle
test reports a named missing fixture when its executable is unavailable; CI builds
and requires it. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution.

MIT licensed. Independent of Mojang and Microsoft.
