# bedrock-services

Native Rust account authentication for Bedrock clients. This crate owns Microsoft
device-code sign-in and refresh, Xbox proof keys, XASD/SISU acquisition, default
NSAL policy and per-relying-party XSTS credentials. Minecraft services add
version-specific discovery, title-scoped NSAL, PlayFab login and service credentials,
and multiplayer tokens minted for the caller's P-384 connection key.

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

The default authentication policy matches Cinnabar's existing Android Minecraft
configuration. It is independent of the game's platform metadata. Request signing
accepts caller time and a borrowed P-256 key; Bedrock session P-384 keys belong to
the session layer. The HTTP edge corrects signed request time from server Date.

Credentials have no Debug or implicit serialization implementation. Their owners
zeroize stored token strings. Standard HTTP and JSON libraries can retain temporary
copies; this is not a guarantee that all credential copies are erased. Secure
storage belongs to the caller; `credentials().refresh_token()` exposes the current
rotated refresh token explicitly.

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
UUID. The Minecraft owner keeps one fresh game-session UUID across service exchanges
and multiplayer mints. It reuses current credentials, starts a fresh service session
when replacement is due, and invalidates an unauthorized mint's exact issuance
before retrying once. Service metadata comes from a bounded HTTPS response; decoding
those claims does not verify a multiplayer peer's identity.

`Minecraft::entity` acquires title or master-player credentials for PlayFab
services, reuses immutable authorizations and renews them on demand within the
expiry margin. Returned identity and expiry must match the request. An expired
or once-rejected source causes one fresh PlayFab login.

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

This slice does not open the WebSocket or adapt messaging to NetherNet. The next
integration must drive bounded socket I/O with redirects disabled, schedule pings,
close/cancel on write failure and own reconnects. Reuse valid TURN credentials
through `credentials(now)`; otherwise request them with `request_credentials`.
SDP identities, request bytes and ICE credentials are sensitive and have no Debug
implementation. Explicit exports and transport buffers are the caller's responsibility.

Persistent proof-key/session caching, account sign-up, Realms, friends/presence,
shared acquisition flights, transient service retries and
cross-process cache coordination remain migration work. Native Cinnabar account
integration, real-account acceptance and source-based vanilla parity are unverified.

## Validation

```sh
cd tools/go-oracle
go build -o ../../target/go-signature-oracle .
cd ../..
BEDROCK_SERVICES_GO_ORACLE="$PWD/target/go-signature-oracle" cargo test
cargo clippy --all-targets -- -D warnings
```

The Go oracle checks signing boundaries on original synthetic requests. Local
HTTP fixtures cover the complete device-code/XASD/SISU/XSTS chain, pacing, refresh
rotation, reuse and rejection without contacting an account service. A further
local chain covers discovery, title policy, PlayFab, service reuse and rejected
multiplayer mint recovery with the same connection key and game-session ID. The oracle
test reports a named missing fixture when its executable is unavailable; CI builds
and requires it. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution.

MIT licensed. Independent of Mojang and Microsoft.
