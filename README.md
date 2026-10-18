# bedrock-services

Native Rust account authentication for Bedrock clients. This crate owns Microsoft
device-code sign-in and refresh, Xbox proof keys, XASD/SISU acquisition, default
NSAL policy and per-relying-party XSTS credentials. Minecraft services add
version-specific discovery, title-scoped NSAL, PlayFab login and service credentials,
multiplayer tokens minted for the caller's P-384 connection key, and account-borrowed
Realms browsing and join resolution.

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

`Account::checkpoint()` exports the current refresh credential and P-256 proof key
as a bounded, zeroizing `Checkpoint` without Debug or implicit serialization.
Store its explicitly exposed `as_bytes()` through your secure storage layer;
`Checkpoint::from_bytes()` takes ownership of zeroizing bytes for
`MicrosoftAuth::restore_account()`. The format checks the complete Xbox policy
and OAuth scope. It does not provide encryption, integrity protection or account
generation fencing: the caller must serialize refresh and persistence, reject
stale revisions and prevent signed-out accounts from being restored.

Restoring preserves proof and refresh ownership, then reacquires access and
derived credentials. Response-clock anchors do not survive restart, so access,
device, SISU, XSTS and title-policy caches are deliberately omitted. This requires
network requests after restart; persistent reuse of derived credentials remains
open work.

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

These concrete HTTP clients use the caller's async runtime. Transport state machines
belong to the separate networking libraries; service credentials do not create an
internal runtime or per-account background tasks.

Persistent derived-token caching, account sign-up, friends/presence,
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
multiplayer mint recovery with the same connection key and game-session ID. A Realms
HTTP chain covers version negotiation and reuse, shared XSTS replacement, invitations,
transport selection, join retry information and credential destination checks. The oracle
test reports a named missing fixture when its executable is unavailable; CI builds
and requires it. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution.

MIT licensed. Independent of Mojang and Microsoft.
