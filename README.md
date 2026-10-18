# bedrock-services

Native Rust account authentication for Bedrock clients. This crate owns Microsoft
device-code sign-in and refresh, Xbox proof keys, XASD/SISU acquisition, default
NSAL policy and per-relying-party XSTS credentials.

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

The first slice has no persistent proof-key/session cache, account sign-up
continuation, title-scoped service policy, PlayFab, Realms, friends/presence,
Minecraft service tokens or Cinnabar account integration. Concurrent acquisition
flights and cross-process cache coordination remain migration work. Real-account
acceptance and source-based vanilla parity are unverified.

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
rotation, reuse and rejection without contacting an account service. The oracle
test reports a named missing fixture when its executable is unavailable; CI builds
and requires it. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution.

MIT licensed. Independent of Mojang and Microsoft.
