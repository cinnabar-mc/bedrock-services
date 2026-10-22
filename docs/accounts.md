# Save and restore an account

Use the [device-code example](../README.md#sign-in-and-print-your-gamertag) for the
first sign-in. Keep one account owner for credential acquisition. Mutable methods
serialize acquisition through Rust borrowing; returned immutable authorizations
can be shared with service requests.

## Save a checkpoint

Call `account.checkpoint()` and pass its `as_bytes()` to your protected storage
layer. If the account is inside `Minecraft`, use `services.checkpoint()` instead;
it can also preserve Minecraft and PlayFab credentials and the game-session ID.
Neither method consumes the live owner or performs storage I/O.

A checkpoint contains a refresh credential and the account's P-256 proof key.
It is not encrypted or authenticated by the SDK. Protect it using your secure
storage backend and enforce these steps in the application:

1. Serialize refresh and persistence for an account. Do not let two processes
   rotate the same refresh credential independently.
2. Associate saved state with the selected account and a revision or lease you
   control. Reject stale saves and stale restores.
3. Persist the current owner after failed or canceled acquisitions too: an earlier
   stage may already have rotated the refresh credential.
4. On sign-out, retire the account generation and prevent older checkpoints from
   restoring it. The SDK does not coordinate storage or account selection.

Bound reads by `xbox::MAX_CHECKPOINT_BYTES` before loading the secret. Optional
cached credentials can be omitted to fit that bound; their absence does not
prevent saving the required refresh credential and proof key.

## Restore protected bytes

Add `zeroize` to your dependencies for the owned secret buffer. Your storage
layer supplies the bytes; the SDK validates framing, proof material, and the
original OAuth/Xbox configuration before returning an account:

```rust,no_run
use bedrock_services::{
    Error,
    oauth::MicrosoftAuth,
    xbox::{Account, Checkpoint, Config},
};
use zeroize::Zeroizing;

fn restore_account(
    protected_bytes: Zeroizing<Vec<u8>>,
    original_policy: Config,
) -> Result<Account, Error> {
    let checkpoint = Checkpoint::from_bytes(protected_bytes)?;
    MicrosoftAuth::new(original_policy)?.restore_account(checkpoint)
}
```

`restore_account` performs no network request. Reuse the same OAuth client ID,
device policy, and scope. The next service call acquires whatever is missing or
expired. Credentials are exposed only through explicit getters; use the current
`credentials().refresh_token()` when your storage format stores tokens separately.

To restore Minecraft state, construct `Minecraft::new(restored_account, config)`
with the same configuration used for its checkpoint, including the persistent
device identity. `Config::desktop` accepts the standard UUID representation;
`DeviceId::compact(uuid)` preserves an existing unhyphenated device ID.

## Understand saved-cache reuse

Minecraft can reuse a saved service credential, validated authentication route,
and service-clock estimate without a fresh discovery request when the full
configuration matches, the saved clocks can advance without host-clock rollback,
and the credential still satisfies its original expiry margin. Its saved
game-session ID is retained. Cached PlayFab state is reused only while valid.
A multiplayer token still needs to be minted for the requested connection key.

If that direct reuse is unavailable, discovery and credential acquisition run as
needed. Operations requiring optional endpoints, such as Realms or signaling,
load their discovery metadata. Saved routes are not permission to send credentials
to arbitrary destinations.

Restored Xbox/OAuth cached entries have separate admission: they stay dormant until
a valid service-time observation qualifies them. Missing time, rollback, or expiry
can force refresh or reacquisition. Importing identical credential bytes does not
bypass that check. Treat caches as an optimization, not a promise of zero requests.

## Adopt externally rotated credentials

`Account::replace_credentials` requires the original OAuth client ID. Identical
material preserves its current state; changed material invalidates derived Xbox
credentials. `Minecraft::replace_credentials` retains the account proof and
game-session identity while discarding derived Minecraft/PlayFab authorizations.
It does not verify that the replacement belongs to the selected account.

Hold your account's storage lease while validating a rotation. With `Minecraft`,
call `xbox_authorization().await` and check the returned XUID against the selected
account before publishing its saved state. Do not infer identity from a matching
OAuth client ID alone.

## Handle sign-in errors

- `DeviceCodeExpired`: start a new attempt and display its new code.
- `AuthorizationDeclined`: return control to your sign-in UI.
- `SignInRequired`: the refresh credential is unusable; request a new sign-in.
- `AccountCreationRequired(challenge)`: present `challenge.signup_url()` to the
  same user, keep the account owner, and retry authorization after completion.
  The SDK does not open the page or retry that challenge for you.

The signup URL contains a signed challenge. It is exposed for that UI only and
redacted by `Debug`/`Display`; do not log or share it. Keep your original operation
deadline. Repeated completed title-policy failures can be cached briefly; avoid
spinning on an unchanged failure.

## Cancel requests and retry deliberately

Dropping an operation future cancels its pending HTTP work and retry wait.
Earlier successful stages remain installed. Discovery, Minecraft credential
issuance, and title-presence updates have bounded retries within the HTTP budget;
OAuth rotation and membership/invitation writes are not automatically replayed.
Server `Retry-After` delays are not shortened to fit the remaining budget.

When using returned authorizations for your own service traffic, retain the
exact issuance. Pass that value to `reject` after an explicit rejection before
reacquiring; a late rejection cannot evict its replacement. Built-in service
methods apply their documented rejection policy themselves.

Credential owners zeroize their stored token strings when dropped. Standard
HTTP, JSON, TLS, and application buffers can retain copies; storage and explicit
exports remain your application's responsibility.
