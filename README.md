# bedrock-services

Sign in with Microsoft, restore a saved Xbox account, mint a Minecraft multiplayer
token, and read Realms or social data from Rust. Optional WebSocket drivers support
NetherNet signaling and Xbox Real-Time Activity subscriptions.

This library handles account and service requests. Your application owns its
sign-in UI, protected account storage, game connection, and reconnect policy.

## Install

This crate is currently installed from Git:

```sh
cargo add bedrock-services --git https://github.com/cinnabar-mc/bedrock-services --branch dev
cargo add tokio --features macros,rt,time
```

Use Rust 1.93 or newer and commit your application's `Cargo.lock`.
HTTP calls run on your Tokio runtime. The library does not start a runtime or
background account worker.

## Sign in and print your gamertag

Save this as `src/main.rs`, run `cargo run`, and follow the displayed sign-in
instructions. The loop waits until each poll is due, including any service
request to slow down.

```rust,no_run
use bedrock_services::{
    oauth::{MicrosoftAuth, Poll},
    xbox::Config as OAuthConfig,
};
use std::time::SystemTime;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), bedrock_services::Error> {
    let mut microsoft = MicrosoftAuth::new(OAuthConfig::default())?;
    let mut attempt = microsoft.start(SystemTime::now()).await?;
    println!(
        "Open {} and enter {}",
        attempt.verification_uri(),
        attempt.user_code(),
    );

    let credentials = loop {
        let delay = attempt.next_poll()
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(delay).await;
        match microsoft.poll(&mut attempt, SystemTime::now()).await? {
            Poll::Pending => continue,
            Poll::Authorized(credentials) => break credentials,
        }
    };

    let mut account = microsoft.into_account(credentials)?;
    let authorization = account.authorize("http://xboxlive.com").await?;
    println!("Signed in as {}", authorization.gamertag());
    Ok(())
}
```

The verification code is intended for the signing-in user. Access tokens, refresh
tokens, authorization headers, and account checkpoints are private credentials;
keep them out of logs. The example keeps its account in memory. To avoid another
interactive sign-in, [save and restore a checkpoint](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/accounts.md).

If authorization reports `AccountCreationRequired`, show its `signup_url()` in
your sign-in UI, keep the same account, then retry after the user completes the
page. [The account guide](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/accounts.md#handle-sign-in-errors) covers this flow.

## Use the account

| Task | Start here |
| --- | --- |
| Save an account, restore it on startup, or adopt a refresh rotation | [Account storage](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/accounts.md) |
| Mint a token for your connection's key | [Minecraft tokens](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/minecraft.md#mint-a-multiplayer-token) |
| List Realms, resolve a selected Realm, or read friends and presence | [Minecraft and social services](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/minecraft.md) |
| Open NetherNet signaling or subscribe to Xbox RTA | [Messaging and realtime](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/realtime.md) |
| Publish title presence or a multiplayer session, then clean it up | [Activity and session writes](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/activity.md) |

To use Minecraft services, move the account into `Minecraft::new` with your
application's game version, protocol number, and persistent device UUID. Reuse
that owner for later requests so its credentials and service state can be reused.
The multiplayer token is minted for a P-384 public key that you supply; retain
the matching private key for Login and key exchange.

Social reads can use `account.social()` directly. Realms, catalogs, profile
artwork, and Minecraft inbox data are available through `Minecraft`. Listing a
Realm or social activity does not open a game connection or accept an invitation.

## WebSocket support

Enable `signaling-tokio` for `signaling::websocket::MessagingSocket`, or
`rta-tokio` for `xbox::rta::websocket::RtaSocket`. These drivers use your Tokio
runtime and progress when you call `drive().await`; they create no background
task. You can instead integrate the pure message state with your own WebSocket.
See [messaging and realtime](https://github.com/cinnabar-mc/bedrock-services/blob/dev/docs/realtime.md) for setup and shutdown.

An interactive signaling example is included in this checkout:

```sh
cargo run --locked --features signaling-tokio --example messaging -- <game-version> <protocol> <persistent-device-uuid> <network-id>
```

Supply version and protocol values from your game protocol implementation, keep
the device UUID stable between runs, and choose a distinct local network ID.
The example signs in, requests TURN server entries, prints their count, and closes.
It does not join a Minecraft server.

## License

MIT licensed; see [LICENSE](https://github.com/cinnabar-mc/bedrock-services/blob/dev/LICENSE) and
[third-party attribution](https://github.com/cinnabar-mc/bedrock-services/blob/dev/THIRD_PARTY_NOTICES.md). Independent of Mojang and Microsoft.
