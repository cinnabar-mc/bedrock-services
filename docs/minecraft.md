# Use Minecraft and social services

Start with a signed-in or [restored account](accounts.md). Move it into one
`Minecraft` owner for Minecraft-specific services. Supply the game version and
protocol number from your protocol implementation, plus a persistent nonnil
device UUID. Keep the same configuration when restoring a checkpoint.

## Mint a multiplayer token

Add the public-key and UUID types used by your application:

```sh
cargo add p384@0.14 --features ecdsa
cargo add uuid --features v4
```

Your connection layer generates and retains its P-384 private key. This helper
borrows the matching public key, creates the service owner, and returns both
owner and token so later calls can reuse the account state:

```rust,no_run
use bedrock_services::{
    Error,
    minecraft::{Config, Minecraft, MultiplayerToken},
    xbox::Account,
};
use p384::ecdsa::VerifyingKey;
use uuid::Uuid;

async fn mint_for_connection(
    account: Account,
    game_version: &str,
    protocol: u32,
    persistent_device_id: Uuid,
    connection_key: &VerifyingKey,
) -> Result<(Minecraft, MultiplayerToken), Error> {
    let config = Config::desktop(game_version, protocol, persistent_device_id);
    let mut services = Minecraft::new(account, config)?;
    let token = services.multiplayer_token(connection_key).await?;
    Ok((services, token))
}
```

Use `token.as_str()` in your Login/transport identity integration. Keep the same
private key through client-data signing and server key exchange. The library
never generates or replaces that key. `expires_at()` is the original hard expiry;
use `valid(services.service_time())` before handing it to Login. Carry that
absolute expiry through delayed signaling rather than restarting a duration.

Minecraft discovers its service routes, acquires Xbox/PlayFab credentials as
needed, and reuses current credentials. A rejected multiplayer mint invalidates
its exact issuance and retries once with a replacement. A token response does
not verify another game peer's identity. The game packet connection belongs to
your networking layer.

## List Realms

A Realms view borrows the same account and service state:

```rust,no_run
use bedrock_services::{minecraft::Minecraft, realms};

async fn list_realms(services: &mut Minecraft) -> Result<(), realms::Error> {
    let mut realms = services.realms().await?;
    for realm in realms.list().await? {
        println!("{}: {}", realm.id, realm.name);
    }
    Ok(())
}
```

Listing does not accept invitations or start a connection. To show an invite,
call `preview_invite(code)`; use the separate `accept_invite(code)` call only
when the user chooses to accept. `details(id)` and `pending_invites()` provide
additional reads.

## Resolve a selected Realm

Call `join` only for the Realm the user selected. One call makes one join attempt:

```rust,no_run
use bedrock_services::{
    minecraft::Minecraft,
    realms::{self, Join},
};
use std::num::NonZeroU64;

async fn resolve_realm(
    services: &mut Minecraft,
    realm_id: NonZeroU64,
) -> Result<(), realms::Error> {
    match services.realms().await?.join(realm_id, &[]).await? {
        Join::Ready(address) => println!("NetherNet JSON-RPC: {}", address.address),
        Join::Pending { retry_after } => {
            println!("retry this selected Realm after {retry_after:?}");
        }
        _ => eprintln!("unsupported join response"),
    }
    Ok(())
}
```

Schedule `Pending` retries yourself, within your own overall deadline. Canceling
a join future cancels its HTTP work. Supply measured `PingResult`s instead of
`&[]` if your application measures region latency. Only `NETHERNET_JSONRPC`
assignments are joinable; other protocols return an unsupported network error.
The returned address is the NetherNet identity.

The owner retains negotiated Realms version state between views; selected version
rejections can trigger bounded version negotiation. Missing optional Realms
discovery fails Realms calls without preventing authentication-only operations.

## Read friends and presence

Social reads work directly on an Xbox account; a `Minecraft` owner also offers
`social()` with the same interface:

```rust,no_run
use bedrock_services::{
    Error,
    xbox::{Account, social::{PeopleList, ProfileDetail}},
};

async fn print_friends(account: &mut Account) -> Result<(), Error> {
    let friends = account.social()
        .people(PeopleList::Friends, ProfileDetail::Full).await?;
    for friend in friends {
        println!("{}: {:?}", friend.gamertag, friend.presence_state);
    }
    Ok(())
}
```

Use `current_profile`, `profile`, `current_presence`, or `presences` for specific
reads. Choose `ProfileDetail::Basic` when decorations are unnecessary. Missing
presence is not proof that a friend is offline; unknown states remain available.
`with_language` chooses a preferred language for a borrowed view.

`social().activities(service_config, users)` reads multiplayer activity metadata.
Use `minecraft::SERVICE_CONFIG_ID` for the crate's Minecraft service configuration.
Session references and restrictions still need application validation before
joining. Read calls do not subscribe to changes or create membership.

## Browse catalogs and other account data

`services.gatherings().await?.search_items(&SearchFilter::default()).await`
returns one catalog page in service order. Supply the response's continuation
in the next filter to request another page. Your application selects language,
visibility, supported item types, sorting, and artwork. `CatalogItem::properties`
decodes known display/connection properties for one item; a malformed card can
be skipped without losing its neighbors.

Catalog reads and `player_counts` do not allocate a game server. Player counts
retain a cached snapshot and throttle completed refresh attempts; missing or
negative counts remain distinct from zero. `join_experience(id)` is a separate
allocation request with no automatic retry. A failed or canceled allocation can
have an uncertain result: observe it before making another allocation.

Additional views reuse the same account instead of creating another sign-in:

| Task | View |
| --- | --- |
| Read Xbox game invitations without accepting or dismissing them | `notifications().game_invites()` |
| Read explicit statistics selections or achievement progress | `statistics()` / `achievements()` |
| Fetch Minecraft persona image bytes or showcase metadata | `profile()` |
| Refresh Minecraft marketing/inbox messages | `player_messaging().refresh(language)` |

Profile image bytes still need your decoder and cache policy; returned image URLs
are not credential destinations. Achievement pagination is bounded and does not
fetch artwork. Missing statistics/scores are not synthesized as zero.

The Minecraft inbox keeps its own messaging session and continuation. Refreshing
does not mark/delete messages; `report_events` records explicit interactions with
the original message/button IDs. Your application orders those writes and handles
uncertain results. This inbox is separate from Xbox invitations and the
[NetherNet signaling service](realtime.md).
