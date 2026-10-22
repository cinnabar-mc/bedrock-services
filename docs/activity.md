# Publish activity and clean it up

Presence, directory membership, discoverable activity, and invitations are
separate writes. Your application chooses when to publish them and owns their
cleanup. Reading social or invitation data does not authorize a game join.

A canceled HTTP write may have reached the service. Keep the operation's local
state so you can reconcile that result; dropping a borrowed service view does
not undo remote changes.

## Publish title presence

The authenticated title determines which presence is updated. This helper marks
local dispatch so the application can retain uncertainty across cancellation:

```rust,no_run
use bedrock_services::{
    Error,
    xbox::{Account, presence::{State, TitleUpdate, UpdateResult}},
};

async fn mark_active(
    account: &mut Account,
    dispatched: &mut bool,
) -> Result<UpdateResult, Error> {
    let update = TitleUpdate::new(State::Active);
    account.title_presence()
        .update_with_dispatch(&update, || *dispatched = true).await
}

async fn remove_presence(account: &mut Account) -> Result<(), Error> {
    account.title_presence().remove().await
}
```

Keep `dispatched` in application state outside a cancelable operation. The callback
runs after request preparation and final signing, before HTTP dispatch; it means
the write could apply, not that it succeeded. `update` is also available without
a callback. Both can retry throttled/unavailable replies within their HTTP budget.

Use `UpdateResult::heartbeat_after` to schedule the next explicit heartbeat, with
a fallback chosen by your app. There is no heartbeat task. `RichPresence` accepts
a title-defined ID, service configuration, and bounded substitution parameters.

On shutdown, call `remove()` even if the preceding update failed or was canceled.
It sends once without relying on a local success flag. A failed or canceled
removal can also be uncertain; keep that cleanup obligation visible to your app.

## Prepare directory membership

A Multiplayer Session Directory membership needs a validated `Reference` and a
current RTA `Binding`. Obtain the actual RTA connection from its initial directory
snapshot, then combine it with your stable per-session subscription UUID using
`connection.directory_binding`. See [RTA setup](realtime.md#subscribe-to-xbox-rta).
Do not invent a connection UUID from social metadata.

For cancellation-sensitive creation, retain a `PublishAttempt` before awaiting
its creation write. This helper selects explicit followed-user restrictions:

```rust,no_run
use bedrock_services::xbox::{
    Account,
    mpsd::{self, Binding, MemberData, Publish, PublishAttempt, Reference, Restriction},
};

fn prepare_host(
    account: &mut Account,
    reference: &Reference,
    binding: Binding,
) -> Result<PublishAttempt, mpsd::Error> {
    account.mpsd().publish_attempt(reference, Publish {
        binding,
        member: MemberData::default(),
        constants: None,
        max_members: None,
        properties: None,
        join: Restriction::Followed,
        read: Restriction::Followed,
    })
}
```

Then call `account.mpsd().publish_retained(&mut attempt).await`. A successful
result returns the `Session` you must retain. The creation uses `If-None-Match: *`;
it does not overwrite an existing session, publish activity, or send invitations.
Call `publish_activity(&session)` and `invite` separately when needed. Retain the
session even if one of those later operations fails.

## Recover an uncertain creation

1. Keep the same `PublishAttempt`, reference, binding, and account proof after
   cancellation or failure. Final signed dispatch permits only that one creation
   write; do not create a replacement intent just because its response was lost.
2. Check `attempt.needs_reconciliation()`. An observed 412 is a known rejection;
   a dispatched uncertain write needs recovery.
3. Call `reconcile_publish(&mut attempt)`. It adopts only the exact original
   active membership with its original binding and a concrete validator.
4. Keep the obligation if reconciliation fails. A 404 does not rule out a
   still-applying request; a replaced binding is not yours to delete.
5. After recovery, either continue with the returned session or perform guarded
   cleanup. Your application owns the recovery deadline and storage/lifetime.

## Refresh and leave an owned session

Session methods enforce the account/proof owner and use conditional validators.
An uncertain write or conflict requires `sync` before another mutation. Fresh
snapshots replace the whole member map. Compare change numbers only on the same
branch; a new branch has a separate sequence.

For cleanup tied to the original RTA binding:

```rust,no_run
use bedrock_services::xbox::{
    Account,
    mpsd::{self, Binding, Session, Update},
};

async fn leave_original_membership(
    account: &mut Account,
    session: &mut Session,
    original_binding: Binding,
) -> Result<Update, mpsd::Error> {
    let mut directory = account.mpsd();
    if matches!(directory.sync(session).await?, Update::Closed) {
        return Ok(Update::Closed);
    }
    directory.leave_bound(session, original_binding).await
}
```

`leave_bound` refuses a replacement binding or missing validator. The retained
binding can support cleanup after its RTA socket ends. A successful leave or
observed remote deletion closes the local owner. Session `Drop` sends nothing.
`set_properties_bound` similarly requires the active original binding and a
validator for title admission updates; a conflict needs refresh.

After RTA reconnect, explicitly bind the membership to the new current connection
and refresh it before further work. Directory shoulder taps request a refresh;
they are not complete session snapshots or title admission decisions.

## Join from an activity or invitation

`read_handle` previews the handle's resolved session without creating membership.
Validate its reference, selected title, intended recipient, and original expiry
before joining. Retain those observations for validation of the joined snapshot.

Create one `JoinAttempt` with the selected handle and actual RTA binding, then
call `join`. Only a returned `JoinOutcome::Precondition` permits another attempt;
wait its suggested delay and retain the same intent. `Exhausted` ends that intent.
Other errors and canceled writes can have applied remotely, so reconcile ownership
and clean up before considering another join. The SDK does not start a game
connection or a join retry worker.

Title-owned custom data can contain private admission nonces. Keep it, protected
headers, and invitation/session identifiers out of routine logs. Retire account
state on sign-out so old completions cannot mutate the newly selected account.
