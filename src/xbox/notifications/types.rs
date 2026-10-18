use super::{CATEGORY, INVITE_TYPE, MAX_INBOX_ACTIONS};
use crate::Error;
use serde::{Deserialize, Deserializer, de};
use serde_json::Value;
use std::{
    collections::HashMap,
    time::{Instant, SystemTime},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

/// One explicit inbox response, bound to its authenticated recipient.
/// Service metadata is untrusted and this owner establishes no session membership.
pub struct Inbox {
    owner: String,
    observed_time: SystemTime,
    observed_at: Instant,
    /// Supported invitation notifications in service order.
    pub invites: Vec<GameInvite>,
    /// Malformed items skipped without discarding valid neighboring notifications.
    pub malformed_items: usize,
    /// Well-formed keys with unsupported notification category/type, skipped without interpretation.
    pub unsupported_items: usize,
}

impl Inbox {
    /// Retains the exact authenticated recipient and the HTTP edge's original clock sample.
    pub(super) fn new(owner: String, observed_time: SystemTime, observed_at: Instant) -> Self {
        Self {
            owner,
            observed_time,
            observed_at,
            invites: Vec::new(),
            malformed_items: 0,
            unsupported_items: 0,
        }
    }

    /// Returns the authenticated account whose inbox was read, not an invitation actor.
    pub fn owner_xuid(&self) -> &str {
        &self.owner
    }

    /// Returns the service-corrected UTC sample taken when this response was decoded.
    pub fn observed_time(&self) -> SystemTime {
        self.observed_time
    }

    /// Returns the paired monotonic anchor for preserving original invitation deadlines.
    pub fn observed_at(&self) -> Instant {
        self.observed_at
    }
}

/// A game invitation notification; its actions remain untrusted selection metadata.
pub struct GameInvite {
    /// Service subscription identifier, distinct from every action and MPSD handle.
    pub subscription_id: String,
    /// Title location and platform metadata reported for this notification.
    pub options: InviteOptions,
    /// Actions array followed by an optional singleton Action, in service order.
    pub actions: Vec<InviteAction>,
    /// Service-reported actions omitted from this response.
    pub other_action_count: u64,
    /// Whether the service reports that this notification has been marked read.
    pub marked_read: bool,
    /// Whether the service reports that this notification has been seen.
    pub seen: bool,
}

/// Notification options, without title-specific acceptance policy.
#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InviteOptions {
    /// Launch location; kind and title identity must be checked by the application.
    #[serde(default)]
    pub location: Location,
    /// Reported platform names, including unknown future platforms.
    #[serde(default)]
    pub platforms: Vec<String>,
}

/// A service-reported title or other launch location. URLs are display metadata only.
#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Location {
    /// Location identifier; kind 3 reports a title ID.
    #[serde(default, rename = "Id")]
    pub id: String,
    /// Service location type, retaining unknown numeric values.
    #[serde(default, rename = "Type")]
    pub kind: u32,
    /// Display name, never a session reference.
    #[serde(default)]
    pub name: String,
    /// Reported package family name.
    #[serde(default, rename = "Pfn")]
    pub package_family_name: String,
    /// Reported title image; the SDK does not fetch it.
    #[serde(default)]
    pub display_image: String,
}

/// One invitation action. The actor is not necessarily the session's host.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InviteAction {
    /// Actor reported for this action, normally the inviter.
    #[serde(default)]
    pub actor: Actor,
    /// Service action identifier, distinct from the MPSD handle.
    #[serde(default, rename = "ActionId")]
    pub action_id: String,
    /// Optional creation time; invitation expiry comes from LaunchInfo instead.
    #[serde(
        default,
        rename = "ActionTime",
        deserialize_with = "optional_timestamp"
    )]
    pub created_at: Option<SystemTime>,
    /// Handle, original expiry and per-platform title metadata.
    pub launch_info: LaunchInfo,
}

/// Reported action actor. Kind 1 identifies a user; other kinds remain uninterpreted.
#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Actor {
    /// Actor identity; for kind 1 this is the inviter's XUID, not the inbox recipient.
    #[serde(default, rename = "Id")]
    pub id: String,
    /// Service actor type, retaining unknown numeric values.
    #[serde(default, rename = "Type")]
    pub kind: u32,
    /// Reported display name.
    #[serde(default)]
    pub name: String,
    /// Classic Xbox gamertag.
    #[serde(default, rename = "ClassicGamertag")]
    pub classic_gamertag: String,
    /// Base portion of the modern gamertag.
    #[serde(default, rename = "ModernGamertag")]
    pub modern_gamertag: String,
    /// Modern gamertag's numeric suffix.
    #[serde(default, rename = "ModernGamertagSuffix")]
    pub modern_gamertag_suffix: String,
    /// Fully qualified modern gamertag reported by the service.
    #[serde(default, rename = "UniqueModernGamertag")]
    pub unique_modern_gamertag: String,
}

/// Untrusted invitation launch metadata. Resolving this handle creates no membership.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchInfo {
    /// Non-nil MPSD handle to resolve and later join under the actual account owner.
    #[serde(rename = "mpsdHandleId")]
    pub handle: Uuid,
    /// Original absolute service expiry; callers must not reset it during refresh or retry.
    #[serde(rename = "expirationTime", deserialize_with = "timestamp")]
    pub expires: SystemTime,
    /// Decoded escaped JSON indexed by platform name, including unknown platforms.
    #[serde(default, deserialize_with = "game_types")]
    pub game_types: HashMap<String, GameType>,
}

/// Title metadata for one platform, without a platform preference or admission policy.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GameType {
    /// Service title identifier.
    #[serde(default)]
    pub title_id: String,
    /// Package family name for this platform.
    #[serde(default, rename = "pfn")]
    pub package_family_name: String,
    /// Other reported package family names.
    #[serde(default, rename = "boundPfns")]
    pub bound_package_family_names: Vec<String>,
}

/// Classifies an item key before interpreting supported invitation data.
pub(super) fn decode(item: Value) -> Result<Option<GameInvite>, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Key {
        subscription_category: String,
        subscription_type: String,
        #[serde(default, rename = "ActionId")]
        action_id: String,
    }
    let key = Key::deserialize(&item).map_err(|_| Error::Invalid("notification key"))?;
    if key.subscription_category.is_empty()
        || key.subscription_type.is_empty()
        || !key.action_id.is_empty()
    {
        return Err(Error::Invalid("notification key"));
    }
    if key.subscription_category != CATEGORY || key.subscription_type != INVITE_TYPE {
        return Ok(None);
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Invite {
        #[serde(default, rename = "SubscriptionId")]
        subscription_id: String,
        #[serde(default, rename = "NotificationOptions")]
        options: InviteOptions,
        #[serde(default)]
        actions: Option<Vec<InviteAction>>,
        #[serde(default)]
        action: Option<InviteAction>,
        #[serde(default)]
        other_action_count: u64,
        #[serde(default)]
        marked_read: bool,
        #[serde(default)]
        seen: bool,
    }
    let invite: Invite =
        serde_json::from_value(item).map_err(|_| Error::Invalid("game invitation"))?;
    let mut actions = invite.actions.unwrap_or_default();
    if actions.len() > MAX_INBOX_ACTIONS {
        return Err(Error::Invalid("notification action count"));
    }
    actions.extend(invite.action);
    if actions.is_empty()
        || actions
            .iter()
            .any(|action| action.launch_info.handle.is_nil())
    {
        return Err(Error::Invalid("game invitation actions"));
    }
    Ok(Some(GameInvite {
        subscription_id: invite.subscription_id,
        options: invite.options,
        actions,
        other_action_count: invite.other_action_count,
        marked_read: invite.marked_read,
        seen: invite.seen,
    }))
}

/// Parses an RFC3339 UTC instant with checked platform conversion and redacted diagnostics.
fn parse_timestamp(value: &str) -> Result<SystemTime, &'static str> {
    let value = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| "notification timestamp")?;
    let delta = value - OffsetDateTime::UNIX_EPOCH;
    if delta.is_negative() {
        SystemTime::UNIX_EPOCH.checked_sub(delta.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH.checked_add(delta.unsigned_abs())
    }
    .ok_or("notification timestamp range")
}

/// Decodes required service expiry without retaining its raw string in errors.
fn timestamp<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
    parse_timestamp(&String::deserialize(deserializer)?).map_err(de::Error::custom)
}

/// Keeps absent action creation times distinct from the invitation's required expiry.
fn optional_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SystemTime>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_timestamp(&value).map_err(de::Error::custom))
        .transpose()
}

/// Decodes the service's JSON-in-a-string form without treating it as a URL or launch command.
fn game_types<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<String, GameType>, D::Error> {
    let encoded = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
    if encoded.is_empty() {
        return Ok(HashMap::new());
    }
    serde_json::from_str::<Option<HashMap<String, GameType>>>(&encoded)
        .map(Option::unwrap_or_default)
        .map_err(|_| de::Error::custom("invitation game types"))
}
