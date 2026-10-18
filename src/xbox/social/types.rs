use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Relationship lists exposed by the concrete PeopleHub read API.
#[derive(Clone, Copy, Debug)]
pub enum PeopleList {
    /// Accepted friends, excluding pending requests.
    Friends,
    /// Accounts following the signed-in account.
    Followers,
    /// Accounts followed by the signed-in account.
    Following,
}

impl PeopleList {
    /// Encodes the selected relationship group without accepting arbitrary URL paths.
    pub(super) fn selector(self) -> &'static str {
        match self {
            Self::Friends => "friends",
            Self::Followers => "followers",
            Self::Following => "social",
        }
    }
}

/// Detail requested from PeopleHub; basic lists carry no implied online/offline state.
#[derive(Clone, Copy, Debug)]
pub enum ProfileDetail {
    /// Relationship and identity fields, without profile decorations.
    Basic,
    /// Profile, presence and multiplayer-summary decorations.
    Full,
}

/// Profile and relationship data returned by PeopleHub. Unknown fields are ignored.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct User {
    /// Network-wide Xbox identifier. Partial service rows may omit it.
    #[serde(default)]
    pub xuid: String,
    /// Legacy gamertag spelling returned by the service.
    #[serde(default)]
    pub gamertag: String,
    /// Display-name fallback when no gamertag is supplied.
    #[serde(default)]
    pub display_name: String,
    /// Display part of the modern gamertag.
    pub modern_gamertag: Option<String>,
    /// Disambiguation suffix of the modern gamertag.
    pub modern_gamertag_suffix: Option<String>,
    /// Fully qualified modern gamertag, including its suffix.
    pub unique_modern_gamertag: Option<String>,
    /// Privacy-filtered real name, when supplied.
    pub real_name: Option<String>,
    /// Raw gamerpic URL. Download and URL policy belong to the caller.
    #[serde(rename = "displayPicRaw")]
    pub display_picture: Option<String>,
    /// Accepted friendship state, or absent for undecorated/partial data.
    pub is_friend: Option<bool>,
    /// Whether the caller follows this account.
    pub is_followed_by_caller: Option<bool>,
    /// Whether this account follows the caller.
    pub is_following_caller: Option<bool>,
    /// Pending incoming friend-request state.
    pub is_friend_request_received: Option<bool>,
    /// Pending outgoing friend-request state.
    pub is_friend_request_sent: Option<bool>,
    /// Raw reported presence state; unknown values remain distinguishable from Offline.
    pub presence_state: Option<String>,
    /// Localized presence description, when decorated.
    pub presence_text: Option<String>,
    /// Title/device presence entries; unknown states remain raw strings.
    #[serde(default, deserialize_with = "nullable_list")]
    pub presence_details: Vec<UserPresence>,
    /// Nonnegative gamerscore, accepting service string or number forms.
    /// Missing or unrecognized well-formed values remain absent.
    #[serde(default, rename = "gamerScore", deserialize_with = "optional_integer")]
    pub gamerscore: Option<u64>,
    /// Optional title-defined multiplayer decoration, preserved without join inference.
    pub multiplayer_summary: Option<Value>,
}

impl User {
    /// Reports only an explicit Online state; the original optional state remains available.
    pub fn is_online(&self) -> bool {
        self.presence_state
            .as_deref()
            .is_some_and(|state| state.eq_ignore_ascii_case("Online"))
    }
}

/// A PeopleHub title/device decoration, distinct from the Presence API's device tree.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct UserPresence {
    /// Device name reported for this title.
    #[serde(alias = "device")]
    pub device: Option<String>,
    /// Optional device subtype, preserved without platform assumptions.
    #[serde(alias = "deviceSubType")]
    pub device_sub_type: Option<String>,
    /// Reported activity state, including unknown future values.
    #[serde(alias = "state")]
    pub state: Option<String>,
    /// Title identifier, accepting decimal text or numeric service forms.
    #[serde(
        default,
        rename = "TitleId",
        alias = "titleId",
        deserialize_with = "optional_integer"
    )]
    pub title_id: Option<u64>,
    /// Localized summary for the title.
    #[serde(alias = "presenceText")]
    pub presence_text: Option<String>,
    /// Localized in-title activity text.
    #[serde(alias = "richPresenceText")]
    pub rich_presence_text: Option<String>,
    /// Whether the service marks this entry as the displayed primary status.
    #[serde(rename = "IsPrimary", alias = "isPrimary")]
    pub primary: Option<bool>,
    /// Whether the service identifies the title as a game.
    #[serde(rename = "IsGame", alias = "isGame")]
    pub game: Option<bool>,
}

/// Full Presence API record. These observations do not authorize joining a session.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Presence {
    /// Xbox identity whose presence was returned.
    pub xuid: String,
    /// Raw service state; absent and unfamiliar states are preserved.
    pub state: Option<String>,
    /// Reported devices. A missing tree is treated as empty, without inferring Offline.
    #[serde(default, deserialize_with = "nullable_list")]
    pub devices: Vec<DevicePresence>,
    /// Most recently observed title, when retained by the service.
    pub last_seen: Option<LastSeen>,
}

/// Device-specific title observations.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
pub struct DevicePresence {
    /// Raw device type, including future platform names.
    #[serde(rename = "type")]
    pub device_type: Option<String>,
    /// Titles observed on this device.
    #[serde(default, deserialize_with = "nullable_list")]
    pub titles: Vec<TitlePresence>,
}

/// One title in a Presence API device tree.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
pub struct TitlePresence {
    /// Title identifier, when present.
    pub id: Option<u32>,
    /// Localized title name.
    pub name: Option<String>,
    /// Title-specific activity/media fields, preserved for downstream consumers.
    pub activity: Option<Value>,
}

/// Last-seen data; timestamps remain service text and are not credential clocks.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LastSeen {
    /// Last reported device type.
    pub device_type: Option<String>,
    /// Last reported title identifier.
    pub title_id: Option<u32>,
    /// Localized name of the title.
    pub title_name: Option<String>,
    /// Original service timestamp text.
    pub timestamp: Option<String>,
}

/// Multiplayer session locator retained for later joining or invitation operations.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SessionReference {
    /// Service configuration, when supplied by a complete reference.
    #[serde(rename = "scid")]
    pub service_config_id: Option<uuid::Uuid>,
    /// Session-template name, without case normalization.
    pub template_name: Option<String>,
    /// Session name, without case normalization.
    pub name: Option<String>,
}

/// Directory activity handle carrying session identity and title-defined metadata.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Activity {
    /// Handle identifier, when supplied.
    pub id: Option<uuid::Uuid>,
    /// Raw handle type, including unknown future kinds.
    #[serde(rename = "type")]
    pub handle_type: Option<String>,
    /// Locator for the corresponding multiplayer session.
    #[serde(rename = "sessionRef")]
    pub session: Option<SessionReference>,
    /// Xbox identity of the session owner.
    pub owner_xuid: Option<String>,
    /// Title identifier as returned by the directory.
    pub title_id: Option<String>,
    /// Reported invitation protocol, without transport inference.
    pub invite_protocol: Option<String>,
    /// Title-defined world/device metadata. No joinability defaults are added.
    pub custom_properties: Option<Value>,
    /// Platform/title associations preserved for downstream selection.
    pub game_types: Option<Value>,
    /// Optional session restrictions. Absence is not an open or joinable session.
    pub related_info: Option<ActivityInfo>,
}

/// Directory restrictions retained without deciding whether the caller can join.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ActivityInfo {
    /// Whether the session is closed to new joins; absent is unknown.
    pub closed: Option<bool>,
    /// Raw restriction, including unrecognized future values.
    pub join_restriction: Option<String>,
    /// Raw visibility policy, including unrecognized future values.
    pub visibility: Option<String>,
    /// Maximum reported membership, when provided.
    pub max_members_count: Option<u32>,
    /// Invitation protocol reported for the authenticated user.
    pub invite_protocol: Option<String>,
}

/// Reads only a representable nonnegative integer while tolerating unrelated valid JSON values.
fn optional_integer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    Ok(value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok())))
}

/// Accepts the service's missing/null list representation without inventing member records.
pub(super) fn nullable_list<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}
