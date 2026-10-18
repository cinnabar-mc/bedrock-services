//! Realms catalog metadata and explicit transport selection.

use serde::{Deserialize, Deserializer, Serialize};
use std::{num::NonZeroU64, time::Duration};

/// A catalog entry; browsing does not resolve a connection or accept an invitation.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct Realm {
    /// Positive identifier used by detail and join requests.
    pub id: NonZeroU64,
    /// Display name of the Realm.
    #[serde(default)]
    pub name: String,
    /// Owner display name, when supplied.
    #[serde(default)]
    pub owner: String,
    /// Owner's Xbox identifier.
    #[serde(default, rename = "ownerUUID")]
    pub owner_xuid: String,
    /// Server description, when supplied.
    #[serde(default)]
    pub motd: String,
    /// Service state, retained for future states such as OPEN and CLOSED.
    #[serde(default)]
    pub state: String,
    /// Current world category.
    #[serde(default)]
    pub world_type: String,
    /// Maximum players reported by the service.
    #[serde(default)]
    pub max_players: u32,
    /// Days remaining before renewal, when visible to this account.
    #[serde(default)]
    pub days_left: i32,
    /// Whether the subscription has expired.
    #[serde(default)]
    pub expired: bool,
    /// Membership flag supplied by the service.
    #[serde(default)]
    pub member: bool,
    /// Player metadata, generally supplied only by a detail request.
    #[serde(default, deserialize_with = "players")]
    pub players: Vec<Player>,
}

/// Player metadata returned with Realm details.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct Player {
    /// Service player identifier.
    #[serde(default)]
    pub uuid: String,
    /// Player display name.
    #[serde(default, rename = "Name", alias = "name")]
    pub name: String,
    /// Operator permission reported by the service.
    #[serde(default)]
    pub operator: bool,
    /// Whether the invitation has been accepted.
    #[serde(default)]
    pub accepted: bool,
    /// Whether the player is currently online.
    #[serde(default)]
    pub online: bool,
    /// Permission name, including any newer service value.
    #[serde(default)]
    pub permission: String,
}

/// Allows a null player list without losing the non-null public collection contract.
fn players<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Player>, D::Error> {
    Ok(Option::<Vec<Player>>::deserialize(deserializer)?.unwrap_or_default())
}

/// A measured region latency supplied by the caller; an empty slice sends an empty array.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResult {
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
    /// Service region identifier.
    pub region: String,
}

/// A transport advertised by Realms; unknown values are preserved for explicit rejection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkProtocol {
    /// UDP RakNet, also used for an absent or empty protocol field.
    #[default]
    Default,
    /// NetherNet with WebSocket signaling.
    NetherNet,
    /// NetherNet with JSON-RPC signaling.
    NetherNetJsonRpc,
    /// A newer or unsupported service protocol, never treated as RakNet.
    Unknown(String),
}

impl<'de> Deserialize<'de> for NetworkProtocol {
    /// Normalizes known service names while retaining unsupported values.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let protocol = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        let protocol = protocol.trim();
        Ok(match protocol.to_ascii_uppercase().as_str() {
            "" | "DEFAULT" => Self::Default,
            "NETHERNET" => Self::NetherNet,
            "NETHERNET_JSONRPC" => Self::NetherNetJsonRpc,
            _ => Self::Unknown(protocol.to_owned()),
        })
    }
}

/// A resolved address and the transport required to use it.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct RealmAddress {
    /// RakNet host/port or NetherNet network identity, retained without IPv6 rewriting.
    pub address: String,
    /// Transport and signaling selection returned by the service.
    #[serde(default)]
    pub network_protocol: NetworkProtocol,
    /// Whether the service reports an update pending for this Realm.
    #[serde(default)]
    pub pending_update: bool,
    /// Optional service region selection metadata.
    #[serde(default, rename = "sessionRegionData")]
    pub session_region: Option<SessionRegion>,
}

/// Region information reported after the service chooses a Realm instance.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct SessionRegion {
    /// Selected region name.
    #[serde(default)]
    pub region_name: String,
    /// Quality value supplied by the service.
    #[serde(default)]
    pub service_quality: i32,
}

/// The outcome of one join request, without sleeping or retrying in the background.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Join {
    /// The service returned connection details, including its exact protocol.
    Ready(RealmAddress),
    /// The Realm is not ready; retry no earlier than this duration after receipt.
    Pending {
        /// Service-provided Retry-After delay, including a possible zero delay.
        retry_after: Duration,
    },
}
