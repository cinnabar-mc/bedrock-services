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
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkProtocol {
    /// NetherNet with JSON-RPC signaling.
    NetherNetJsonRpc,
    /// An unsupported service protocol, retained without enabling a join.
    Unknown(String),
}

impl Default for NetworkProtocol {
    /// Treats an absent protocol as unsupported rather than selecting a transport.
    fn default() -> Self {
        Self::Unknown(String::new())
    }
}

/// A validated service assignment reached through Player Messaging JSON-RPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinTarget<'a> {
    nethernet_id: &'a str,
}

impl<'a> JoinTarget<'a> {
    /// Returns the trimmed service routing identity without imposing numeric or UUID syntax.
    pub fn nethernet_id(self) -> &'a str {
        self.nethernet_id
    }
}

impl NetworkProtocol {
    /// Resolves both service address forms through one supported-protocol and identity rule.
    pub(crate) fn target<'a>(&self, id: &'a str) -> Result<JoinTarget<'a>, crate::Error> {
        match self {
            Self::NetherNetJsonRpc => {
                let nethernet_id = id.trim();
                if nethernet_id.is_empty() {
                    return Err(crate::Error::Invalid("service join NetherNet ID"));
                }
                Ok(JoinTarget { nethernet_id })
            }
            Self::Unknown(_) => Err(crate::Error::UnsupportedNetworkProtocol),
        }
    }
}

impl<'de> Deserialize<'de> for NetworkProtocol {
    /// Normalizes known service names while retaining unsupported values.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let protocol = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        let protocol = protocol.trim();
        Ok(match protocol.to_ascii_uppercase().as_str() {
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
    /// NetherNet network identity returned by the service.
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

impl RealmAddress {
    /// Resolves the response's supported transport and trimmed routing identity.
    pub fn target(&self) -> Result<JoinTarget<'_>, crate::Error> {
        self.network_protocol.target(&self.address)
    }

    /// Returns the JSON-RPC routing identity, rejecting blank IDs and unsupported protocols.
    pub fn nethernet_id(&self) -> Result<&str, crate::Error> {
        Ok(self.target()?.nethernet_id())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Both services resolve the same normalized identity and refuse every other protocol.
    #[test]
    fn service_targets_share_protocol_and_identity_rules() {
        for protocol in [
            serde_json::Value::Null,
            json!(""),
            json!("DEFAULT"),
            json!("NETHERNET"),
            json!("FUTURE"),
            json!(" nethernet_jsonrpc "),
        ] {
            for id in [
                "42",
                " opaque:identifier ",
                " e7032735-bd67-45b0-810e-c6760ec87b91 ",
                " ",
            ] {
                let realm: RealmAddress =
                    serde_json::from_value(json!({"address":id,"networkProtocol":protocol}))
                        .unwrap();
                let gathering: crate::minecraft::gatherings::JoinAddress =
                    serde_json::from_value(json!({"netherNetId":id,"networkProtocol":protocol}))
                        .unwrap();
                let supported = protocol == json!(" nethernet_jsonrpc ");
                let expected = supported && !id.trim().is_empty();
                assert_eq!(realm.target().is_ok(), expected);
                assert_eq!(gathering.target().is_ok(), expected);
                assert_eq!(realm.nethernet_id().is_ok(), expected);
                if expected {
                    assert_eq!(realm.target().unwrap().nethernet_id(), id.trim());
                    assert_eq!(gathering.target().unwrap().nethernet_id(), id.trim());
                    assert_eq!(realm.nethernet_id().unwrap(), id.trim());
                } else if !supported {
                    assert!(matches!(
                        realm.target(),
                        Err(crate::Error::UnsupportedNetworkProtocol)
                    ));
                    assert!(matches!(
                        gathering.target(),
                        Err(crate::Error::UnsupportedNetworkProtocol)
                    ));
                }
            }
        }
    }

    /// Unsupported protocol names remain readable but cannot become joinable addresses.
    #[test]
    fn only_jsonrpc_assignments_pass_join_validation() {
        for protocol in [
            None,
            Some(""),
            Some("DEFAULT"),
            Some("NETHERNET"),
            Some("FUTURE"),
        ] {
            let mut value = json!({"address":"42"});
            if let Some(protocol) = protocol {
                value["networkProtocol"] = json!(protocol);
            }
            let address: RealmAddress = serde_json::from_value(value.clone()).unwrap();
            assert!(matches!(
                address.network_protocol,
                NetworkProtocol::Unknown(_)
            ));
            assert!(matches!(
                address.target(),
                Err(crate::Error::UnsupportedNetworkProtocol)
            ));
            let assignment: crate::minecraft::gatherings::JoinAddress =
                serde_json::from_value(value).unwrap();
            assert_eq!(assignment.network_protocol, address.network_protocol);
        }
        for protocol in ["NETHERNET_JSONRPC", " nethernet_jsonrpc "] {
            let address: RealmAddress = serde_json::from_value(json!({
                "address":"42", "networkProtocol":protocol
            }))
            .unwrap();
            assert_eq!(address.network_protocol, NetworkProtocol::NetherNetJsonRpc);
            address.target().unwrap();
        }
    }
}
