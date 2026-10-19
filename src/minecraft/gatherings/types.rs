use crate::{Error, realms::NetworkProtocol};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt, marker::PhantomData};
use uuid::Uuid;

/// One explicit PlayFab-shaped catalog query; empty defaults encode as an empty object.
#[derive(Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SearchFilter {
    /// Optional result count, from one through fifty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// Original opaque continuation for an explicit next-page request.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub continuation_token: String,
    /// Optional OData expression, passed to the service without local interpretation.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub filter: String,
    /// Locale requested in returned dictionaries, separate from the search header.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub language: String,
    /// Optional OData ordering expression.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub order_by: String,
    /// Search terms.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub search: String,
    /// Optional field selection.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub select: String,
}

/// One ordered page; no implicit pagination, sorting, hiding or localization is applied.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct SearchResult {
    /// Opaque server continuation, not a URL to follow.
    #[serde(deserialize_with = "null_default")]
    pub continuation_token: String,
    /// Original item order, including hidden and unsupported content types.
    #[serde(deserialize_with = "object_list")]
    pub items: Vec<CatalogItem>,
}

/// Display metadata from the PlayFab-shaped gatherings catalog, never connection approval.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct CatalogItem {
    /// Service item identifier, distinct from its experience ID.
    #[serde(rename = "Id", deserialize_with = "null_default")]
    pub id: String,
    /// Title-defined item type; applications decide which types they support.
    #[serde(deserialize_with = "null_default")]
    pub content_type: String,
    /// Service visibility flag.
    #[serde(rename = "IsHidden", deserialize_with = "null_default")]
    pub hidden: bool,
    /// Original locale keys and text, without guessed fallback.
    #[serde(deserialize_with = "null_default")]
    pub title: BTreeMap<String, String>,
    /// Original locale keys and description text.
    #[serde(deserialize_with = "null_default")]
    pub description: BTreeMap<String, String>,
    /// Untrusted image URLs; this service never fetches them.
    #[serde(deserialize_with = "object_list")]
    pub images: Vec<Image>,
    /// Exact optional title-specific JSON, allowing malformed card properties to be skipped locally.
    pub display_properties: Option<Box<RawValue>>,
}

impl CatalogItem {
    /// Parses this card's known properties without changing the original raw metadata or listing.
    ///
    /// # Errors
    /// Rejects absent/nonobject properties or malformed known values; unrelated cards remain usable.
    pub fn properties(&self) -> Result<DisplayProperties, Error> {
        let raw = self
            .display_properties
            .as_ref()
            .ok_or(Error::Invalid("gatherings display properties"))?;
        serde_json::from_str::<Object<DisplayProperties>>(raw.get())
            .map(|value| value.0)
            .map_err(|_| Error::Invalid("gatherings display properties"))
    }
}

/// A catalog image selected by tag/type independently of its URL.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Image {
    /// Service image identifier.
    #[serde(rename = "Id", deserialize_with = "null_default")]
    pub id: String,
    /// Display role, for example an icon or banner.
    #[serde(deserialize_with = "null_default")]
    pub tag: String,
    /// Service image category.
    #[serde(rename = "Type", deserialize_with = "null_default")]
    pub kind: String,
    /// Untrusted image location, retained without fetching.
    #[serde(rename = "Url", deserialize_with = "null_default")]
    pub url: String,
}

/// Known title properties; unknown metadata remains in the original card's raw JSON.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DisplayProperties {
    /// Experience selection text; applications require a nonnil UUID before explicit join.
    #[serde(deserialize_with = "null_default")]
    pub experience_id: String,
    /// Optional direct server host, not a complete URL or authorized HTTP destination.
    #[serde(rename = "url", deserialize_with = "null_default")]
    pub host: String,
    /// Optional direct server port; zero means no direct endpoint.
    #[serde(deserialize_with = "null_default")]
    pub port: u16,
    /// Presence determines ranked/creator grouping; zero is a real rank.
    pub rank: Option<i64>,
    /// News headline.
    #[serde(deserialize_with = "null_default")]
    pub news_title: String,
    /// News body.
    #[serde(deserialize_with = "null_default")]
    pub news: String,
    /// Advertised activities in original order.
    #[serde(deserialize_with = "object_list")]
    pub available_games: Vec<AvailableGame>,
    /// Display creator name, not authenticated account identity.
    #[serde(deserialize_with = "null_default")]
    pub creator_name: String,
    /// Original service creator identifier.
    #[serde(deserialize_with = "null_default")]
    pub original_creator_id: String,
    /// Informational lower client-version label.
    #[serde(deserialize_with = "null_default")]
    pub min_client_version: String,
    /// Informational upper client-version label, never a protocol acceptance rule.
    #[serde(deserialize_with = "null_default")]
    pub max_client_version: String,
    /// Service's string-encoded Xbox requirement label.
    #[serde(rename = "requireXBL", deserialize_with = "null_default")]
    pub require_xbl: String,
    /// Marketplace identifier, never opened by the SDK.
    #[serde(rename = "storePageId", deserialize_with = "null_default")]
    pub store_page_id: String,
    /// Original optional allow-list metadata, not an SDK egress override.
    #[serde(rename = "whitelistUrl", deserialize_with = "null_default")]
    pub whitelist_url: String,
    /// Original optional allow-list metadata.
    #[serde(rename = "allowListUrl", deserialize_with = "null_default")]
    pub allow_list_url: String,
}

/// One advertised mode/activity, without implicit image resolution.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AvailableGame {
    /// Activity title.
    #[serde(deserialize_with = "null_default")]
    pub title: String,
    /// Activity subtitle.
    #[serde(deserialize_with = "null_default")]
    pub subtitle: String,
    /// Activity description.
    #[serde(deserialize_with = "null_default")]
    pub description: String,
    /// Tag selecting an image in the parent card.
    #[serde(deserialize_with = "null_default")]
    pub image_tag: String,
}

/// An experience population; missing and negative values stay distinct from zero.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperiencePlayerCount {
    /// Original experience identifier.
    pub experience_id: Uuid,
    /// Optional signed service count; callers own display policy.
    #[serde(default)]
    pub player_count: Option<i64>,
}

/// Actual result of an explicit join, separate from untrusted catalog display properties.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct JoinAddress {
    /// Original service transport, including unknown variants for caller refusal.
    pub network_protocol: NetworkProtocol,
    /// Direct UDP server host, only for the default transport.
    #[serde(rename = "ipV4Address", deserialize_with = "null_default")]
    pub ip_v4_address: String,
    /// Original NetherNet routing identity; callers apply the selected signaling dialect.
    #[serde(rename = "netherNetId", deserialize_with = "null_default")]
    pub nethernet_id: String,
    /// Direct UDP port, only for the default transport.
    #[serde(deserialize_with = "null_default")]
    pub port: u16,
    /// Original destination metadata, not a replacement account or proof.
    #[serde(deserialize_with = "null_object")]
    pub destination_info: DestinationInfo,
}

impl JoinAddress {
    /// Validates required fields for known transports without treating an unknown protocol as UDP.
    pub(super) fn validate(&self) -> Result<(), Error> {
        let valid = match self.network_protocol {
            NetworkProtocol::Default => !self.ip_v4_address.trim().is_empty() && self.port != 0,
            NetworkProtocol::NetherNet | NetworkProtocol::NetherNetJsonRpc => {
                !self.nethernet_id.trim().is_empty()
            }
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Invalid("gatherings join address"))
        }
    }
}

/// Opaque destination identifiers and labels from the original explicit join response.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DestinationInfo {
    /// Creator identifier supplied by the service.
    #[serde(rename = "creatorId", deserialize_with = "null_default")]
    pub creator_id: String,
    /// Original experience identifier; nil means absent.
    #[serde(rename = "experienceId", deserialize_with = "null_default")]
    pub experience_id: Uuid,
    /// Original experience display label.
    #[serde(deserialize_with = "null_default")]
    pub experience_name: String,
    /// Original telemetry scenario identifier; nil means absent.
    #[serde(rename = "scenarioId", deserialize_with = "null_default")]
    pub scenario_id: Uuid,
    /// Original additional telemetry label.
    #[serde(rename = "mpsasScenarioId", deserialize_with = "null_default")]
    pub mpsas_scenario_id: String,
    /// Selected server identifier.
    #[serde(rename = "serverId", deserialize_with = "null_default")]
    pub server_id: String,
    /// Original target identifier.
    #[serde(rename = "targetId", deserialize_with = "null_default")]
    pub target_id: String,
    /// Selected world identifier; nil means absent.
    #[serde(rename = "worldId", deserialize_with = "null_default")]
    pub world_id: Uuid,
    /// Selected world display label.
    #[serde(deserialize_with = "null_default")]
    pub world_name: String,
}

/// Requires an object before forwarding the same map to the DTO's derived field/duplicate rules.
pub(super) struct Object<T>(pub(super) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object")
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

/// Matches null scalar fields without accepting unrelated JSON types.
fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Matches null object fields while refusing positional-array struct decoding.
fn null_object<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<Object<T>>::deserialize(d)?
        .map(|value| value.0)
        .unwrap_or_default())
}

/// Decodes only object-shaped list members; null lists are empty, as in the baseline.
fn object_list<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<Object<T>>>::deserialize(d)?
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.0)
        .collect())
}
