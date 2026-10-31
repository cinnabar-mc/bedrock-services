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
    #[serde(deserialize_with = "localized_text")]
    pub title: BTreeMap<String, String>,
    /// Original locale keys and description text.
    #[serde(deserialize_with = "localized_text")]
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

/// Catalog display fields; unused metadata remains in the original card's raw JSON.
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
    /// Original NetherNet routing identity for Player Messaging.
    #[serde(rename = "netherNetId", deserialize_with = "null_default")]
    pub nethernet_id: String,
    /// Original destination metadata, not a replacement account or proof.
    #[serde(deserialize_with = "null_object")]
    pub destination_info: DestinationInfo,
}

impl JoinAddress {
    /// Resolves the response through the same JSON-RPC target rules as Realms.
    pub fn target(&self) -> Result<crate::realms::JoinTarget<'_>, Error> {
        self.network_protocol.target(&self.nethernet_id)
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

/// Retains null struct entries as defaults while refusing positional arrays or unrelated scalars.
fn object_list<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<Option<Object<T>>>>::deserialize(d)?
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.map(|value| value.0).unwrap_or_default())
        .collect())
}

/// Preserves locale keys and null string values as empty text without accepting other value types.
fn localized_text<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
    Ok(Option::<BTreeMap<String, Option<String>>>::deserialize(d)?
        .unwrap_or_default()
        .into_iter()
        .map(|(locale, value)| (locale, value.unwrap_or_default()))
        .collect())
}
