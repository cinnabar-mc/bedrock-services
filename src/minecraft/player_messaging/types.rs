use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::collections::HashMap;

/// A successful marketing refresh, retaining original service order and category counts.
/// No message metadata is authenticated game/session authority.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Session {
    /// Opaque continuation from this response; empty does not replace the retained token.
    #[serde(deserialize_with = "null_default")]
    pub continuation_token: String,
    /// Top-level marketing surfaces, separate from category messages.
    #[serde(deserialize_with = "null_sequence")]
    pub messages: Vec<Message>,
    /// Service counts and the currently loaded per-category messages.
    #[serde(deserialize_with = "null_default")]
    pub inbox_summary: InboxSummary,
    /// Uninterpreted optional settings, never a replacement for caller policy.
    pub inbox_settings: Option<Box<RawValue>>,
}

/// Service totals, which may exceed the number of messages loaded in this response.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct InboxSummary {
    /// Reported total, preserving signed wire values for application projection.
    #[serde(rename = "totalNumberOfMessages", deserialize_with = "null_default")]
    pub total: i64,
    /// Categories in service order.
    #[serde(deserialize_with = "null_sequence")]
    pub categories: Vec<Category>,
}

/// One category's reported totals, metadata, continuation and loaded messages.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Category {
    /// Reported message total; not the length of the loaded subset.
    #[serde(rename = "totalNumberOfMessages", deserialize_with = "null_default")]
    pub total: i64,
    /// Reported unread total; applications decide how to project negative values.
    #[serde(
        rename = "totalNumberOfUnreadMessages",
        deserialize_with = "null_default"
    )]
    pub unread: i64,
    /// Reported category spelling and display metadata.
    #[serde(rename = "categoryInfo", deserialize_with = "null_default")]
    pub info: CategoryInfo,
    /// Original category continuation, without an implicit follow-up request.
    #[serde(deserialize_with = "null_default")]
    pub continuation_token: String,
    /// The currently loaded messages in this category.
    #[serde(deserialize_with = "null_sequence")]
    pub messages: Vec<Message>,
}

/// Untrusted service category metadata; its image is never automatically fetched.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CategoryInfo {
    /// Original category type, matched by application policy.
    #[serde(rename = "type", deserialize_with = "null_default")]
    pub kind: String,
    /// Display name.
    #[serde(deserialize_with = "null_default")]
    pub name: String,
    /// Display-only category image.
    #[serde(deserialize_with = "null_default")]
    pub image: Image,
}

/// One marketing surface or inbox message, before application filtering/projection.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Message {
    /// Service message identity, distinct from its instance and report identity.
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    /// Instance identity used by ordered inbox reports.
    #[serde(deserialize_with = "null_default")]
    pub instance_id: String,
    /// Whether this message is a service control.
    #[serde(deserialize_with = "null_default")]
    pub is_control: bool,
    /// Report identity supplied by this same message.
    #[serde(deserialize_with = "null_default")]
    pub report_id: String,
    /// Display-only sender text.
    #[serde(deserialize_with = "null_default")]
    pub sender: String,
    /// Requested display surface; unknown values remain metadata.
    #[serde(deserialize_with = "null_default")]
    pub surface: String,
    /// Requested layout template; unknown values remain metadata.
    #[serde(deserialize_with = "null_default")]
    pub template: String,
    /// Service permission to show this message in game, not a game admission.
    #[serde(deserialize_with = "null_default")]
    pub allow_in_game: bool,
    /// Header, body and ribbon text.
    #[serde(rename = "messageText", deserialize_with = "null_default")]
    pub text: MessageText,
    /// Keyed button metadata, never an automatically opened URI.
    #[serde(deserialize_with = "null_map")]
    pub buttons: HashMap<String, Button>,
    /// Keyed image metadata, never an authenticated fetch destination.
    #[serde(deserialize_with = "null_map")]
    pub images: HashMap<String, Image>,
    /// Original category spelling.
    #[serde(deserialize_with = "null_default")]
    pub inbox_category: String,
    /// Original received timestamp, without guessed parsing of future formats.
    #[serde(deserialize_with = "null_default")]
    pub date_received: String,
    /// Original expiration metadata, separate from credentials or world approval.
    #[serde(deserialize_with = "null_default")]
    pub expiration_date: String,
    /// Original read/unread status, without a mutation on refresh.
    #[serde(deserialize_with = "null_default")]
    pub status: String,
    /// Multi-item layout contents in service order.
    #[serde(rename = "messageItemList", deserialize_with = "null_sequence")]
    pub items: Vec<MessageItem>,
    /// Unused style metadata retained without a recursive application model.
    pub style: Option<Box<RawValue>>,
    /// Named button-art colors.
    #[serde(deserialize_with = "null_map")]
    pub colors: HashMap<String, Color>,
}

/// A message's textual presentation.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MessageText {
    /// Header text.
    #[serde(deserialize_with = "null_default")]
    pub header: String,
    /// Body text.
    #[serde(deserialize_with = "null_default")]
    pub body: String,
    /// Ribbon/banner text.
    #[serde(rename = "bannerText", deserialize_with = "null_default")]
    pub banner: String,
}

/// A reported button; URI launch/egress policy belongs to the application.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Button {
    /// Original button identity.
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    /// Display text.
    #[serde(deserialize_with = "null_default")]
    pub text: String,
    /// Original description.
    #[serde(deserialize_with = "null_default")]
    pub description: String,
    /// Display/action link, never a credential destination.
    #[serde(deserialize_with = "null_default")]
    pub link: String,
    /// Original action spelling, including unrecognized future values.
    #[serde(deserialize_with = "null_default")]
    pub action: String,
}

/// Image metadata; bytes require separate caller egress/cache/decoder validation.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Image {
    /// Original image identity, when present.
    #[serde(deserialize_with = "null_default")]
    pub id: String,
    /// Untrusted display/download URL.
    #[serde(deserialize_with = "null_default")]
    pub url: String,
    /// Reported dimensions, not image decoder authority.
    #[serde(rename = "imageSize", deserialize_with = "null_default")]
    pub size: ImageSize,
}

/// Original reported image dimensions.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct ImageSize {
    /// Reported width.
    #[serde(deserialize_with = "null_default")]
    pub width: i64,
    /// Reported height.
    #[serde(deserialize_with = "null_default")]
    pub height: i64,
}

/// One multi-item message entry, preserving optional unused metadata.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MessageItem {
    /// Optional button data.
    #[serde(deserialize_with = "null_default")]
    pub button: Button,
    /// Optional image data.
    #[serde(deserialize_with = "null_default")]
    pub image: Image,
    /// Text or other well-formed banner metadata.
    pub sale_banner: Option<Box<RawValue>>,
    /// Subtitle text.
    #[serde(rename = "subTitle", deserialize_with = "null_default")]
    pub sub_title: String,
    /// Unused footer call-to-action metadata.
    #[serde(rename = "FooterCTA")]
    pub footer_cta: Option<Box<RawValue>>,
    /// Footer header text.
    #[serde(rename = "FooterHeader", deserialize_with = "null_default")]
    pub footer_header: String,
    /// Footer body text.
    #[serde(rename = "FooterBody", deserialize_with = "null_default")]
    pub footer_body: String,
}

impl MessageItem {
    /// Returns only textual sale banners; other well-formed representations remain unused.
    pub fn sale_banner_text(&self) -> String {
        self.sale_banner
            .as_ref()
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
            .unwrap_or_default()
    }
}

/// One named art color, with the baseline's object-valued `hexColor` channels.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Color {
    /// RGB channels, not a CSS/hexadecimal string.
    #[serde(rename = "hexColor", deserialize_with = "null_default")]
    pub rgb: Rgb,
}

/// Eight-bit color channels in the original wire representation.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Rgb {
    /// Red channel.
    #[serde(deserialize_with = "null_default")]
    pub r: u8,
    /// Green channel.
    #[serde(deserialize_with = "null_default")]
    pub g: u8,
    /// Blue channel.
    #[serde(deserialize_with = "null_default")]
    pub b: u8,
}

/// The baseline decoder leaves a zero field unchanged for JSON null, as for an absent field.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

/// Preserves the baseline's zero-valued null struct elements without losing valid neighbors.
fn null_sequence<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<Vec<Option<T>>>::deserialize(deserializer).map(|values| {
        values
            .unwrap_or_default()
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect()
    })
}

/// Preserves null struct-valued map entries as zero metadata, not fabricated authority.
fn null_map<'de, D, T>(deserializer: D) -> Result<HashMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<HashMap<String, Option<T>>>::deserialize(deserializer).map(|values| {
        values
            .unwrap_or_default()
            .into_iter()
            .map(|(key, value)| (key, value.unwrap_or_default()))
            .collect()
    })
}
