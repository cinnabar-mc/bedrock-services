use serde::{
    Deserialize, Deserializer,
    de::{DeserializeSeed, MapAccess, Visitor, value::MapAccessDeserializer},
};
use serde_json::value::RawValue;
use std::{collections::HashMap, fmt, marker::PhantomData};

// Decode each occurrence in wire order; one field declaration owns its name, type and null policy.
macro_rules! record {
    ($(#[$doc:meta])* pub struct $name:ident {
        $($(#[$field_doc:meta])* pub $field:ident: $ty:ty => $wire:literal, $mode:ident;)*
    }) => {
        $(#[$doc])*
        #[derive(Default)]
        pub struct $name { $($(#[$field_doc])* pub $field: $ty,)* }

        impl<'de> Deserialize<'de> for $name {
            /// Decodes a named record with later scalar values replacing earlier values.
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let mut value = Self::default();
                Self::deserialize_in_place(deserializer, &mut value)?;
                Ok(value)
            }

            /// Merges repeated object fields while preserving the wire's null semantics.
            fn deserialize_in_place<D: Deserializer<'de>>(deserializer: D, place: &mut Self) -> Result<(), D::Error> {
                struct RecordVisitor<'a>(&'a mut $name);
                impl<'de> Visitor<'de> for RecordVisitor<'_> {
                    type Value = ();
                    /// Describes the required non-positional record shape.
                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a player messaging object")
                    }
                    /// Applies every occurrence and skips unknown metadata without retaining it.
                    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
                        while let Some(name) = map.next_key::<String>()? {
                            $(if name.eq_ignore_ascii_case($wire) {
                                record!(@read $mode, map, self.0.$field);
                                continue;
                            })*
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                        Ok(())
                    }
                }
                deserializer.deserialize_map(RecordVisitor(place))
            }
        }
    };
    (@read merge, $map:ident, $field:expr) => { $map.next_value_seed(InPlace(&mut $field))?; };
    (@read sequence, $map:ident, $field:expr) => { $map.next_value_seed(Sequence(&mut $field))?; };
    (@read mapping, $map:ident, $field:expr) => { $map.next_value_seed(Mapping(&mut $field))?; };
    (@read raw, $map:ident, $field:expr) => { $field = $map.next_value()?; };
}

record! {
/// A successful marketing refresh, retaining original service order and category counts.
/// No message metadata is authenticated game/session authority.
pub struct Session {
    /// Opaque continuation from this response; empty does not replace the retained token.
    pub continuation_token: String => "continuationToken", merge;
    /// Top-level marketing surfaces, separate from category messages.
    pub messages: Vec<Message> => "messages", sequence;
    /// Service counts and the currently loaded per-category messages.
    pub inbox_summary: InboxSummary => "inboxSummary", merge;
    /// Uninterpreted optional settings, never a replacement for caller policy.
    pub inbox_settings: Option<Box<RawValue>> => "inboxSettings", raw;
}
}

record! {
/// Service totals, which may exceed the number of messages loaded in this response.
pub struct InboxSummary {
    /// Reported total, preserving signed wire values for application projection.
    pub total: i64 => "totalNumberOfMessages", merge;
    /// Categories in service order.
    pub categories: Vec<Category> => "categories", sequence;
}
}

record! {
/// One category's reported totals, metadata, continuation and loaded messages.
pub struct Category {
    /// Reported message total; not the length of the loaded subset.
    pub total: i64 => "totalNumberOfMessages", merge;
    /// Reported unread total; applications decide how to project negative values.
    pub unread: i64 => "totalNumberOfUnreadMessages", merge;
    /// Reported category spelling and display metadata.
    pub info: CategoryInfo => "categoryInfo", merge;
    /// Original category continuation, without an implicit follow-up request.
    pub continuation_token: String => "continuationToken", merge;
    /// The currently loaded messages in this category.
    pub messages: Vec<Message> => "messages", sequence;
}
}

record! {
/// Untrusted service category metadata; its image is never automatically fetched.
pub struct CategoryInfo {
    /// Original category type, matched by application policy.
    pub kind: String => "type", merge;
    /// Display name.
    pub name: String => "name", merge;
    /// Display-only category image.
    pub image: Image => "image", merge;
}
}

record! {
/// One marketing surface or inbox message, before application filtering/projection.
pub struct Message {
    /// Service message identity, distinct from its instance and report identity.
    pub id: String => "id", merge;
    /// Instance identity used by ordered inbox reports.
    pub instance_id: String => "instanceId", merge;
    /// Whether this message is a service control.
    pub is_control: bool => "isControl", merge;
    /// Report identity supplied by this same message.
    pub report_id: String => "reportId", merge;
    /// Display-only sender text.
    pub sender: String => "sender", merge;
    /// Requested display surface; unknown values remain metadata.
    pub surface: String => "surface", merge;
    /// Requested layout template; unknown values remain metadata.
    pub template: String => "template", merge;
    /// Service permission to show this message in game, not a game admission.
    pub allow_in_game: bool => "allowInGame", merge;
    /// Header, body and ribbon text.
    pub text: MessageText => "messageText", merge;
    /// Keyed button metadata, never an automatically opened URI.
    pub buttons: HashMap<String, Button> => "buttons", mapping;
    /// Keyed image metadata, never an authenticated fetch destination.
    pub images: HashMap<String, Image> => "images", mapping;
    /// Original category spelling.
    pub inbox_category: String => "inboxCategory", merge;
    /// Original received timestamp, without guessed parsing of future formats.
    pub date_received: String => "dateReceived", merge;
    /// Original expiration metadata, separate from credentials or world approval.
    pub expiration_date: String => "expirationDate", merge;
    /// Original read/unread status, without a mutation on refresh.
    pub status: String => "status", merge;
    /// Multi-item layout contents in service order.
    pub items: Vec<MessageItem> => "messageItemList", sequence;
    /// Unused style metadata retained without a recursive application model.
    pub style: Option<Box<RawValue>> => "style", raw;
    /// Named button-art colors.
    pub colors: HashMap<String, Color> => "colors", mapping;
}
}

record! {
/// A message's textual presentation.
pub struct MessageText {
    /// Header text.
    pub header: String => "header", merge;
    /// Body text.
    pub body: String => "body", merge;
    /// Ribbon/banner text.
    pub banner: String => "bannerText", merge;
}
}

record! {
/// A reported button; URI launch/egress policy belongs to the application.
pub struct Button {
    /// Original button identity.
    pub id: String => "id", merge;
    /// Display text.
    pub text: String => "text", merge;
    /// Original description.
    pub description: String => "description", merge;
    /// Display/action link, never a credential destination.
    pub link: String => "link", merge;
    /// Original action spelling, including unrecognized future values.
    pub action: String => "action", merge;
}
}

record! {
/// Image metadata; bytes require separate caller egress/cache/decoder validation.
pub struct Image {
    /// Original image identity, when present.
    pub id: String => "id", merge;
    /// Untrusted display/download URL.
    pub url: String => "url", merge;
    /// Reported dimensions, not image decoder authority.
    pub size: ImageSize => "imageSize", merge;
}
}

record! {
/// Original reported image dimensions.
pub struct ImageSize {
    /// Reported width.
    pub width: i64 => "width", merge;
    /// Reported height.
    pub height: i64 => "height", merge;
}
}

record! {
/// One multi-item message entry, preserving optional unused metadata.
pub struct MessageItem {
    /// Optional button data.
    pub button: Button => "button", merge;
    /// Optional image data.
    pub image: Image => "image", merge;
    /// Text or other well-formed banner metadata.
    pub sale_banner: Option<Box<RawValue>> => "saleBanner", raw;
    /// Subtitle text.
    pub sub_title: String => "subTitle", merge;
    /// Unused footer call-to-action metadata.
    pub footer_cta: Option<Box<RawValue>> => "footerCTA", raw;
    /// Footer header text.
    pub footer_header: String => "footerHeader", merge;
    /// Footer body text.
    pub footer_body: String => "footerBody", merge;
}
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

record! {
/// One named art color, with the baseline's object-valued `hexColor` channels.
pub struct Color {
    /// RGB channels, not a CSS/hexadecimal string.
    pub rgb: Rgb => "hexColor", merge;
}
}

record! {
/// Eight-bit color channels in the original wire representation.
pub struct Rgb {
    /// Red channel.
    pub r: u8 => "r", merge;
    /// Green channel.
    pub g: u8 => "g", merge;
    /// Blue channel.
    pub b: u8 => "b", merge;
}
}

/// Admits named JSON records through their existing field decoder, never positional arrays.
/// The map is streamed without a recursive value or a second record allocation.
pub(super) struct Object<T>(pub(super) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    /// Restricts only the container shape; the original decoder still owns fields and duplicates.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = T;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a player messaging object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map))
            }
        }

        deserializer
            .deserialize_map(ObjectVisitor(PhantomData))
            .map(Self)
    }
}

/// Preserves zero-valued null struct elements without accepting positional records.
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

/// Leaves scalar and struct fields unchanged for null and decodes nonnull values in place.
struct InPlace<'a, T>(&'a mut T);

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for InPlace<'_, T> {
    type Value = ();
    /// Uses the option visitor only to distinguish null from an actual field value.
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_option(self)
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for InPlace<'_, T> {
    type Value = ();
    /// Describes a nullable field without including its contents in errors.
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a nullable field")
    }
    /// JSON null leaves an existing scalar or record unchanged.
    fn visit_none<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    /// Delegates replacement or record merging to the field's owning type.
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        T::deserialize_in_place(deserializer, self.0)
    }
}

/// Replaces a repeated sequence, retaining default-valued null record elements.
struct Sequence<'a, T>(&'a mut Vec<T>);
impl<'de, T: Deserialize<'de> + Default> DeserializeSeed<'de> for Sequence<'_, T> {
    type Value = ();
    /// A null sequence clears the prior slice, just like an empty replacement.
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        *self.0 = null_sequence(deserializer)?;
        Ok(())
    }
}

/// Merges repeated maps, replacing individual entries and clearing the map on null.
struct Mapping<'a, T>(&'a mut HashMap<String, T>);
impl<'de, T: Deserialize<'de> + Default> DeserializeSeed<'de> for Mapping<'_, T> {
    type Value = ();
    /// Keeps existing keys that are absent from a later nonnull map occurrence.
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        match Option::<HashMap<String, Option<T>>>::deserialize(deserializer)? {
            None => self.0.clear(),
            Some(values) => self.0.extend(
                values
                    .into_iter()
                    .map(|(key, value)| (key, value.unwrap_or_default())),
            ),
        }
        Ok(())
    }
}
