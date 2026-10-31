//! Open profile-setting keys with the service's batch-update wire envelope.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

/// Profile biography text.
pub const BIO: &str = "Bio";
/// Profile location text.
pub const LOCATION: &str = "Location";
/// Boolean avatar-display preference, encoded as `1` or `0`.
pub const SHOW_USER_AS_AVATAR: &str = "ShowUserAsAvatar";
/// Comma-separated preferred platform names.
pub const PREFERRED_PLATFORMS: &str = "PreferredPlatforms";
/// Profile color-theme identifier.
pub const WEB_COLOR_THEME: &str = "WebColorTheme";

/// Arbitrary profile settings; unknown keys and empty values remain valid entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileSettings(BTreeMap<String, String>);

impl Deref for ProfileSettings {
    type Target = BTreeMap<String, String>;
    /// Borrows the canonical map without projecting a separate list of known fields.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ProfileSettings {
    /// Allows arbitrary setting IDs through the same map used by the wire codec.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ProfileSettings {
    /// Reports the service's true value; every other string is false.
    pub fn show_user_as_avatar(&self) -> bool {
        self.get(SHOW_USER_AS_AVATAR)
            .is_some_and(|value| value == "1")
    }

    /// Sets the avatar preference using the service's boolean string convention.
    pub fn with_show_user_as_avatar(mut self, value: bool) -> Self {
        self.insert(
            SHOW_USER_AS_AVATAR.into(),
            if value { "1" } else { "0" }.into(),
        );
        self
    }

    /// Splits the original platform text without filtering unknown platform names.
    pub fn preferred_platforms(&self) -> Vec<&str> {
        self.get(PREFERRED_PLATFORMS)
            .map_or("", String::as_str)
            .split(',')
            .collect()
    }

    /// Sets comma-separated platform names without imposing a closed platform list.
    pub fn with_preferred_platforms(mut self, platforms: &[&str]) -> Self {
        self.insert(PREFERRED_PLATFORMS.into(), platforms.join(","));
        self
    }

    /// Decodes sparse/null rows as service defaults and applies duplicate IDs in order.
    fn from_wire(value: &Value) -> Result<Self, &'static str> {
        let root = object(value)?;
        let Some(rows) = root
            .and_then(|root| root.get("settings"))
            .filter(|rows| !rows.is_null())
        else {
            return Ok(Self::default());
        };
        let rows = rows.as_array().ok_or("invalid profile settings list")?;
        let mut settings = Self::default();
        for row in rows {
            let row = object(row)?;
            let setting = object(
                row.and_then(|row| row.get("userSetting"))
                    .unwrap_or(&Value::Null),
            )?;
            let id = text(setting.and_then(|setting| setting.get("id")))?;
            let value = text(setting.and_then(|setting| setting.get("value")))?;
            settings.insert(id.into(), value.into());
        }
        Ok(settings)
    }
}

impl Serialize for ProfileSettings {
    /// Encodes map entries in the service envelope; an empty map sends an empty array.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Setting<'a> {
            id: &'a str,
            value: &'a str,
        }
        #[derive(Serialize)]
        struct Row<'a> {
            #[serde(rename = "userSetting")]
            setting: Setting<'a>,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            settings: Vec<Row<'a>>,
        }
        Wire {
            settings: self
                .iter()
                .map(|(id, value)| Row {
                    setting: Setting { id, value },
                })
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProfileSettings {
    /// Retains unknown keys while reporting malformed shapes without their values.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_wire(&value).map_err(serde::de::Error::custom)
    }
}

/// Accepts service objects or null while refusing positional arrays and scalars.
fn object(value: &Value) -> Result<Option<&Map<String, Value>>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::Object(map) => Ok(Some(map)),
        _ => Err("invalid profile settings object"),
    }
}

/// Reads an optional setting string, preserving the service's empty/null default.
fn text(value: Option<&Value>) -> Result<&str, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(value)) => Ok(value),
        _ => Err("invalid profile settings text"),
    }
}
