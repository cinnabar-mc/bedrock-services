//! Caller-owned device and locale policy, independent from Xbox's device platform.

use crate::Error;
use std::fmt;
use uuid::Uuid;

/// A stable device UUID with an explicit Minecraft-service wire representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DeviceId {
    uuid: Uuid,
    compact: bool,
}

impl DeviceId {
    /// Preserves the lowercase, unhyphenated representation of an existing device ID.
    pub fn compact(uuid: Uuid) -> Self {
        Self {
            uuid,
            compact: true,
        }
    }
}

impl From<Uuid> for DeviceId {
    /// Uses the standard lowercase, hyphenated UUID representation.
    fn from(uuid: Uuid) -> Self {
        Self {
            uuid,
            compact: false,
        }
    }
}

impl fmt::Display for DeviceId {
    /// Formats the persisted identity using its caller-selected wire representation.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.compact {
            self.uuid.simple().fmt(formatter)
        } else {
            self.uuid.hyphenated().fmt(formatter)
        }
    }
}

/// Stable policy for one Minecraft account session; the caller persists its device ID.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Version supplied by the application's generated protocol infrastructure.
    pub game_version: String,
    /// Protocol number supplied alongside the generated game version.
    pub network_protocol_version: u32,
    /// Stable device identity, distinct from per-connection proof keys.
    pub device_id: DeviceId,
    /// Minecraft services platform (independent from Xbox's authentication platform).
    pub platform: String,
    /// Store associated with the device.
    pub store_platform: String,
    /// Device category sent to the session service.
    pub device_type: String,
    /// Available memory in bytes.
    pub memory_bytes: u64,
    /// Hardware memory classification sent alongside available bytes.
    pub hardware_memory_tier: u8,
    /// Language and region tag, such as en-US.
    pub language_code: String,
    /// Language code without its region.
    pub language: String,
    /// Region code.
    pub region_code: String,
    /// Explicit service treatment opt-ins.
    pub treatment_overrides: Vec<String>,
    /// Device capabilities; an empty list is encoded as an array.
    pub capabilities: Vec<String>,
}

impl Config {
    /// Creates desktop service settings from your game/protocol version and persistent device ID.
    pub fn desktop(
        game_version: impl Into<String>,
        network_protocol_version: u32,
        device_id: impl Into<DeviceId>,
    ) -> Self {
        Self {
            game_version: game_version.into(),
            device_id: device_id.into(),
            platform: "Windows10".into(),
            network_protocol_version,
            store_platform: "uwp.store".into(),
            device_type: "Windows10".into(),
            memory_bytes: 16 * (1 << 30),
            hardware_memory_tier: 5,
            language_code: "en-US".into(),
            language: "en".into(),
            region_code: "US".into(),
            treatment_overrides: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    /// Rejects missing policy and version path separators before any request.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.device_id.uuid.is_nil()
            || self.network_protocol_version == 0
            || self.hardware_memory_tier == 0
            || self.game_version.is_empty()
            || self.game_version.len() > 64
            || !self
                .game_version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            || self.platform.is_empty()
            || self.store_platform.is_empty()
            || self.device_type.is_empty()
        {
            return Err(Error::Invalid("Minecraft device policy"));
        }
        Ok(())
    }

    /// Builds the PlayFab user identity for session start.
    pub(crate) fn user(&self, ticket: &str) -> serde_json::Value {
        serde_json::json!({"languageCode":self.language_code,"language":self.language,
            "regionCode":self.region_code,"token":ticket,"tokenType":"PlayFab"})
    }

    /// Builds session policy from one discovery result and one stable device owner.
    pub(crate) fn start(&self, title: &str, ticket: &str) -> serde_json::Value {
        let mut device = serde_json::json!({"applicationType":"MinecraftPE", "capabilities":self.capabilities,
            "gameVersion":self.game_version,"id":self.device_id.to_string(),"memory":self.memory_bytes.to_string(),
            "hardwareMemoryTier":self.hardware_memory_tier,"networkProtocolVersion":self.network_protocol_version,
            "platform":self.platform,"playFabTitleId":title,"storePlatform":self.store_platform,"type":self.device_type});
        if !self.treatment_overrides.is_empty() {
            device["treatmentOverrides"] = serde_json::json!(self.treatment_overrides);
        }
        serde_json::json!({"device": device, "user": self.user(ticket)})
    }
}
