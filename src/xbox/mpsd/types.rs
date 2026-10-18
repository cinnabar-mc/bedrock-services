use super::{Error, MAX_ETAG_BYTES, MAX_NAME_BYTES};
use crate::xbox::social;
use p256::ecdsa::VerifyingKey;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// A complete validated directory locator, distinct from incomplete social observations.
/// No Debug implementation: session names and custom metadata may identify private worlds.
#[derive(Clone, Serialize)]
pub struct Reference {
    #[serde(rename = "scid")]
    pub(super) scid: Uuid,
    #[serde(rename = "templateName")]
    pub(super) template: String,
    pub(super) name: String,
}

impl Reference {
    /// Validates each path component without normalizing its case.
    ///
    /// # Errors
    /// Rejects nil SCIDs, empty/oversize names and path delimiters or dot segments.
    pub fn new(scid: Uuid, template: String, name: String) -> Result<Self, Error> {
        if scid.is_nil() {
            return Err(Error::Invalid("session service configuration"));
        }
        for component in [&template, &name] {
            if component.is_empty()
                || component.len() > MAX_NAME_BYTES
                || matches!(component.as_str(), "." | "..")
                || component
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '%'))
            {
                return Err(Error::Invalid("session reference component"));
            }
        }
        Ok(Self {
            scid,
            template,
            name,
        })
    }

    /// Returns the caller-selected SCID.
    pub fn service_config_id(&self) -> Uuid {
        self.scid
    }
    /// Borrows the original template name.
    pub fn template_name(&self) -> &str {
        &self.template
    }
    /// Borrows the original session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Matches the service's case-insensitive template/session identity.
    pub(super) fn same(&self, other: &Self) -> bool {
        self.scid == other.scid
            && self.template.eq_ignore_ascii_case(&other.template)
            && self.name.eq_ignore_ascii_case(&other.name)
    }
}

impl TryFrom<&social::SessionReference> for Reference {
    type Error = Error;
    fn try_from(value: &social::SessionReference) -> Result<Self, Self::Error> {
        Self::new(
            value
                .service_config_id
                .ok_or(Error::Invalid("incomplete session reference"))?,
            value
                .template_name
                .as_ref()
                .ok_or(Error::Invalid("incomplete session reference"))?
                .clone(),
            value
                .name
                .as_ref()
                .ok_or(Error::Invalid("incomplete session reference"))?
                .clone(),
        )
    }
}

/// One active caller-owned RTA connection and its stable session subscription identifier.
/// The application must supply a binding from the same account and reconcile on reconnect.
#[derive(Clone, Copy)]
pub struct Binding {
    pub(super) connection: Uuid,
    pub(super) subscription: Uuid,
}

impl Binding {
    /// Validates actual connection/subscription UUIDs; this does not open or verify an RTA socket.
    ///
    /// # Errors
    /// Rejects nil identifiers.
    pub fn new(connection: Uuid, subscription: Uuid) -> Result<Self, Error> {
        if connection.is_nil() || subscription.is_nil() {
            return Err(Error::Invalid("RTA session binding"));
        }
        Ok(Self {
            connection,
            subscription,
        })
    }
}

/// Explicit directory restriction for a newly published session.
#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Restriction {
    /// Anyone allowed by the title's other policies.
    None,
    /// Members must share a local connection.
    Local,
    /// The caller's followed social group, matching the inspected creation default.
    #[default]
    Followed,
}

/// Title-owned member constants/properties; omitted sections do not clear existing data.
#[derive(Default)]
pub struct MemberData {
    /// Immutable member metadata established during creation/join.
    pub constants: Option<Value>,
    /// Mutable member metadata established during creation/join.
    pub properties: Option<Value>,
}

/// Initial directory state. Activity publication is a separate explicit operation.
pub struct Publish {
    /// The active caller-owned RTA binding.
    pub binding: Binding,
    /// Title-owned host member data.
    pub member: MemberData,
    /// Immutable title-defined session constants.
    pub constants: Option<Value>,
    /// Mutable title-defined session properties, including application-owned world metadata/nonces.
    pub properties: Option<Value>,
    /// Explicit initial join restriction.
    pub join: Restriction,
    /// Explicit initial read restriction.
    pub read: Restriction,
}

/// A directory section retaining both system and title-defined fields without joinability defaults.
#[derive(Deserialize, Default)]
pub struct Section {
    /// Service-defined fields, including unrecognized future fields.
    pub system: Option<Value>,
    /// Title-owned metadata. This may contain private world admission nonces.
    pub custom: Option<Value>,
}

/// A member in the last complete directory response.
#[derive(Deserialize)]
pub struct Member {
    /// Immutable member identity and title metadata.
    pub constants: Option<Section>,
    /// Mutable membership/connection metadata.
    pub properties: Option<Section>,
}

impl Member {
    /// Borrows the reported Xbox identity without inferring admission or membership ownership.
    pub fn xuid(&self) -> Option<&str> {
        self.constants
            .as_ref()?
            .system
            .as_ref()?
            .get("xuid")?
            .as_str()
    }
}

/// A fresh complete snapshot; missing members never retain an earlier member list.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    /// Optional service revision branch, which can rotate during a session lifetime.
    pub branch: Option<Uuid>,
    /// Optional monotonic change number within the reported branch.
    pub change_number: Option<u64>,
    /// Immutable session constants.
    pub constants: Option<Section>,
    /// Mutable session properties.
    pub properties: Option<Section>,
    /// Null members are preserved as absent membership, not fabricated records.
    #[serde(default, deserialize_with = "nullable_members")]
    pub members: BTreeMap<String, Option<Member>>,
    /// Role metadata retained for caller interpretation.
    pub role_types: Option<Value>,
    /// When supplied, must match the owner reference before the snapshot is installed.
    #[serde(rename = "sessionRef")]
    pub(super) reference: Option<social::SessionReference>,
}

/// Accepts absent/null member maps while preserving the complete fresh response semantics.
fn nullable_members<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, Option<Member>>, D::Error> {
    Ok(Option::<BTreeMap<String, Option<Member>>>::deserialize(d)?.unwrap_or_default())
}

/// One account/proof-bound local snapshot. Drop performs no remote cleanup.
pub struct Session {
    pub(super) reference: Reference,
    pub(super) owner: String,
    pub(super) proof: VerifyingKey,
    pub(super) description: Description,
    pub(super) etag: Option<HeaderValue>,
    pub(super) closed: bool,
    pub(super) uncertain: bool,
}

impl Session {
    /// Borrows the validated locator, including after deletion for diagnostics/cleanup policy.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }
    /// Borrows the last accepted complete snapshot.
    pub fn description(&self) -> &Description {
        &self.description
    }
    /// Reports local closure after leave or deletion.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// Reports a canceled/failed write or conflict that requires explicit reconciliation.
    pub fn needs_sync(&self) -> bool {
        self.uncertain
    }

    /// Forgets stale snapshot/validator state when this local membership ends.
    pub(super) fn end(&mut self) {
        self.closed = true;
        self.uncertain = false;
        self.description = Description::default();
        self.etag = None;
    }
}

/// Metadata returned after explicit invitation creation; no notification delivery is inferred.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invitation {
    /// Directory handle used by the receiver's explicit join attempt.
    pub id: Uuid,
    /// Service-provided expiration text; the receiver enforces its account/join policy.
    pub expiration: Option<String>,
    /// Platform/title associations retained without transport inference.
    pub game_types: Option<Value>,
    /// The invited account when the service includes it.
    pub invited_xuid: Option<String>,
    /// The authenticated sender when included.
    pub sender_xuid: Option<String>,
    /// The response locator when supplied.
    #[serde(rename = "sessionRef")]
    pub(super) reference: Option<social::SessionReference>,
}

/// Accepts bounded HTTP validators without exposing them through Debug or errors.
pub(super) fn etag(headers: &reqwest::header::HeaderMap) -> Result<Option<HeaderValue>, Error> {
    headers
        .get(reqwest::header::ETAG)
        .map(|value| {
            let bytes = value.as_bytes();
            let tag = bytes.strip_prefix(b"W/").unwrap_or(bytes);
            if bytes.len() > MAX_ETAG_BYTES
                || tag.len() < 2
                || tag.first() != Some(&b'"')
                || tag.last() != Some(&b'"')
                || tag[1..tag.len() - 1]
                    .iter()
                    .any(|byte| !matches!(*byte, 0x21 | 0x23..=0x7e | 0x80..=0xff))
            {
                return Err(Error::Invalid("session ETag"));
            }
            Ok(value.clone())
        })
        .transpose()
}
