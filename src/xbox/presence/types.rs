use crate::Error;
use serde::Serialize;
use uuid::Uuid;

/// SDK byte bound for each rich-presence identifier or substitution parameter.
pub const MAX_TEXT_BYTES: usize = 256;
/// SDK bound for rich-presence substitution parameters in one update.
pub const MAX_PARAMETERS: usize = 16;

/// Whether the authenticated title is currently active.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// The user is active in this title.
    Active,
    /// The user is no longer active in this title.
    Inactive,
}

/// Display placement reported for the authenticated title.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Placement {
    /// Full-screen title placement.
    Full,
    /// Title snapped alongside another application.
    Snapped,
    /// Title occupying the remainder beside a snapped application.
    Fill,
    /// Title running in the background.
    Background,
}

/// Validated title-defined rich presence, borrowed without copying caller text.
/// The caller supplies the title's service configuration and activity policy.
#[derive(Clone, Copy, Serialize)]
pub struct RichPresence<'a> {
    id: &'a str,
    scid: Uuid,
    #[serde(rename = "params", skip_serializing_if = "is_empty")]
    parameters: &'a [&'a str],
}

impl<'a> RichPresence<'a> {
    /// Validates a non-nil service configuration and bounded nonempty activity identifier.
    ///
    /// # Errors
    /// Rejects nil configuration IDs and empty, oversized or control-containing identifiers.
    pub fn new(service_config: Uuid, id: &'a str) -> Result<Self, Error> {
        if service_config.is_nil() {
            return Err(Error::Invalid("presence service configuration"));
        }
        validate_text(id, false)?;
        Ok(Self {
            id,
            scid: service_config,
            parameters: &[],
        })
    }

    /// Supplies bounded substitution values; empty values remain valid substitutions.
    ///
    /// # Errors
    /// Rejects excessive parameter counts, oversized values and control characters.
    pub fn with_parameters(mut self, parameters: &'a [&'a str]) -> Result<Self, Error> {
        if parameters.len() > MAX_PARAMETERS {
            return Err(Error::Invalid("presence parameter count"));
        }
        for parameter in parameters {
            validate_text(parameter, true)?;
        }
        self.parameters = parameters;
        Ok(self)
    }
}

/// One explicit activity update, also used for caller-scheduled heartbeats.
/// Title identity comes from the authenticated title, never from this payload.
#[derive(Clone, Copy)]
pub struct TitleUpdate<'a> {
    state: State,
    placement: Option<Placement>,
    rich_presence: Option<RichPresence<'a>>,
}

impl<'a> TitleUpdate<'a> {
    /// Creates a state-only update; the service's default placement remains in effect.
    pub fn new(state: State) -> Self {
        Self {
            state,
            placement: None,
            rich_presence: None,
        }
    }

    /// Reports an explicit display placement.
    #[must_use]
    pub fn with_placement(mut self, placement: Placement) -> Self {
        self.placement = Some(placement);
        self
    }

    /// Includes already-validated title-defined rich presence.
    #[must_use]
    pub fn with_rich_presence(mut self, presence: RichPresence<'a>) -> Self {
        self.rich_presence = Some(presence);
        self
    }

    /// Encodes the bounded title update with the reference JSON encoder's trailing newline.
    pub(super) fn encode(&self) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Activity<'a> {
            rich_presence: RichPresence<'a>,
        }
        #[derive(Serialize)]
        struct Request<'a> {
            state: State,
            #[serde(skip_serializing_if = "Option::is_none")]
            placement: Option<Placement>,
            #[serde(skip_serializing_if = "Option::is_none")]
            activity: Option<Activity<'a>>,
        }
        let mut bytes = serde_json::to_vec(&Request {
            state: self.state,
            placement: self.placement,
            activity: self
                .rich_presence
                .map(|rich_presence| Activity { rich_presence }),
        })
        .map_err(|_| Error::Invalid("presence request JSON"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Omits an absent parameter list without serializing a second representation.
fn is_empty(parameters: &&[&str]) -> bool {
    parameters.is_empty()
}

/// Bounds text before acquisition or JSON allocation; diagnostics never echo caller text.
fn validate_text(value: &str, empty_allowed: bool) -> Result<(), Error> {
    if (!empty_allowed && value.is_empty())
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(Error::Invalid("presence text"));
    }
    Ok(())
}
