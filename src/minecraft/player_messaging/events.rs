use crate::Error;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use uuid::Uuid;

/// One explicit marketing interaction, not a game invitation or account authorization.
/// Empty optional identifiers are omitted from the wire. The service's nonempty
/// event type remains open rather than duplicating a client-specific policy table.
#[derive(Default)]
pub struct Event<'a> {
    /// Service event type, such as Click, Delete, ReadAll or DeleteAllRead.
    pub event_type: &'a str,
    /// Original interaction time, or the HTTP edge's current time when absent.
    pub time: Option<SystemTime>,
    /// Message instance identity; empty for bulk interactions.
    pub instance_id: &'a str,
    /// Service report identity, when supplied by the same message.
    pub report_id: &'a str,
    /// Original service button identity, when reporting a button interaction.
    pub button_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Entry<'a> {
    event_date_time: String,
    event_type: &'a str,
    session_id: Uuid,
    #[serde(skip_serializing_if = "str::is_empty")]
    instance_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    report_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    button_id: &'a str,
}

/// Projects one explicit batch with a single caller-supplied clock sample.
pub(super) fn entries<'a>(
    events: &[Event<'a>],
    session: Uuid,
    now: SystemTime,
) -> Result<Vec<Entry<'a>>, Error> {
    if events.is_empty() {
        return Err(Error::Invalid("player messaging has no events"));
    }
    events
        .iter()
        .map(|event| {
            if event.event_type.is_empty() {
                return Err(Error::Invalid("player messaging event type"));
            }
            Ok(Entry {
                event_date_time: timestamp(event.time.unwrap_or(now))?,
                event_type: event.event_type,
                session_id: session,
                instance_id: event.instance_id,
                report_id: event.report_id,
                button_id: event.button_id,
            })
        })
        .collect()
}

/// Emits the baseline's UTC millisecond format using checked platform-to-wire conversion.
fn timestamp(at: SystemTime) -> Result<String, Error> {
    let nanos = match at.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).map_err(|_| Error::TimeRange)?,
        Err(error) => -i128::try_from(error.duration().as_nanos()).map_err(|_| Error::TimeRange)?,
    };
    let at = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| Error::TimeRange)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.millisecond(),
    ))
}
