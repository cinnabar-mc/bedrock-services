//! Borrowed service credential persistence with original absolute expiry.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(in crate::minecraft) struct Snapshot<'a> {
    header: &'a str,
    expires: SystemTime,
    treatments: Vec<String>,
    configurations: HashMap<String, Configuration>,
    treatment_context: String,
}

impl Authorization {
    /// Borrows the sensitive header and retains the service's metadata unchanged.
    pub(in crate::minecraft) fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            header: &self.header,
            expires: self.expires.into(),
            treatments: self.treatments.clone(),
            configurations: self.configurations.clone(),
            treatment_context: self.treatment_context.clone(),
        }
    }
}

impl Snapshot<'_> {
    /// Revalidates claims and the original refresh margin against fresh service time.
    pub(in crate::minecraft) fn restore(self, now: SystemTime) -> Result<Authorization, Error> {
        let nanos = self
            .expires
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::TimeRange)?
            .as_nanos();
        let expires = OffsetDateTime::from_unix_timestamp_nanos(
            i128::try_from(nanos).map_err(|_| Error::TimeRange)?,
        )
        .map_err(|_| Error::TimeRange)?;
        TokenResponse {
            authorization_header: self.header.into(),
            valid_until: expires.format(&Rfc3339).map_err(|_| Error::TimeRange)?,
            treatments: self.treatments,
            configurations: self.configurations,
            treatment_context: self.treatment_context,
        }
        .authorization(now)
    }
}
