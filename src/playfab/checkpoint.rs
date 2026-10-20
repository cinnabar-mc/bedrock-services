//! Borrowed secure-store representation; secret strings stay inside the checkpoint allocation.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct Snapshot<'a> {
    ticket: &'a str,
    player_id: &'a str,
    reusable_until: SystemTime,
    entity_id: &'a str,
    entity_kind: &'a str,
    entity_token: &'a str,
    entity_expires: SystemTime,
}

impl Session {
    /// Borrows secret values while retaining original absolute renewal deadlines.
    pub(crate) fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            ticket: &self.ticket,
            player_id: &self.player_id,
            reusable_until: self.reusable_until,
            entity_id: &self.entity.id,
            entity_kind: &self.entity.kind,
            entity_token: &self.entity.token,
            entity_expires: self.entity.expires.into(),
        }
    }
}

impl Snapshot<'_> {
    /// Restores a reusable login without extending its original lifetime.
    pub(crate) fn restore(self, now: SystemTime) -> Option<Session> {
        if now >= self.reusable_until
            || self.ticket.is_empty()
            || self.player_id.is_empty()
            || self.entity_id.is_empty()
            || self.entity_kind != EntityKind::TitlePlayerAccount.as_str()
            || self.entity_token.is_empty()
        {
            return None;
        }
        let nanos = self
            .entity_expires
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let expires =
            OffsetDateTime::from_unix_timestamp_nanos(i128::try_from(nanos).ok()?).ok()?;
        let entity = Entity {
            id: self.entity_id.into(),
            kind: self.entity_kind.into(),
            token: Zeroizing::new(self.entity_token.into()),
            expires,
        };
        entity.header_value().ok()?;
        Some(Session {
            ticket: Zeroizing::new(self.ticket.into()),
            player_id: self.player_id.into(),
            entity: Arc::new(entity),
            reusable_until: self.reusable_until,
        })
    }
}
