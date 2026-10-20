//! Optional service cache bound to account policy, validated routes and original expiry.

use super::*;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct Snapshot<'a> {
    config: Config,
    environment: Environment,
    session_id: uuid::Uuid,
    observed: SystemTime,
    #[serde(default)]
    saved_local: Option<SystemTime>,
    #[serde(default)]
    saved_service: Option<SystemTime>,
    #[serde(borrow)]
    playfab: Option<playfab::checkpoint::Snapshot<'a>>,
    #[serde(borrow)]
    authorization: Option<token::checkpoint::Snapshot<'a>>,
}

impl Minecraft {
    /// Saves optional game credentials without making account persistence depend on cache size.
    pub(super) fn service_checkpoint(&self) -> Result<xbox::Checkpoint, Error> {
        let account = self.xbox.checkpoint()?;
        if let Some(saved) = &self.restored {
            return account.with_services(saved);
        }
        if self.playfab.is_none() && self.authorization.is_none() {
            return Ok(account);
        }
        let (Some(environment), Some(observed)) = (&self.environment, self.http.response_time())
        else {
            return Ok(account);
        };
        let saved_local = self.http.local_time();
        let snapshot = Snapshot {
            config: self.config.clone(),
            environment: environment.clone(),
            session_id: self.session_id,
            observed,
            saved_local: Some(saved_local),
            saved_service: Some(self.http.now()),
            playfab: self.playfab.as_ref().map(|session| session.snapshot()),
            authorization: self.authorization.as_ref().map(|token| token.snapshot()),
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(xbox::MAX_CHECKPOINT_BYTES));
        // Stop before growth so optional service metadata cannot displace required credentials.
        let mut writer = Bounded(&mut bytes);
        if serde_json::to_writer(&mut writer, &snapshot).is_err() {
            return Ok(account);
        }
        account.with_services(&bytes)
    }

    /// Reuses a policy-bound auth route only while its saved credential and clock remain valid.
    pub(super) fn resume_service_checkpoint(&mut self) -> bool {
        let Some(bytes) = self.restored.as_ref() else {
            return false;
        };
        let Ok(snapshot) = serde_json::from_slice::<Snapshot<'_>>(bytes) else {
            return false;
        };
        if snapshot.config != self.config
            || snapshot.session_id.is_nil()
            || validate_service_url(&snapshot.environment.service_uri).is_err()
            || validate_service_url(&snapshot.environment.issuer).is_err()
            || playfab::login_url(&snapshot.environment.play_fab_title_id).is_err()
        {
            return false;
        }
        let (Some(local), Some(service)) = (snapshot.saved_local, snapshot.saved_service) else {
            return false;
        };
        let Some(now) = self.http.resumed_time(service, local) else {
            return false;
        };
        if service < snapshot.observed {
            return false;
        }
        let Some(authorization) = snapshot
            .authorization
            .and_then(|saved| saved.restore(now).ok())
        else {
            return false;
        };
        self.playfab = snapshot
            .playfab
            .and_then(|saved| saved.restore(now))
            .map(Arc::new);
        if let Some(session) = &self.playfab {
            self.entities.insert(
                playfab::EntityKind::TitlePlayerAccount,
                Arc::clone(&session.entity),
            );
        }
        self.authorization = Some(Arc::new(authorization));
        self.environment = Some(snapshot.environment);
        self.session_id = snapshot.session_id;
        self.restored_route = true;
        self.http.resume_clock(now, snapshot.observed);
        self.restored = None;
        true
    }

    /// Admits matching entries after discovery supplies a new service clock observation.
    pub(super) fn admit_service_checkpoint(&mut self, response_date: Option<SystemTime>) {
        let Some(bytes) = self.restored.take() else {
            return;
        };
        let Ok(snapshot) = serde_json::from_slice::<Snapshot<'_>>(&bytes) else {
            return;
        };
        if snapshot.config != self.config
            || self.environment.as_ref() != Some(&snapshot.environment)
            || response_date.is_none_or(|now| now < snapshot.observed)
            || snapshot.session_id.is_nil()
        {
            return;
        }
        let now = self.http.now();
        self.session_id = snapshot.session_id;
        self.playfab = snapshot
            .playfab
            .and_then(|saved| saved.restore(now))
            .map(Arc::new);
        if let Some(session) = &self.playfab {
            self.entities.insert(
                playfab::EntityKind::TitlePlayerAccount,
                Arc::clone(&session.entity),
            );
        }
        self.authorization = snapshot
            .authorization
            .and_then(|saved| saved.restore(now).ok())
            .map(Arc::new);
        self.xbox.admit_service_clock(&self.http);
    }
}

struct Bounded<'a>(&'a mut Vec<u8>);

impl std::io::Write for Bounded<'_> {
    /// Rejects optional metadata before the bounded secret allocation would grow.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0.capacity() - self.0.len() {
            return Err(std::io::Error::other("service checkpoint size"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// The checkpoint writer has no buffered transport to flush.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
