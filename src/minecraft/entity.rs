use super::Minecraft;
use crate::{Error, playfab};
use std::sync::Arc;

impl Minecraft {
    /// Acquires or reuses a title/master-player credential for the discovered title.
    ///
    /// Renewal happens on demand within the expiry margin. An expired or once
    /// rejected source causes one fresh PlayFab login; no background task runs.
    /// Cancellation leaves previously installed stages available to the owner.
    ///
    /// # Errors
    /// Returns bounded HTTP failures or rejects missing, expired or mismatched
    /// credential metadata. A second rejected exchange is returned to the caller.
    pub async fn entity(
        &mut self,
        kind: playfab::EntityKind,
    ) -> Result<Arc<playfab::Entity>, Error> {
        for attempt in 0..2 {
            let session = self.playfab().await?;
            let now = self.http.now();
            if let Some(entity) = self.entities.get(&kind).filter(|entity| entity.valid(now)) {
                return Ok(Arc::clone(entity));
            }
            let source = self
                .entities
                .get(&kind)
                .filter(|entity| entity.unexpired(now))
                .or_else(|| {
                    self.entities
                        .get(&playfab::EntityKind::TitlePlayerAccount)
                        .filter(|entity| entity.unexpired(now))
                })
                .unwrap_or(&session.entity);
            if !source.unexpired(now) && attempt == 0 {
                self.playfab = None;
                self.entities.clear();
                continue;
            }
            if !source.unexpired(now) {
                return Err(Error::Invalid("expired PlayFab exchange source"));
            }
            let id = match kind {
                playfab::EntityKind::TitlePlayerAccount => session.entity.id(),
                playfab::EntityKind::MasterPlayerAccount => session.player_id(),
            };
            let title = &self
                .environment
                .as_ref()
                .ok_or(Error::Invalid("missing discovery"))?
                .play_fab_title_id;
            match playfab::exchange(&mut self.http, title, source, kind, id).await {
                Ok(entity) => {
                    let entity = Arc::new(entity);
                    self.entities.insert(kind, Arc::clone(&entity));
                    return Ok(entity);
                }
                Err(Error::Status { status, .. })
                    if status == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 =>
                {
                    self.playfab = None;
                    self.entities.clear();
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::Invalid("PlayFab entity acquisition exhausted"))
    }
}
