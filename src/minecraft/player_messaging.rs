//! Minecraft Player Messaging marketing surfaces and inbox interactions.
//!
//! This account-borrowed service retains one distinct messaging session and its
//! continuation. It does not receive Xbox game invitations, join worlds, fetch
//! message artwork or follow links. Callers own polling, deadlines and reporting
//! policy; requests have no implicit retry or background worker.

mod events;
mod types;

pub use events::Event;
pub use types::{
    Button, Category, CategoryInfo, Color, Image, ImageSize, InboxSummary, Message, MessageItem,
    MessageText, Rgb, Session,
};

use super::{Minecraft, append, validate_service_url};
use crate::{Error, http::Response};
use reqwest::{StatusCode, header::HeaderValue};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) struct State {
    session_id: Uuid,
    continuation: Zeroizing<String>,
}

impl State {
    /// Creates the messaging session once, separately from the credential exchange's session.
    pub(super) fn new() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            continuation: Zeroizing::new(String::new()),
        }
    }
}

/// Borrows the existing account's discovery, Minecraft authorization and HTTP owner.
pub struct PlayerMessaging<'a> {
    pub(super) minecraft: &'a mut Minecraft,
}

impl PlayerMessaging<'_> {
    /// Returns the stable Player Messaging session, distinct from the auth session.
    pub fn session_id(&self) -> Uuid {
        self.minecraft.messaging_state.session_id
    }

    /// Refreshes marketing messages and inbox categories without marking or deleting any row.
    /// Only a completely decoded success advances a nonempty continuation token.
    /// Cancellation or failure leaves the previous continuation available to the caller.
    ///
    /// # Errors
    /// Rejects invalid headers/discovery, HTTP/status/body limits and malformed result framing.
    pub async fn refresh(&mut self, language: &str) -> Result<Session, Error> {
        let language = language_header(language)?;
        let body = serde_json::json!({
            "sessionId": self.session_id(),
            "continuationToken": self.minecraft.messaging_state.continuation.as_str(),
        });
        let response = self.send("session", "refresh", language, &body).await?;
        #[derive(Deserialize)]
        struct Envelope {
            result: Option<Session>,
        }
        let session = response
            .json::<Envelope>()?
            .result
            .ok_or(Error::Invalid("player messaging result"))?;
        if !session.continuation_token.is_empty() {
            self.minecraft.messaging_state.continuation =
                Zeroizing::new(session.continuation_token.clone());
        }
        Ok(session)
    }

    /// Reports explicit interactions on the same retained messaging session and continuation.
    /// A successful HTTP response acknowledges the report request, not a game invitation.
    /// Caller-provided times are preserved; absent times use the HTTP edge's wall clock.
    /// The caller owns retry/uncertain-write policy and ordering relative to later interactions.
    ///
    /// # Errors
    /// Rejects empty events/types, invalid timestamps/headers, discovery and bounded HTTP failures.
    pub async fn report_events(
        &mut self,
        language: &str,
        events: &[Event<'_>],
    ) -> Result<(), Error> {
        let language = language_header(language)?;
        let entries = events::entries(events, self.session_id(), SystemTime::now())?;
        let body = serde_json::json!({
            "SessionId": self.session_id(),
            "continuationToken": self.minecraft.messaging_state.continuation.as_str(),
            "events": entries,
        });
        self.send("messages", "event", language, &body).await?;
        Ok(())
    }

    /// Sends one explicit request to the discovered messaging origin with its exact issuance.
    async fn send(
        &mut self,
        collection: &str,
        action: &str,
        language: Option<HeaderValue>,
        body: &impl Serialize,
    ) -> Result<Response, Error> {
        self.minecraft.discover().await?;
        let uri = self
            .minecraft
            .messaging_environment
            .as_ref()
            .and_then(|environment| environment.get("prod"))
            .and_then(|environment| environment.get("serviceUri"))
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Invalid("missing player messaging discovery"))?;
        validate_service_url(uri)?;
        let url = append(uri, &["api", "v1.0", collection, action])?;
        let token = self.minecraft.authorize().await?;
        let mut request = self.minecraft.http.post_json(url.as_str(), body)?;
        request
            .headers_mut()
            .insert("authorization", token.header_value()?);
        request
            .headers_mut()
            .insert("accept", HeaderValue::from_static("application/json"));
        request.headers_mut().insert(
            "session-id",
            HeaderValue::from_str(&self.session_id().to_string())
                .map_err(|_| Error::Invalid("player messaging session"))?,
        );
        if let Some(language) = language {
            request.headers_mut().insert("accept-language", language);
        }
        let response = self
            .minecraft
            .http
            .send_with_limit(request, crate::http::SERVICE_RESPONSE_LIMIT)
            .await?;
        if response.status == StatusCode::UNAUTHORIZED {
            self.minecraft.reject(&token);
        }
        response.success()?;
        Ok(response)
    }
}

/// Validates optional locale header bytes before acquisition; it does not guess a locale grammar.
fn language_header(language: &str) -> Result<Option<HeaderValue>, Error> {
    if language.is_empty() {
        return Ok(None);
    }
    HeaderValue::from_str(language)
        .map(Some)
        .map_err(|_| Error::Invalid("player messaging language header"))
}

#[cfg(test)]
mod tests;
