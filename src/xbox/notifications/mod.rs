//! Explicit, account-borrowed Xbox game invitation inbox reads.
//!
//! Notifications supply untrusted handles and display metadata, not session
//! membership or title admission. Reads never mark, dismiss or accept an invite.
//! The caller owns refresh scheduling, account generation and any later join.

mod types;

pub use types::{
    Actor, GameInvite, GameType, Inbox, InviteAction, InviteOptions, LaunchInfo, Location,
};

use super::{Account, XBOX_RELYING_PARTY, social::validate_xuid};
use crate::Error;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::time::Instant;
use url::Url;

const ENDPOINT: &str = "https://notificationinbox.xboxlive.com";
const CONTRACT: &str = "1";
const CATEGORY: &str = "Microsoft.Xbox.Multiplayer";
const INVITE_TYPE: &str = "GameInvites";

/// Largest requested and retained notification batch.
pub const MAX_INBOX_ITEMS: usize = 200;
/// Largest requested Actions array; a singleton Action may accompany it.
pub const MAX_INBOX_ACTIONS: usize = 5;

/// Borrows the existing account's HTTP client, proof and policy-selected XSTS cache.
pub struct Notifications<'a> {
    account: &'a mut Account,
    #[cfg(test)]
    fixture_base: Option<Url>,
}

impl Account {
    /// Borrows one-shot notification reads without acquiring credentials or starting tasks.
    pub fn notifications(&mut self) -> Notifications<'_> {
        Notifications {
            account: self,
            #[cfg(test)]
            fixture_base: None,
        }
    }
}

impl Notifications<'_> {
    /// Reads this account's game invitation inbox with bounded item/action counts.
    /// Malformed items and unsupported categories are counted separately and skipped;
    /// valid neighbors remain available. No service mutation or implicit retry occurs.
    ///
    /// # Errors
    /// Returns a redacted acquisition/status error, invalid recipient identity,
    /// malformed envelope or an item count exceeding the requested bound.
    pub async fn game_invites(&mut self) -> Result<Inbox, Error> {
        let identity = self.account.authorize(XBOX_RELYING_PARTY).await?;
        validate_xuid(identity.xuid())?;
        let url = self.destination(identity.xuid())?;
        let token = self.account.authorize_service(&url).await?;
        if token.xuid() != identity.xuid() {
            return Err(Error::Invalid("notification recipient identity"));
        }
        let request = self
            .account
            .http
            .request(Method::GET, url.as_str())
            .header("x-xbl-contract-version", CONTRACT)
            .build()?;
        let response = self.account.send_service(request, token).await?;
        if response.status != StatusCode::OK {
            return Err(Error::Status {
                status: response.status,
                xerr: None,
            });
        }
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default)]
            items: Option<Vec<Value>>,
        }
        let envelope: Envelope = response.json()?;
        let items = envelope.items.unwrap_or_default();
        if items.len() > MAX_INBOX_ITEMS {
            return Err(Error::Invalid("notification inbox item count"));
        }
        let mut inbox = Inbox::new(
            identity.xuid().to_owned(),
            self.account.http.now(),
            Instant::now(),
        );
        for item in items {
            match types::decode(item) {
                Ok(Some(invite)) => inbox.invites.push(invite),
                Ok(None) => inbox.unsupported_items += 1,
                Err(_) => inbox.malformed_items += 1,
            }
        }
        Ok(inbox)
    }

    /// Constructs the fixed service's escaped account path and explicit invitation filter.
    fn destination(&self, xuid: &str) -> Result<Url, Error> {
        let mut url = Url::parse(ENDPOINT).map_err(|_| Error::Invalid("notification endpoint"))?;
        #[cfg(test)]
        if let Some(base) = &self.fixture_base {
            url = base.clone();
        }
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("notification path"))?
            .pop_if_empty()
            .extend(["users", xuid, "inbox"]);
        url.query_pairs_mut()
            .append_pair("maxItems", &MAX_INBOX_ITEMS.to_string())
            .append_pair("maxActions", &MAX_INBOX_ACTIONS.to_string())
            .append_pair("subscriptionCategory", CATEGORY)
            .append_pair("subscriptionType", INVITE_TYPE);
        Ok(url)
    }
}

#[cfg(test)]
mod tests;
