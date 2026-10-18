//! Account-borrowed Multiplayer Session Directory lifecycle and invitation writes.
//!
//! Each call performs one bounded HTTP operation after credential acquisition.
//! Sessions retain account/proof identity and optimistic validators, with exclusive
//! mutation through Rust borrows. No RTA socket, subscription task, retry loop or
//! remote cleanup on Drop exists. Supply an active RTA binding, explicitly publish
//! activity after creation, reconcile canceled writes and call leave on shutdown.
//! Title custom data can contain admission nonces; these owners have no Debug.

mod join;
mod publish;
mod types;

pub use join::{JoinAttempt, JoinOutcome, MAX_JOIN_ATTEMPTS};
pub use publish::PublishAttempt;
pub use types::{
    Binding, Description, Invitation, Member, MemberData, Publish, Reference, Restriction, Section,
    Session,
};

use super::{Account, Authorization, social::validate_xuid};
use crate::http::Response;
use reqwest::{
    Method, StatusCode,
    header::{HeaderName, HeaderValue},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    sync::Arc,
};
use url::Url;

pub(super) const ENDPOINT: &str = "https://sessiondirectory.xboxlive.com";
pub(super) const CONTRACT: &str = "107";
const CHANGE_EVERYTHING: &str = "everything";
/// Largest encoded request body, including its trailing newline.
pub const MAX_REQUEST_BYTES: usize = crate::http::RESPONSE_LIMIT;
/// Largest accepted session-template or session-name component.
pub const MAX_NAME_BYTES: usize = 256;
/// Largest retained service ETag.
pub const MAX_ETAG_BYTES: usize = 1024;
/// Largest complete session membership snapshot retained by this API.
pub const MAX_MEMBERS: usize = 4096;

/// Redacted local, lifecycle and HTTP failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Account acquisition or bounded HTTP failed.
    #[error(transparent)]
    Service(#[from] crate::Error),
    /// The service refused an operation; diagnostics and response text are not retained.
    #[error("session directory returned HTTP {0}")]
    Status(u16),
    /// A supplied or received document violates the local API contract.
    #[error("invalid session directory data: {0}")]
    Invalid(&'static str),
    /// A body, membership list or metadata field exceeds its bound.
    #[error("session directory capacity exceeded")]
    Limit,
    /// This local session membership ended.
    #[error("session directory owner is closed")]
    Closed,
    /// The session or join attempt belongs to a different account/proof owner.
    #[error("session directory account owner mismatch")]
    WrongAccount,
    /// A previous write may have applied or observed a conflict; refresh before another mutation.
    #[error("session directory owner requires synchronization")]
    SyncRequired,
    /// The response carries an older change number; the current snapshot is preserved.
    #[error("stale session directory snapshot")]
    Stale,
    /// A successful, exhausted, failed or canceled join write cannot be replayed.
    #[error("session directory join attempt is no longer writable")]
    JoinFinished,
    /// A dispatched or completed publication cannot be replayed.
    #[error("session directory publication is no longer writable")]
    PublishFinished,
}

/// The result of one explicit refresh or write, without hidden retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Update {
    /// A complete new response replaced the snapshot.
    Updated,
    /// A conditional GET confirmed the existing validator.
    Unchanged,
    /// The service deleted the session, or this account explicitly left it.
    Closed,
    /// A conditional write was explicitly rejected; synchronize before another write.
    PreconditionFailed,
}

/// Borrows one existing account's HTTP, proof and per-relying-party XSTS cache.
pub struct Directory<'a> {
    account: &'a mut Account,
    #[cfg(test)]
    fixture_base: Option<Url>,
}

impl Account {
    /// Borrows the concrete MPSD owner without acquiring credentials or starting subscriptions.
    pub fn mpsd(&mut self) -> Directory<'_> {
        Directory {
            account: self,
            #[cfg(test)]
            fixture_base: None,
        }
    }
}

impl Directory<'_> {
    /// Reads one complete referenced session; missing members replace, rather than merge, old state.
    ///
    /// # Errors
    /// Returns a redacted service/status/metadata error; no remote membership is created.
    pub async fn read(&mut self, reference: &Reference) -> Result<Session, Error> {
        let url = self.session_url(reference)?;
        let token = self.token(&url, None).await?;
        let response = self
            .send(Arc::clone(&token), Method::GET, url, None, None)
            .await?;
        require(&response, StatusCode::OK)?;
        self.session(reference.clone(), token.xuid(), response)
    }

    /// Creates membership once with If-None-Match:*, returning its owner before activity publication.
    /// Call publish_activity separately, retaining this owner if that later operation fails.
    /// Dropping/canceling this future may leave a remote session: reconcile by the supplied reference.
    ///
    /// # Errors
    /// Returns redacted account/status/metadata failures. Existing sessions are never overwritten.
    pub async fn publish(
        &mut self,
        reference: &Reference,
        config: Publish,
    ) -> Result<Session, Error> {
        let mut attempt = self.publish_attempt(reference, config)?;
        self.publish_retained(&mut attempt).await
    }

    /// Explicitly refreshes this owner; canceled/failed writes force an unconditional GET.
    /// Branch rotations remain valid; lower change numbers on the same known branch are rejected.
    ///
    /// # Errors
    /// Returns redacted service/status, account mismatch, stale or metadata errors.
    pub async fn sync(&mut self, session: &mut Session) -> Result<Update, Error> {
        self.check(session, false)?;
        let url = self.session_url(&session.reference)?;
        let token = self.token(&url, Some(&session.owner)).await?;
        let condition = (!session.uncertain)
            .then(|| session.etag.clone())
            .flatten()
            .map(|etag| (reqwest::header::IF_NONE_MATCH, etag));
        let conditional = condition.is_some();
        let response = self.send(token, Method::GET, url, None, condition).await?;
        match response.status {
            StatusCode::OK => {
                install(session, response)?;
                Ok(Update::Updated)
            }
            StatusCode::NOT_MODIFIED if conditional => Ok(Update::Unchanged),
            StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => {
                session.end();
                Ok(Update::Closed)
            }
            _ => Err(Error::Status(response.status.as_u16())),
        }
    }

    /// Replaces title-owned session custom properties using the owner's latest exact ETag when present.
    ///
    /// # Errors
    /// Returns redacted lifecycle/service failures. Conflict or uncertain writes require sync.
    pub async fn set_properties(
        &mut self,
        session: &mut Session,
        custom: &Value,
    ) -> Result<Update, Error> {
        self.update(
            session,
            encode(&PropertiesPatch {
                properties: CustomPatch { custom },
            })?,
            false,
        )
        .await
    }

    /// Replaces session custom properties only under the original active membership and validator.
    /// Use this for title admission state that must not overwrite an observed replacement session.
    ///
    /// # Errors
    /// Rejects dirty/closed owners, replaced bindings and absent validators before mutation I/O.
    pub async fn set_properties_bound(
        &mut self,
        session: &mut Session,
        binding: Binding,
        custom: &Value,
    ) -> Result<Update, Error> {
        self.check(session, true)?;
        if !session.is_bound(binding) {
            return Err(Error::Invalid("session property binding"));
        }
        if session.etag.is_none() {
            return Err(Error::Invalid("session property validator"));
        }
        self.set_properties(session, custom).await
    }

    /// Replaces this account's mutable member custom properties; never modifies another member.
    ///
    /// # Errors
    /// Returns redacted lifecycle/service failures. Conflict or uncertain writes require sync.
    pub async fn set_member_properties(
        &mut self,
        session: &mut Session,
        custom: &Value,
    ) -> Result<Update, Error> {
        self.update(
            session,
            encode(&MembersPatch {
                members: MePatch {
                    me: PropertiesPatch {
                        properties: CustomPatch { custom },
                    },
                },
            })?,
            false,
        )
        .await
    }

    /// Explicitly binds this membership to the caller's current RTA connection after reconnect.
    /// The caller orders connection generations; the SDK creates no subscription or reconciliation task.
    ///
    /// # Errors
    /// Returns redacted lifecycle/service failures. Conflict or uncertain writes require sync.
    pub async fn bind(&mut self, session: &mut Session, binding: Binding) -> Result<Update, Error> {
        self.update(session, encode(&json!({"members":{"me":{"properties":{"system":{
            "active":true,"connection":binding.connection,"subscription":{"id":binding.subscription.to_string().to_uppercase(),"changeTypes":[CHANGE_EVERYTHING]}}}}}}))?, false).await
    }

    /// Removes only this account's membership using members.me:null. Success closes the local owner.
    /// A failed/canceled leave remains explicitly reconcilable; Drop never sends this request.
    ///
    /// # Errors
    /// Returns redacted lifecycle/service failures. Conflict or uncertain writes require sync.
    pub async fn leave(&mut self, session: &mut Session) -> Result<Update, Error> {
        self.update(session, encode(&json!({"members":{"me":null}}))?, true)
            .await
    }

    /// Removes this owner's membership only under its original binding and exact current validator.
    /// The retained binding permits cleanup after its RTA socket ends; synchronize dirty owners first.
    ///
    /// # Errors
    /// Returns lifecycle, ownership, missing-validator or service errors without deleting a replacement.
    pub async fn leave_bound(
        &mut self,
        session: &mut Session,
        binding: Binding,
    ) -> Result<Update, Error> {
        self.check(session, true)?;
        if !session.is_bound(binding) {
            return Err(Error::Invalid("session cleanup binding"));
        }
        if session.etag.is_none() {
            return Err(Error::Invalid("session cleanup validator"));
        }
        self.leave(session).await
    }

    /// Publishes the existing membership as this account's discoverable activity, once.
    /// Social::activities remains the single read/search API. Cancellation can leave an activity published.
    ///
    /// # Errors
    /// Returns redacted account/lifecycle/status errors, without retrying or discarding the session owner.
    pub async fn publish_activity(&mut self, session: &Session) -> Result<(), Error> {
        self.check(session, true)?;
        let bytes = encode(&json!({"type":"activity","version":1,"sessionRef":session.reference}))?;
        let url = self.destination(&["handles"])?;
        let token = self.token(&url, Some(&session.owner)).await?;
        let response = self
            .send(token, Method::POST, url, Some(bytes), None)
            .await?;
        if matches!(response.status, StatusCode::OK | StatusCode::CREATED) {
            Ok(())
        } else {
            Err(Error::Status(response.status.as_u16()))
        }
    }

    /// Sends one invitation to an explicit XUID/title, returning the created handle.
    /// Title selection and notification reception belong to the application; cancellation may still send it.
    ///
    /// # Errors
    /// Returns redacted input/lifecycle/status or response account/session binding failures.
    pub async fn invite(
        &mut self,
        session: &Session,
        xuid: &str,
        title_id: &str,
    ) -> Result<Invitation, Error> {
        self.check(session, true)?;
        validate_xuid(xuid)?;
        if title_id.is_empty()
            || title_id.len() > 10
            || !title_id.bytes().all(|c| c.is_ascii_digit())
            || !title_id.parse::<u32>().is_ok_and(|id| id != 0)
        {
            return Err(Error::Invalid("invitation title"));
        }
        let bytes = encode(
            &json!({"type":"invite","version":1,"sessionRef":session.reference,
            "invitedXuid":xuid,"inviteAttributes":{"titleId":title_id}}),
        )?;
        let url = self.destination(&["handles"])?;
        let token = self.token(&url, Some(&session.owner)).await?;
        let response = self
            .send(token, Method::POST, url, Some(bytes), None)
            .await?;
        if !matches!(response.status, StatusCode::OK | StatusCode::CREATED) {
            return Err(Error::Status(response.status.as_u16()));
        }
        let invite: Invitation = response.json()?;
        if invite.id.is_nil()
            || invite.invited_xuid.as_deref().is_some_and(|id| id != xuid)
            || invite
                .sender_xuid
                .as_deref()
                .is_some_and(|id| id != session.owner)
            || invite.reference.as_ref().is_some_and(|r| {
                Reference::try_from(r).map_or(true, |r| !session.reference.same(&r))
            })
        {
            return Err(Error::Invalid("invitation identity"));
        }
        Ok(invite)
    }

    /// Serializes one owner's mutation with optimistic concurrency and an explicit dirty-before-I/O fence.
    async fn update(
        &mut self,
        session: &mut Session,
        bytes: Vec<u8>,
        leave: bool,
    ) -> Result<Update, Error> {
        self.check(session, true)?;
        let url = self.session_url(&session.reference)?;
        let token = self.token(&url, Some(&session.owner)).await?;
        let condition = session
            .etag
            .clone()
            .unwrap_or_else(|| HeaderValue::from_static("*"));
        let request = self.request(
            Method::PUT,
            url,
            Some(bytes),
            Some((reqwest::header::IF_MATCH, condition)),
        )?;
        session.uncertain = true;
        let response = self.account.send_service(request, token).await?;
        match response.status {
            StatusCode::OK => {
                install(session, response)?;
                if leave {
                    session.end();
                    Ok(Update::Closed)
                } else {
                    Ok(Update::Updated)
                }
            }
            StatusCode::NO_CONTENT => {
                session.end();
                Ok(Update::Closed)
            }
            StatusCode::PRECONDITION_FAILED => Ok(Update::PreconditionFailed),
            _ => Err(Error::Status(response.status.as_u16())),
        }
    }

    /// Rejects account/proof cross-use and dirty/closed mutations before account or service I/O.
    fn check(&self, session: &Session, writable: bool) -> Result<(), Error> {
        if session.proof != *self.account.key.verifying_key() {
            return Err(Error::WrongAccount);
        }
        if session.closed {
            return Err(Error::Closed);
        }
        if writable && session.uncertain {
            return Err(Error::SyncRequired);
        }
        Ok(())
    }

    /// Acquires the exact destination's policy-selected credential and checks its Xbox identity.
    async fn token(&mut self, url: &Url, owner: Option<&str>) -> Result<Arc<Authorization>, Error> {
        let token = self.account.authorize_service(url).await?;
        validate_xuid(token.xuid())?;
        if owner.is_some_and(|owner| owner != token.xuid()) {
            return Err(Error::WrongAccount);
        }
        Ok(token)
    }

    /// Constructs only this service's fixed endpoint plus individually escaped components.
    fn destination(&self, path: &[&str]) -> Result<Url, Error> {
        let mut url = Url::parse(ENDPOINT).map_err(|_| Error::Invalid("directory endpoint"))?;
        #[cfg(test)]
        if let Some(base) = &self.fixture_base {
            url = base.clone();
        }
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("directory path"))?
            .pop_if_empty()
            .extend(path);
        Ok(url)
    }

    /// Constructs the complete fixed-owner URL without following Content-Location to another origin.
    fn session_url(&self, reference: &Reference) -> Result<Url, Error> {
        self.destination(&[
            "serviceconfigs",
            &reference.scid.to_string(),
            "sessionTemplates",
            &reference.template,
            "sessions",
            &reference.name,
        ])
    }

    /// Materializes body, conditional and contract headers before the shared final signing boundary.
    fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
        condition: Option<(HeaderName, HeaderValue)>,
    ) -> Result<reqwest::Request, Error> {
        let mut request = self
            .account
            .http
            .request(method, url.as_str())
            .header("x-xbl-contract-version", CONTRACT);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .header("content-length", body.len())
                .body(body);
        }
        if let Some((name, value)) = condition {
            request = request.header(name, value);
        }
        Ok(request.build().map_err(crate::Error::from)?)
    }

    /// Performs one final signed service request, retaining no token diagnostic text.
    async fn send(
        &mut self,
        token: Arc<Authorization>,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
        condition: Option<(HeaderName, HeaderValue)>,
    ) -> Result<Response, Error> {
        let request = self.request(method, url, body, condition)?;
        Ok(self.account.send_service(request, token).await?)
    }

    /// Installs a new local owner only after complete bounded identity/metadata validation.
    fn session(
        &self,
        reference: Reference,
        owner: &str,
        response: Response,
    ) -> Result<Session, Error> {
        let mut session = Session {
            reference,
            owner: owner.to_owned(),
            proof: *self.account.key.verifying_key(),
            description: Description::default(),
            etag: None,
            closed: false,
            uncertain: false,
        };
        install(&mut session, response)?;
        Ok(session)
    }
}

/// Installs a fresh complete response, comparing change numbers only within the same known branch.
fn install(session: &mut Session, response: Response) -> Result<(), Error> {
    let description: Description = response.json()?;
    if description.members.len() > MAX_MEMBERS {
        return Err(Error::Limit);
    }
    if description
        .members
        .get("me")
        .and_then(Option::as_ref)
        .and_then(Member::xuid)
        .is_some_and(|owner| owner != session.owner)
    {
        return Err(Error::Invalid("session member identity"));
    }
    if description
        .reference
        .as_ref()
        .is_some_and(|r| Reference::try_from(r).map_or(true, |r| !session.reference.same(&r)))
    {
        return Err(Error::Invalid("session response reference"));
    }
    let same_branch = session
        .description
        .branch
        .zip(description.branch)
        .is_some_and(|(a, b)| a == b);
    if same_branch
        && session
            .description
            .change_number
            .zip(description.change_number)
            .is_some_and(|(a, b)| b < a)
    {
        return Err(Error::Stale);
    }
    let etag = types::etag(&response.headers)?;
    session.description = description;
    session.etag = etag;
    session.uncertain = false;
    Ok(())
}

/// Builds only the caller's initialized active membership; subscription identity remains stable across retries.
fn member(binding: Binding, data: MemberData) -> Value {
    let mut member = json!({"constants":{"system":{"initialize":true}},"properties":{"system":{
        "active":true,"connection":binding.connection,"subscription":{"id":binding.subscription.to_string().to_uppercase(),"changeTypes":[CHANGE_EVERYTHING]}}}});
    if let Some(custom) = data.constants {
        member["constants"]["custom"] = custom;
    }
    if let Some(custom) = data.properties {
        member["properties"]["custom"] = custom;
    }
    member
}

/// Rejects unexpected status without retaining peer-controlled diagnostics.
fn require(response: &Response, status: StatusCode) -> Result<(), Error> {
    if response.status == status {
        Ok(())
    } else {
        Err(Error::Status(response.status.as_u16()))
    }
}

/// Writes bounded JSON without allocating an arbitrarily large serialized intermediate.
fn encode(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    struct Body(Vec<u8>);
    impl Write for Body {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > (MAX_REQUEST_BYTES - 1).saturating_sub(self.0.len()) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut body = Body(Vec::new());
    serde_json::to_writer(&mut body, value).map_err(|_| Error::Limit)?;
    body.0.push(b'\n');
    Ok(body.0)
}

/// Borrows title metadata while encoding, avoiding a cloned intermediate JSON tree.
#[derive(Serialize)]
struct CustomPatch<'a> {
    custom: &'a Value,
}
/// Encodes the mutable property section of a session or member.
#[derive(Serialize)]
struct PropertiesPatch<'a> {
    properties: CustomPatch<'a>,
}
/// Selects only the authenticated member alias.
#[derive(Serialize)]
struct MePatch<'a> {
    me: PropertiesPatch<'a>,
}
/// Encodes a member-only property patch without reproducing snapshot state.
#[derive(Serialize)]
struct MembersPatch<'a> {
    members: MePatch<'a>,
}

#[cfg(test)]
mod tests;
