use super::{Binding, Directory, Error, MemberData, Reference, Session, encode, member, types};
use p256::ecdsa::VerifyingKey;
use reqwest::{Method, StatusCode, header::HeaderValue};
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Maximum explicit PUT attempts permitted for one handle join; only 412 permits another.
pub const MAX_JOIN_ATTEMPTS: u8 = 3;
const JOIN_RETRY_DELAY: Duration = Duration::from_millis(250);

/// One account/proof-bound join intent with stable body and subscription IDs.
/// A canceled or failed network write is sealed because it may have applied remotely.
/// Only an explicit service 412 response permits another bounded attempt.
pub struct JoinAttempt {
    proof: VerifyingKey,
    handle: Uuid,
    initial: Option<Value>,
    body: Option<Zeroizing<Vec<u8>>>,
    owner: Option<String>,
    condition: HeaderValue,
    attempts: u8,
    ready: bool,
}

/// One attempt's concrete result; the caller owns retry waiting, deadlines and cancellation.
#[non_exhaustive]
pub enum JoinOutcome {
    /// Membership was created; activity publication remains a separate explicit operation.
    Joined(Box<Session>),
    /// The write was rejected without applying; keep the same JoinAttempt and wait before calling join again.
    Precondition {
        /// Source-based suggested delay, with no internal sleep or task.
        retry_after: Duration,
        /// Number of remaining service attempts on this owner.
        remaining: u8,
    },
    /// The last permitted attempt received 412; this owner cannot issue another write.
    Exhausted,
}

impl Directory<'_> {
    /// Creates a bounded join intent without account or service I/O.
    /// Use an activity/invitation's explicit handle ID and this account's actual RTA binding.
    ///
    /// # Errors
    /// Rejects nil handles and oversize member documents.
    pub fn join_attempt(
        &self,
        handle: Uuid,
        binding: Binding,
        data: MemberData,
    ) -> Result<JoinAttempt, Error> {
        if handle.is_nil() {
            return Err(Error::Invalid("join handle"));
        }
        let initial = json!({"members":{"me":member(binding, data)}});
        let _ = encode(&initial)?;
        Ok(JoinAttempt {
            proof: *self.account.key.verifying_key(),
            handle,
            initial: Some(initial),
            body: None,
            owner: None,
            condition: HeaderValue::from_static("*"),
            attempts: 0,
            ready: true,
        })
    }

    /// Attempts one handle join. Only 412 reopens the same stable intent, at most three times.
    /// Transport failure, cancellation after admission and any other status seal the intent;
    /// do not create a replacement intent blindly, because membership may already exist.
    ///
    /// # Errors
    /// Returns redacted account/status/Content-Location failures or JoinFinished for a sealed intent.
    pub async fn join(&mut self, attempt: &mut JoinAttempt) -> Result<JoinOutcome, Error> {
        if attempt.proof != *self.account.key.verifying_key() {
            return Err(Error::WrongAccount);
        }
        if !attempt.ready || attempt.attempts >= MAX_JOIN_ATTEMPTS {
            return Err(Error::JoinFinished);
        }
        let url = self.destination(&["handles", &attempt.handle.to_string(), "session"])?;
        let token = self.token(&url, attempt.owner.as_deref()).await?;
        if attempt.body.is_none() {
            let initial = attempt.initial.as_mut().ok_or(Error::JoinFinished)?;
            initial["members"]["me"]["constants"]["system"]["xuid"] = json!(token.xuid());
            attempt.body = Some(Zeroizing::new(encode(initial)?));
            attempt.initial = None;
            attempt.owner = Some(token.xuid().to_owned());
        }
        let body = attempt.body.as_ref().ok_or(Error::JoinFinished)?.to_vec();
        let request = self.request(
            Method::PUT,
            url,
            Some(body),
            Some((reqwest::header::IF_MATCH, attempt.condition.clone())),
        )?;
        // Commit ambiguity before the first network poll, retaining the same bytes on explicit 412 retries.
        attempt.attempts += 1;
        attempt.ready = false;
        let response = self.account.send_service(request, token).await?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            attempt.condition =
                types::etag(&response.headers)?.unwrap_or_else(|| HeaderValue::from_static("*"));
            if attempt.attempts == MAX_JOIN_ATTEMPTS {
                return Ok(JoinOutcome::Exhausted);
            }
            attempt.ready = true;
            return Ok(JoinOutcome::Precondition {
                retry_after: JOIN_RETRY_DELAY * (1_u32 << (attempt.attempts - 1)),
                remaining: MAX_JOIN_ATTEMPTS - attempt.attempts,
            });
        }
        super::require(&response, StatusCode::OK)?;
        let location = response
            .headers
            .get(reqwest::header::CONTENT_LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(Error::Invalid("join Content-Location"))?;
        let reference = location_reference(location)?;
        let owner = attempt.owner.as_deref().ok_or(Error::JoinFinished)?;
        Ok(JoinOutcome::Joined(Box::new(
            self.session(reference, owner, response)?,
        )))
    }
}

/// Parses only a valid fixed-service locator; no response-provided authority is ever used for credentials.
pub(super) fn location_reference(location: &str) -> Result<Reference, Error> {
    if location.len() > 6 * super::MAX_NAME_BYTES + 256 {
        return Err(Error::Invalid("join Content-Location"));
    }
    if location.contains('\\')
        || location.split('/').any(|part| {
            let decoded = percent_encoding::percent_decode_str(part).collect::<Vec<_>>();
            matches!(decoded.as_slice(), b"." | b"..")
        })
    {
        return Err(Error::Invalid("join Content-Location path"));
    }
    let base =
        url::Url::parse(super::ENDPOINT).map_err(|_| Error::Invalid("directory endpoint"))?;
    let url = base
        .join(location)
        .map_err(|_| Error::Invalid("join Content-Location"))?;
    if url.origin() != base.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("join Content-Location policy"));
    }
    let parts: Vec<_> = url
        .path_segments()
        .ok_or(Error::Invalid("join Content-Location path"))?
        .collect();
    if parts.len() != 6
        || !parts[0].eq_ignore_ascii_case("serviceconfigs")
        || !parts[2].eq_ignore_ascii_case("sessionTemplates")
        || !parts[4].eq_ignore_ascii_case("sessions")
    {
        return Err(Error::Invalid("join Content-Location path"));
    }
    let decode = |part: &str| {
        percent_encoding::percent_decode_str(part)
            .decode_utf8()
            .map(|value| value.into_owned())
            .map_err(|_| Error::Invalid("join Content-Location encoding"))
    };
    let scid = Uuid::parse_str(&decode(parts[1])?)
        .map_err(|_| Error::Invalid("join Content-Location SCID"))?;
    Reference::new(scid, decode(parts[3])?, decode(parts[5])?)
}
