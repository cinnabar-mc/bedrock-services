//! Caller-retained creation intent and explicit recovery after an uncertain publication.

use super::{Binding, Directory, Error, Publish, Reference, Session, encode, member, require};
use p256::ecdsa::VerifyingKey;
use reqwest::{Method, StatusCode, header::HeaderValue};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// One fixed account/proof, reference and RTA binding for a single creation write.
/// Keep this owner across cancellation; dropping it performs no remote cleanup.
pub struct PublishAttempt {
    proof: VerifyingKey,
    reference: Reference,
    binding: Binding,
    initial: Option<Value>,
    body: Option<Zeroizing<Vec<u8>>>,
    owner: Option<String>,
    state: State,
}

enum State {
    Prepared,
    Dispatched,
    Rejected,
    Adopted,
}

impl PublishAttempt {
    /// Borrows the original locator for recovery without creating another publication intent.
    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    /// Returns the original connection/subscription pair for guarded membership cleanup.
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// Reports HTTP dispatch whose result has not yielded an owned Session or a known rejection.
    /// A missing session on a later read cannot rule out a still-applying canceled request.
    pub fn needs_reconciliation(&self) -> bool {
        matches!(self.state, State::Dispatched)
    }
}

impl Directory<'_> {
    /// Captures one bounded creation intent without authentication or service I/O.
    ///
    /// # Errors
    /// Rejects an oversized title document before retaining it.
    pub fn publish_attempt(
        &self,
        reference: &Reference,
        config: Publish,
    ) -> Result<PublishAttempt, Error> {
        let mut initial = json!({"properties":{"system":{"joinRestriction":config.join,
            "readRestriction":config.read,"closed":false}},
            "members":{"me":member(config.binding, config.member)}});
        if let Some(custom) = config.constants {
            initial["constants"] = json!({"custom":custom});
        }
        if let Some(custom) = config.properties {
            initial["properties"]["custom"] = custom;
        }
        let _ = encode(&initial)?;
        Ok(PublishAttempt {
            proof: *self.account.key.verifying_key(),
            reference: reference.clone(),
            binding: config.binding,
            initial: Some(initial),
            body: None,
            owner: None,
            state: State::Prepared,
        })
    }

    /// Creates membership once with If-None-Match:*, retaining exact dispatch ambiguity.
    /// Pre-dispatch failures permit an explicit retry; dispatch seals the write permanently.
    /// Only an observed 412 proves rejection. Activity publication remains separate.
    ///
    /// # Errors
    /// Returns redacted acquisition/status/metadata errors or PublishFinished after dispatch.
    pub async fn publish_retained(
        &mut self,
        attempt: &mut PublishAttempt,
    ) -> Result<Session, Error> {
        if attempt.proof != *self.account.key.verifying_key() {
            return Err(Error::WrongAccount);
        }
        if !matches!(attempt.state, State::Prepared) {
            return Err(Error::PublishFinished);
        }
        let url = self.session_url(&attempt.reference)?;
        let token = self.token(&url, attempt.owner.as_deref()).await?;
        if attempt.body.is_none() {
            let initial = attempt.initial.as_mut().ok_or(Error::PublishFinished)?;
            initial["members"]["me"]["constants"]["system"]["xuid"] = json!(token.xuid());
            attempt.body = Some(Zeroizing::new(encode(initial)?));
            attempt.initial = None;
            attempt.owner = Some(token.xuid().to_owned());
        }
        let request = self.request(
            Method::PUT,
            url,
            Some(
                attempt
                    .body
                    .as_ref()
                    .ok_or(Error::PublishFinished)?
                    .to_vec(),
            ),
            Some((
                reqwest::header::IF_NONE_MATCH,
                HeaderValue::from_static("*"),
            )),
        )?;
        let response = self
            .account
            .send_service_with_dispatch(request, token, || attempt.state = State::Dispatched)
            .await?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            attempt.state = State::Rejected;
        }
        require(&response, StatusCode::CREATED)?;
        let session = self.session(
            attempt.reference.clone(),
            attempt.owner.as_deref().ok_or(Error::PublishFinished)?,
            response,
        )?;
        attempt.state = State::Adopted;
        Ok(session)
    }

    /// Reads an uncertain creation and adopts only its original active membership and validator.
    /// No failure, including 404, discards the original recovery obligation.
    ///
    /// # Errors
    /// Rejects different accounts, replaced bindings, absent validators and malformed snapshots.
    pub async fn reconcile_publish(
        &mut self,
        attempt: &mut PublishAttempt,
    ) -> Result<Session, Error> {
        if attempt.proof != *self.account.key.verifying_key() {
            return Err(Error::WrongAccount);
        }
        if !attempt.needs_reconciliation() {
            return Err(Error::PublishFinished);
        }
        let owner = attempt.owner.as_deref().ok_or(Error::PublishFinished)?;
        let url = self.session_url(&attempt.reference)?;
        let token = self.token(&url, Some(owner)).await?;
        let response = self.send(token, Method::GET, url, None, None).await?;
        require(&response, StatusCode::OK)?;
        let session = self.session(attempt.reference.clone(), owner, response)?;
        if !session.is_bound(attempt.binding) || session.etag.is_none() {
            return Err(Error::Invalid("publication recovery binding or validator"));
        }
        attempt.state = State::Adopted;
        Ok(session)
    }
}
