//! Final authorized service traffic shared by concrete Xbox API owners.
use super::{Account, Authorization};
use crate::{Error, http::Response};
use reqwest::{Request, StatusCode};
use std::sync::Arc;

impl Account {
    /// Signs the final concrete request with the exact acquired issuance, then sends it once.
    /// Callers own destination/body and service headers; the HTTP edge fills absent transport defaults.
    pub(super) async fn send_service(
        &mut self,
        mut request: Request,
        token: Arc<Authorization>,
    ) -> Result<Response, Error> {
        let (party, policy) = self
            .service_policy(request.url())
            .ok_or(Error::Invalid("unmatched service endpoint"))?;
        if party != token.relying_party() {
            return Err(Error::Invalid("service relying party mismatch"));
        }
        request
            .headers_mut()
            .insert(reqwest::header::AUTHORIZATION, token.header_value()?);
        self.http.prepare_signature(&mut request)?;
        policy.sign(&mut request, &self.key, self.http.now())?;
        let response = self.http.send(request).await?;
        if token_expired(&response) {
            self.reject(&token);
        }
        Ok(response)
    }
}

/// Invalidates credentials only for an explicit Xbox token_expired authentication challenge.
fn token_expired(response: &Response) -> bool {
    response.status == StatusCode::UNAUTHORIZED
        && response
            .headers
            .get_all("www-authenticate")
            .iter()
            .any(|value| {
                value.to_str().is_ok_and(|value| {
                    value.split(',').any(|part| {
                        let part = part.trim();
                        let part = part
                            .get(..6)
                            .filter(|prefix| prefix.eq_ignore_ascii_case("token "))
                            .map_or(part, |_| part[6..].trim());
                        part.split_once('=').is_some_and(|(name, value)| {
                            name.trim().eq_ignore_ascii_case("error")
                                && value
                                    .trim()
                                    .trim_matches(['\"', '\''])
                                    .eq_ignore_ascii_case("token_expired")
                        })
                    })
                })
            })
}
