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
        request: Request,
        token: Arc<Authorization>,
    ) -> Result<Response, Error> {
        self.send_service_with_dispatch(request, token, || {}).await
    }

    /// Reports conservative dispatch only after final signing, immediately before the HTTP await.
    /// The callback must retain uncertain mutation state; it does not prove remote receipt.
    pub(super) async fn send_service_with_dispatch(
        &mut self,
        request: Request,
        token: Arc<Authorization>,
        dispatched: impl FnOnce(),
    ) -> Result<Response, Error> {
        self.send_service_bounded(request, token, crate::http::RESPONSE_LIMIT, dispatched)
            .await
    }

    /// Selects a concrete read budget without changing final signing or issuance rejection.
    pub(super) async fn send_service_with_limit(
        &mut self,
        request: Request,
        token: Arc<Authorization>,
        response_limit: usize,
    ) -> Result<Response, Error> {
        self.send_service_bounded(request, token, response_limit, || {})
            .await
    }

    /// Owns the sole final policy, signature, dispatch and bounded response path.
    async fn send_service_bounded(
        &mut self,
        mut request: Request,
        token: Arc<Authorization>,
        response_limit: usize,
        dispatched: impl FnOnce(),
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
        dispatched();
        let response = self.http.send_with_limit(request, response_limit).await?;
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
                    let mut quoted = false;
                    let mut escaped = false;
                    value
                        .split(|character| {
                            if escaped {
                                escaped = false;
                                return false;
                            }
                            match character {
                                '\\' if quoted => escaped = true,
                                '"' => quoted = !quoted,
                                ',' if !quoted => return true,
                                _ => {}
                            }
                            false
                        })
                        .any(|part| {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Quoted commas and escaped quotes cannot introduce an authentication error parameter.
    #[test]
    fn challenge_parameters_regression() {
        for (challenge, expired) in [
            (
                r#"Token error="insufficient_scope", error_description="denied,error=token_expired,contact support""#,
                false,
            ),
            (
                r#"Token error_description="denied,\"error=token_expired,contact support""#,
                false,
            ),
            (r#"Token error="token_expired""#, true),
            (
                r#"Token error_description="a,b", error="token_expired""#,
                true,
            ),
            (r#"Bearer realm="a,b", Token error="token_expired""#, true),
        ] {
            let mut response = Response {
                status: StatusCode::UNAUTHORIZED,
                headers: Default::default(),
                body: Default::default(),
            };
            response
                .headers
                .insert("www-authenticate", challenge.parse().unwrap());
            assert_eq!(token_expired(&response), expired, "{challenge}");
            response.status = StatusCode::FORBIDDEN;
            assert!(!token_expired(&response));
        }
    }
}
