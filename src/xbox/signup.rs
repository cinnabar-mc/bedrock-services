//! Proof-bound hosted profile creation from the original SISU rejection.

use crate::{
    Error,
    http::{Response, SISU_ORIGIN},
    signature::SignaturePolicy,
};
use p256::ecdsa::SigningKey;
use reqwest::{Method, Request, StatusCode};
use serde::Deserialize;
use std::{collections::BTreeMap, fmt, time::SystemTime};
use url::Url;
use zeroize::Zeroizing;

const ACCOUNT_CREATION_REQUIRED: u32 = 0x8015_DC09;

/// The original account's signed hosted Xbox profile URL, exposed only for user presentation.
/// It authenticates its browser and must not be logged, shared or persisted as configuration.
pub struct AccountCreationRequired {
    url: Zeroizing<String>,
}

impl AccountCreationRequired {
    /// Borrows the validated signed HTTPS page for this original sign-in UI/browser only.
    #[must_use]
    pub fn signup_url(&self) -> &str {
        &self.url
    }
}

impl fmt::Debug for AccountCreationRequired {
    /// The URL carries an authentication signature and never appears in diagnostics.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountCreationRequired")
    }
}

impl fmt::Display for AccountCreationRequired {
    /// Preserves an actionable error without exposing the signed page.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Xbox profile creation is required")
    }
}

impl std::error::Error for AccountCreationRequired {}

/// Converts only the exact SISU signup challenge; ordinary responses keep their original handling.
pub(super) fn check(
    response: &Response,
    device_id: Option<&str>,
    key: &SigningKey,
    now: SystemTime,
) -> Result<(), Error> {
    if !required(response) {
        return Ok(());
    }
    let (mut url, session) = metadata(response)?;
    let device = device_id
        .filter(|id| !id.is_empty())
        .ok_or(Error::Invalid("SISU signup device identity"))?;
    let mut proxy = Url::parse(SISU_ORIGIN)
        .and_then(|base| base.join("proxy"))
        .map_err(|_| Error::Invalid("SISU proxy endpoint"))?;
    proxy.query_pairs_mut().append_pair("sessionid", session);
    let mut request = Request::new(Method::POST, proxy);
    SignaturePolicy::default().sign(&mut request, key, now)?;
    let signature = request
        .headers()
        .get("signature")
        .and_then(|header| header.to_str().ok())
        .ok_or(Error::Invalid("SISU signup signature"))?;
    let redirect = Url::parse(SISU_ORIGIN)
        .and_then(|base| base.join("sisu_desktop.srf"))
        .map_err(|_| Error::Invalid("SISU signup redirect"))?;
    let mut query = BTreeMap::<String, Vec<Zeroizing<String>>>::new();
    for (name, value) in url.query_pairs() {
        query
            .entry(name.into_owned())
            .or_default()
            .push(Zeroizing::new(value.into_owned()));
    }
    for (name, value) in [
        ("sig", signature.to_owned()),
        ("did", format!("0x{device}")),
        ("redirect", redirect.into()),
        ("sid", session.to_owned()),
    ] {
        query.insert(name.into(), vec![Zeroizing::new(value)]);
    }
    url.query_pairs_mut()
        .clear()
        .extend_pairs(query.iter().flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.as_str(), value.as_str()))
        }));
    Err(Error::AccountCreationRequired(AccountCreationRequired {
        url: Zeroizing::new(url.into()),
    }))
}

/// Validates the original challenge independently of device metadata before a legacy migration.
pub(super) fn metadata(response: &Response) -> Result<(Url, &str), Error> {
    let session = response
        .headers
        .get("x-sessionid")
        .and_then(|header| header.to_str().ok())
        .filter(|session| !session.is_empty())
        .ok_or(Error::Invalid("SISU signup session"))?;
    #[derive(Deserialize)]
    struct Page {
        #[serde(rename = "WebPage")]
        page: String,
    }
    let page = Zeroizing::new(response.json::<Page>()?.page);
    let url = Url::parse(&page).map_err(|_| Error::Invalid("SISU signup page"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Invalid("SISU signup page"));
    }
    Ok((url, session))
}

/// Recognizes only the original failed SISU challenge, before any device migration is allowed.
pub(super) fn required(response: &Response) -> bool {
    response.status != StatusCode::OK
        && response
            .headers
            .get("x-err")
            .and_then(|header| header.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok())
            == Some(ACCOUNT_CREATION_REQUIRED)
}

#[cfg(test)]
mod tests;
