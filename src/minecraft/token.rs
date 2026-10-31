//! Immutable Minecraft service credentials and bounded metadata decoding.

use crate::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::header::HeaderValue;
use serde::Deserialize;
use std::{collections::HashMap, time::SystemTime};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

const CLAIMS_LEEWAY_SECONDS: i64 = 5 * 60;

pub(super) mod checkpoint;

/// Configuration returned with a Minecraft service credential.
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct Configuration {
    /// Service configuration name.
    pub id: String,
    /// Data-driven values retained in their wire string form.
    pub parameters: HashMap<String, String>,
}

/// An immutable service credential. Metadata is decoded from the HTTPS response;
/// it is not a cryptographically verified multiplayer peer identity.
pub struct Authorization {
    header: Zeroizing<String>,
    expires: OffsetDateTime,
    claims_expiry: Option<i64>,
    messaging_id: Uuid,
    treatments: Vec<String>,
    configurations: HashMap<String, Configuration>,
    treatment_context: String,
}

impl Authorization {
    /// Returns the network identity used by player messaging and signaling.
    pub fn messaging_id(&self) -> Uuid {
        self.messaging_id
    }

    /// Returns assigned service treatments.
    pub fn treatments(&self) -> &[String] {
        &self.treatments
    }

    /// Returns service configuration without duplicating a local policy table.
    pub fn configurations(&self) -> &HashMap<String, Configuration> {
        &self.configurations
    }

    /// Returns the service's treatment context.
    pub fn treatment_context(&self) -> &str {
        &self.treatment_context
    }

    /// Returns the sensitive credential for a concrete Minecraft service request.
    pub fn header_value(&self) -> Result<HeaderValue, Error> {
        let mut header = HeaderValue::from_str(&self.header)
            .map_err(|_| Error::Invalid("Minecraft authorization header"))?;
        header.set_sensitive(true);
        Ok(header)
    }

    /// Reserves the service's one-minute refresh margin using caller time.
    pub(crate) fn reusable(&self, now: SystemTime) -> bool {
        let now = OffsetDateTime::from(now);
        now < self.expires - time::Duration::minutes(1)
            && self.claims_expiry.is_none_or(|expiry| {
                now.unix_timestamp() <= expiry.saturating_add(CLAIMS_LEEWAY_SECONDS)
            })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenResponse {
    authorization_header: String,
    valid_until: String,
    #[serde(default)]
    treatments: Vec<String>,
    #[serde(default)]
    configurations: HashMap<String, Configuration>,
    #[serde(default)]
    treatment_context: String,
}

#[derive(Deserialize)]
struct Claims {
    pmid: Uuid,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
}

impl TokenResponse {
    /// Decodes service metadata only after the bounded HTTPS response is accepted.
    pub(super) fn authorization(self, now: SystemTime) -> Result<Authorization, Error> {
        let jwt = self
            .authorization_header
            .strip_prefix("MCToken ")
            .ok_or(Error::Invalid("Minecraft credential prefix"))?;
        let mut parts = jwt.split('.');
        let header = parts.next().filter(|part| !part.is_empty());
        let payload = parts.next().filter(|part| !part.is_empty());
        let signature = parts.next().filter(|part| !part.is_empty());
        if header.is_none() || signature.is_none() || parts.next().is_some() {
            return Err(Error::Invalid("Minecraft credential framing"));
        }
        let payload = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(payload.ok_or(Error::Invalid("Minecraft claims"))?)
                .map_err(|_| Error::Invalid("Minecraft claims encoding"))?,
        );
        let claims: Claims =
            serde_json::from_slice(&payload).map_err(|_| Error::Invalid("Minecraft claims"))?;
        let utc = OffsetDateTime::from(now);
        if claims.pmid.is_nil()
            || claims.exp.is_some_and(|expiry| {
                utc.unix_timestamp() > expiry.saturating_add(CLAIMS_LEEWAY_SECONDS)
            })
            || claims.nbf.is_some_and(|start| {
                utc.unix_timestamp().saturating_add(CLAIMS_LEEWAY_SECONDS) < start
            })
            || claims.iat.is_some_and(|issued| {
                utc.unix_timestamp().saturating_add(CLAIMS_LEEWAY_SECONDS) < issued
            })
        {
            return Err(Error::Invalid("Minecraft claims lifetime or identity"));
        }
        let expires = OffsetDateTime::parse(&self.valid_until, &Rfc3339)
            .map_err(|_| Error::Invalid("Minecraft credential expiry"))?;
        let authorization = Authorization {
            header: Zeroizing::new(self.authorization_header),
            expires,
            claims_expiry: claims.exp,
            messaging_id: claims.pmid,
            treatments: self.treatments,
            configurations: self.configurations,
            treatment_context: self.treatment_context,
        };
        if !authorization.reusable(now) {
            return Err(Error::Invalid("Minecraft credential lifetime"));
        }
        authorization.header_value()?;
        Ok(authorization)
    }
}

/// A multiplayer credential minted for one connection's public key.
/// The caller retains its matching private key throughout Login and key exchange.
pub struct MultiplayerToken {
    pub(super) token: Zeroizing<String>,
    pub(super) public_key: Vec<u8>,
    expires: OffsetDateTime,
}

impl MultiplayerToken {
    /// Borrows the signed token for the Bedrock Login payload.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Returns the exact DER/SPKI public key used by this mint request.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the original hard validity from the mint response, without a refresh margin.
    /// Preserve this absolute value through signaling and Login; copying a remaining
    /// lifetime and anchoring it later would extend the credential.
    pub fn expires_at(&self) -> SystemTime {
        self.expires.into()
    }

    /// Checks hard expiry before Login using the caller's service-aligned time.
    pub fn valid(&self, now: SystemTime) -> bool {
        OffsetDateTime::from(now) < self.expires
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MintResponse {
    signed_token: String,
    valid_until: String,
}

impl MintResponse {
    /// Rejects unusable expiry metadata before exposing a key-bound credential.
    pub(super) fn token(
        self,
        public_key: Vec<u8>,
        now: SystemTime,
    ) -> Result<MultiplayerToken, Error> {
        let expires = OffsetDateTime::parse(&self.valid_until, &Rfc3339)
            .map_err(|_| Error::Invalid("multiplayer credential expiry"))?;
        if self.signed_token.is_empty() || expires <= OffsetDateTime::from(now) {
            return Err(Error::Invalid("multiplayer credential lifetime"));
        }
        Ok(MultiplayerToken {
            token: Zeroizing::new(self.signed_token),
            public_key,
            expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, UNIX_EPOCH};

    /// Reuse honors both the JWT leeway and the response refresh cutoff using caller time.
    #[test]
    fn credential_claim_expiry_regression() {
        let payload =
            URL_SAFE_NO_PAD.encode(json!({"pmid":Uuid::from_u128(7),"exp":600}).to_string());
        let response: TokenResponse = serde_json::from_value(json!({
            "authorizationHeader":format!("MCToken synthetic.{payload}.signature"),
            "validUntil":"1970-01-01T01:00:00Z"
        }))
        .unwrap();
        let credential = response.authorization(UNIX_EPOCH).unwrap();
        assert!(credential.reusable(UNIX_EPOCH + Duration::from_secs(900)));
        assert!(!credential.reusable(UNIX_EPOCH + Duration::from_secs(901)));
        assert!(!credential.reusable(UNIX_EPOCH + Duration::from_secs(1200)));
        assert!(
            credential
                .snapshot()
                .restore(UNIX_EPOCH + Duration::from_secs(901))
                .is_err()
        );
    }
}
