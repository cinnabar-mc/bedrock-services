//! Xbox XAL/NSAL request signatures with caller-supplied time and proof keys.

use crate::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use reqwest::{Request, header::HeaderValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// A server-advertised request signing policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SignaturePolicy {
    /// Version placed in the digest and signature blob.
    pub version: u32,
    /// Maximum signed body prefix; zero signs the complete body.
    #[serde(default)]
    pub max_body_bytes: usize,
    /// Additional signed headers in their advertised order.
    #[serde(default)]
    pub extra_headers: Vec<String>,
}

impl Default for SignaturePolicy {
    /// Returns the XAS authentication policy, which signs the entire body.
    fn default() -> Self {
        Self {
            version: 1,
            max_body_bytes: 0,
            extra_headers: Vec::new(),
        }
    }
}

impl SignaturePolicy {
    /// Signs the actual buffered request body and sets its Signature header.
    /// Streaming bodies are rejected rather than silently signing empty bytes.
    /// The caller supplies signed headers explicitly, including transport defaults.
    pub fn sign(
        &self,
        request: &mut Request,
        key: &SigningKey,
        now: SystemTime,
    ) -> Result<(), Error> {
        let body = request
            .body()
            .map(|body| {
                body.as_bytes()
                    .ok_or(Error::Invalid("request body must be buffered"))
            })
            .transpose()?
            .unwrap_or_default();
        let timestamp = filetime(now)?;
        let digest = self.digest(request, body, timestamp)?;
        let signature: Signature = key
            .sign_prehash(&digest)
            .map_err(|_| Error::Invalid("proof-key signature failed"))?;
        let mut bytes = Vec::with_capacity(76);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&signature.to_bytes());
        let mut header = HeaderValue::from_str(&STANDARD.encode(bytes))
            .map_err(|_| Error::Invalid("signature header"))?;
        header.set_sensitive(true);
        request.headers_mut().insert("signature", header);
        Ok(())
    }

    /// Hashes the decoded URL path, raw query, ordered headers and body prefix.
    fn digest(&self, request: &Request, body: &[u8], timestamp: u64) -> Result<[u8; 32], Error> {
        let mut hash = Sha256::new();
        hash.update(self.version.to_be_bytes());
        hash.update([0]);
        hash.update(timestamp.to_be_bytes());
        hash.update([0]);
        hash.update(request.method().as_str());
        hash.update([0]);
        hash.update(percent_encoding::percent_decode_str(request.url().path()).collect::<Vec<_>>());
        if let Some(query) = request.url().query().filter(|query| !query.is_empty()) {
            hash.update(b"?");
            hash.update(query.as_bytes());
        }
        hash.update([0]);
        for name in
            std::iter::once("authorization").chain(self.extra_headers.iter().map(String::as_str))
        {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::Invalid("signature policy header name"))?;
            if let Some(value) = request.headers().get(name) {
                hash.update(value.as_bytes());
            }
            hash.update([0]);
        }
        let length = if self.max_body_bytes == 0 {
            body.len()
        } else {
            body.len().min(self.max_body_bytes)
        };
        hash.update(&body[..length]);
        hash.update([0]);
        Ok(hash.finalize().into())
    }
}

/// Converts UTC to unsigned 100-nanosecond ticks since 1601 without overflow.
fn filetime(now: SystemTime) -> Result<u64, Error> {
    const OFFSET: i128 = 116_444_736_000_000_000;
    let ticks = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos() / 100).map_err(|_| Error::TimeRange)?,
        Err(error) => {
            -i128::try_from(error.duration().as_nanos() / 100).map_err(|_| Error::TimeRange)?
        }
    };
    u64::try_from(ticks.checked_add(OFFSET).ok_or(Error::TimeRange)?).map_err(|_| Error::TimeRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use std::{process::Command, time::Duration};

    #[derive(Deserialize)]
    struct Fixture {
        key_scalar: u64,
        time_unix_seconds: u64,
        subsecond_nanos: u32,
        requests: Vec<Input>,
    }
    #[derive(Deserialize)]
    struct Input {
        url: String,
        body: String,
        limit: usize,
        headers: Vec<String>,
    }

    /// Verifies Go signatures against Rust canonicalization, including escaped paths
    /// and raw query ordering, duplicate/missing headers and partial body signing.
    #[test]
    fn signatures_match_the_public_go_acquisition_baseline() {
        let Some(oracle) = std::env::var_os("BEDROCK_SERVICES_GO_ORACLE") else {
            eprintln!("missing-fixture: BEDROCK_SERVICES_GO_ORACLE (build tools/go-oracle)");
            return;
        };
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/signature-requests.json"
        );
        let fixture: Fixture =
            serde_json::from_str(include_str!("../tests/fixtures/signature-requests.json"))
                .unwrap();
        let output = Command::new(oracle).arg(path).output().unwrap();
        assert!(output.status.success(), "Go signature oracle failed");
        let reference: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(reference.len(), fixture.requests.len());
        let mut scalar = [0_u8; 32];
        scalar[24..].copy_from_slice(&fixture.key_scalar.to_be_bytes());
        let key = SigningKey::from_slice(&scalar).unwrap();
        let now = UNIX_EPOCH + Duration::new(fixture.time_unix_seconds, fixture.subsecond_nanos);
        for (input, reference) in fixture.requests.iter().zip(reference) {
            let policy = SignaturePolicy {
                version: 1,
                max_body_bytes: input.limit,
                extra_headers: input.headers.clone(),
            };
            let mut request = reqwest::Client::new()
                .post(&input.url)
                .body(input.body.clone())
                .build()
                .unwrap();
            request.headers_mut().insert(
                "authorization",
                HeaderValue::from_static("synthetic-authorization"),
            );
            request
                .headers_mut()
                .append("x-extra", HeaderValue::from_static("first"));
            request
                .headers_mut()
                .append("x-extra", HeaderValue::from_static("second"));
            policy.sign(&mut request, &key, now).unwrap();
            let digest = policy
                .digest(&request, input.body.as_bytes(), filetime(now).unwrap())
                .unwrap();
            for value in [
                reference.as_str(),
                request.headers()["signature"].to_str().unwrap(),
            ] {
                let bytes = STANDARD.decode(value).unwrap();
                assert_eq!(bytes.len(), 76);
                assert_eq!(&bytes[..4], &policy.version.to_be_bytes());
                assert_eq!(&bytes[4..12], &filetime(now).unwrap().to_be_bytes());
                let signature = Signature::from_slice(&bytes[12..]).unwrap();
                key.verifying_key()
                    .verify_prehash(&digest, &signature)
                    .unwrap();
            }
        }
        assert!(filetime(UNIX_EPOCH - Duration::from_secs(11_644_473_601)).is_err());
    }
}
