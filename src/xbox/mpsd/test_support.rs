//! Independent verification of original synthetic signed directory exchanges.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Header policy used by the original independent service signature fixtures.
pub(crate) const SIGNED_HEADERS: &[&str] = &[
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Host",
    "Content-Type",
    "Content-Length",
    "X-Xbl-Contract-Version",
    "If-Match",
    "If-None-Match",
];

/// Borrows one transmitted header value without depending on header case or order.
pub(crate) fn header<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map_or("", |(_, value)| value.trim())
}

/// Independently verifies the actual method, authorization, conditional headers and JSON bytes.
pub(crate) fn verify(
    target: &str,
    headers: &str,
    body: &[u8],
    point: &Value,
    signed_headers: &[&str],
) {
    let encoded = STANDARD.decode(header(headers, "signature")).unwrap();
    let method = headers.split_whitespace().next().unwrap();
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let mut canonical = percent_encoding::percent_decode_str(path).collect::<Vec<_>>();
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        canonical.push(b'?');
        canonical.extend_from_slice(query.as_bytes());
    }
    let mut hash = Sha256::new();
    for field in [
        &encoded[..4],
        &encoded[4..12],
        method.as_bytes(),
        canonical.as_slice(),
        header(headers, "authorization").as_bytes(),
    ] {
        hash.update(field);
        hash.update([0]);
    }
    for name in signed_headers {
        hash.update(header(headers, name).as_bytes());
        hash.update([0]);
    }
    hash.update(body);
    hash.update([0]);
    let mut key = vec![4];
    key.extend(
        URL_SAFE_NO_PAD
            .decode(point["x"].as_str().unwrap())
            .unwrap(),
    );
    key.extend(
        URL_SAFE_NO_PAD
            .decode(point["y"].as_str().unwrap())
            .unwrap(),
    );
    VerifyingKey::from_sec1_bytes(&key)
        .unwrap()
        .verify_prehash(
            &hash.finalize(),
            &Signature::from_slice(&encoded[12..]).unwrap(),
        )
        .unwrap();
}

/// Routes only the concrete feature fixture through its actual account-borrowed directory owner.
#[cfg(feature = "test-support")]
pub(crate) fn directory(
    mut directory: super::Directory<'_>,
    address: std::net::SocketAddr,
) -> super::Directory<'_> {
    directory.fixture_base = Some(url::Url::parse(&format!("http://{address}")).unwrap());
    directory
}

/// Uses the real directory's contract source when independently checking a transmitted fixture request.
#[cfg(feature = "test-support")]
pub(crate) const DIRECTORY_CONTRACT: &str = super::CONTRACT;
