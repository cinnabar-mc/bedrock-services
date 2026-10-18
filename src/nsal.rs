use crate::{Error, http::Http, signature::SignaturePolicy};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TitleData {
    #[serde(rename = "EndPoints")]
    endpoints: Vec<Endpoint>,
    #[serde(default)]
    signature_policies: Vec<SignaturePolicy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Endpoint {
    protocol: String,
    host: String,
    host_type: String,
    relying_party: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    path: String,
    signature_policy_index: Option<isize>,
}

impl TitleData {
    /// Loads public endpoint policy through the plain acquisition client.
    pub async fn load(http: &mut Http) -> Result<Self, Error> {
        let request = http
            .client
            .get(&http.endpoints.nsal)
            .header("x-xbl-contract-version", "1")
            .build()?;
        let response = http.send(request).await?;
        response.success()?;
        response.json()
    }

    /// Selects the first exact host or last wildcard/CIDR match in server order.
    pub fn resolve(&self, url: &Url) -> Option<(&str, SignaturePolicy)> {
        let mut found = None;
        for endpoint in &self.endpoints {
            if endpoint.matches(url) {
                let policy = endpoint
                    .signature_policy_index
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| self.signature_policies.get(index))
                    .cloned()
                    .unwrap_or_default();
                found = Some((endpoint.relying_party.as_str(), policy));
                if endpoint.host_type == "fqdn" {
                    break;
                }
            }
        }
        found
    }
}

impl Endpoint {
    /// Compares advertised scheme, host, effective port and decoded path.
    fn matches(&self, url: &Url) -> bool {
        if self.relying_party.is_empty()
            || self.protocol != url.scheme()
            || (self.port != 0 && url.port_or_known_default() != Some(self.port))
        {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        let matches = match self.host_type.as_str() {
            "fqdn" => host == self.host,
            "wildcard" if self.host.starts_with('*') => wildcard(&self.host, host),
            "cidr" => self
                .host
                .parse::<ipnet::IpNet>()
                .ok()
                .zip(host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|(network, ip)| network.contains(&ip)),
            _ => false,
        };
        matches
            && (self.path.is_empty()
                || percent_encoding::percent_decode_str(url.path()).eq(self.path.bytes()))
    }
}

/// Matches literal host segments separated by '*' without treating dots as regex.
fn wildcard(pattern: &str, mut host: &str) -> bool {
    let mut parts = pattern.split('*').peekable();
    if let Some(first) = parts.next() {
        let Some(rest) = host.strip_prefix(first) else {
            return false;
        };
        host = rest;
    }
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return host.ends_with(part);
        }
        let Some(index) = host.find(part) else {
            return false;
        };
        host = &host[index + part.len()..];
    }
    host.is_empty()
}
