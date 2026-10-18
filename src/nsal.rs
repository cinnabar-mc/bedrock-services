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
    /// Loads public endpoint policy and reports a valid Date on this successful response.
    pub async fn load(http: &mut Http) -> Result<(Self, bool), Error> {
        let request = http
            .request(reqwest::Method::GET, &http.endpoints.nsal)
            .header("x-xbl-contract-version", "1")
            .build()?;
        let response = http.send(request).await?;
        response.success()?;
        let data = response.json()?;
        let calibrated = response
            .headers
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .is_some();
        Ok((data, calibrated))
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
            "cidr" => {
                let ip = match url.host() {
                    Some(url::Host::Ipv4(ip)) => std::net::IpAddr::V4(ip),
                    Some(url::Host::Ipv6(ip)) => std::net::IpAddr::V6(ip),
                    _ => return false,
                };
                self.host
                    .parse::<ipnet::IpNet>()
                    .is_ok_and(|network| network.contains(&ip))
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_cidr_policy_checks_the_address_port_and_decoded_path() {
        let data: TitleData = serde_json::from_str(r#"{
            "EndPoints": [{"Protocol":"https", "Host":"2001:db8::/32", "HostType":"cidr",
                "Port":443, "Path":"/v1/grant", "RelyingParty":"rp://fixture", "SignaturePolicyIndex":-1}],
            "SignaturePolicies":[]
        }"#).unwrap();
        let url = Url::parse("https://[2001:db8::42]/v1%2Fgrant").unwrap();
        let (party, policy) = data.resolve(&url).expect("matching IPv6 network");
        assert_eq!(party, "rp://fixture");
        assert_eq!(policy.version, SignaturePolicy::default().version);
        for url in [
            "https://[2001:db8::42]:8443/v1%2Fgrant",
            "https://[2001:db9::42]/v1%2Fgrant",
            "https://[2001:db8::42]/wrong",
            "https://example.test/v1%2Fgrant",
        ] {
            assert!(
                data.resolve(&Url::parse(url).unwrap()).is_none(),
                "unexpected match: {url}"
            );
        }
    }
}
