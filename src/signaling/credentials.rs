use super::{Error, MAX_BATCH_MESSAGES, MAX_SERVICE_SECONDS};
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Sensitive ICE server credentials. No Debug or implicit serialization is provided.
pub struct IceServer {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    urls: Vec<String>,
}

impl IceServer {
    /// Borrows the service-provided ICE username for the transport adapter.
    pub fn username(&self) -> &str {
        &self.username
    }
    /// Borrows the sensitive ICE password for the transport adapter.
    pub fn password(&self) -> &str {
        &self.password
    }
    /// Returns service-provided STUN/TURN URLs; the transport validates supported schemes.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }
}

/// One cached TURN response with a monotonic expiry supplied by the caller.
pub struct TurnCredentials {
    pub(super) expires: Instant,
    servers: Vec<IceServer>,
}

impl TurnCredentials {
    /// Borrows credentials for immediate copying into a transport's ICE configuration.
    pub fn servers(&self) -> &[IceServer] {
        &self.servers
    }

    /// Checks expiry without reading a clock or retaining a process-independent timestamp.
    pub fn valid(&self, now: Instant) -> bool {
        now < self.expires
    }

    /// Returns the original monotonic expiry for transport handoff without extending it.
    pub fn expires_at(&self) -> Instant {
        self.expires
    }

    /// Decodes a bounded service result and anchors its lifetime to receipt time.
    pub(super) fn from_value(value: Value, now: Instant) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "ExpirationInSeconds")]
            lifetime: u64,
            #[serde(default, rename = "TurnAuthServers")]
            servers: Vec<Server>,
        }
        #[derive(Deserialize)]
        struct Server {
            #[serde(default, rename = "Username")]
            username: String,
            #[serde(default, rename = "Password")]
            password: String,
            #[serde(default, rename = "Urls")]
            urls: Vec<String>,
        }
        let wire: Wire =
            serde_json::from_value(value).map_err(|_| Error::Invalid("TURN credential result"))?;
        if wire.lifetime == 0
            || wire.lifetime > MAX_SERVICE_SECONDS
            || wire.servers.len() > MAX_BATCH_MESSAGES
            || wire.servers.iter().any(|server| {
                server.urls.len() > MAX_BATCH_MESSAGES || server.urls.iter().any(String::is_empty)
            })
        {
            return Err(Error::Invalid("TURN credential lifetime or servers"));
        }
        let expires = now
            .checked_add(Duration::from_secs(wire.lifetime))
            .ok_or(Error::Invalid("TURN credential lifetime"))?;
        Ok(Self {
            expires,
            servers: wire
                .servers
                .into_iter()
                .map(|server| IceServer {
                    username: Zeroizing::new(server.username),
                    password: Zeroizing::new(server.password),
                    urls: server.urls,
                })
                .collect(),
        })
    }
}
