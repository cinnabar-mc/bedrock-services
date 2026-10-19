use super::{Minecraft, ResultBody, append, validate_service_url};
use crate::signaling::{ConnectionRequest, Error, connection};
use reqwest::{Method, StatusCode};
use serde::Deserialize;

#[cfg(test)]
mod tests;

impl Minecraft {
    /// Acquires one authenticated Player Messaging WebSocket upgrade without opening it.
    ///
    /// Uses this owner's service credential and messaging identity. Missing or
    /// malformed optional signaling discovery fails before sending credentials.
    /// The caller supplies WebSocket I/O with redirects disabled and owns reconnects.
    ///
    /// # Errors
    /// Returns redacted discovery/configuration/authentication failures and rejects
    /// insecure destinations. A 401 evicts only the credential used by that request.
    pub async fn messaging_connection(&mut self) -> Result<ConnectionRequest, Error> {
        self.discover().await?;
        let uri = self
            .signaling_environment
            .as_ref()
            .and_then(|environment| environment.get("prod"))
            .and_then(|environment| environment.get("serviceUri"))
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Invalid("missing messaging discovery"))?;
        validate_service_url(uri)?;
        let url = append(uri, &["api", "v1.0", "configuration"])?;
        let authorization = self.authorize().await?;
        let request = self
            .http
            .request(Method::GET, url.as_str())
            .header("authorization", authorization.header_value()?)
            .build()
            .map_err(crate::Error::from)?;
        let response = self.http.send(request).await?;
        if response.status == StatusCode::UNAUTHORIZED {
            self.reject(&authorization);
        }
        response.success()?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Configuration {
            signaling_uri: String,
            ping_frequency: Option<String>,
        }
        let configuration = response.json::<ResultBody<Configuration>>()?.result;
        let mut url = connection::websocket_url(&configuration.signaling_uri)?;
        let ping_interval = connection::ping_interval(configuration.ping_frequency.as_deref())?;
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("WebSocket path"))?
            .pop_if_empty()
            .extend(["ws", "v1.0", "messaging", "connect"]);
        Ok(ConnectionRequest {
            url,
            authorization,
            ping_interval,
            legacy_network_id: None,
        })
    }

    /// Acquires the original legacy WebSocket route on this account's current service issuance.
    /// Unlike Player Messaging, its discovered endpoint needs no configuration HTTP request.
    ///
    /// # Errors
    /// Rejects missing/unsafe legacy discovery and original authentication failures before an upgrade.
    pub async fn legacy_signaling_connection(
        &mut self,
        network_id: u64,
    ) -> Result<ConnectionRequest, Error> {
        self.discover().await?;
        let uri = self
            .legacy_signaling_environment
            .as_ref()
            .and_then(|environment| environment.get("prod"))
            .and_then(|environment| environment.get("serviceUri"))
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Invalid("missing legacy signaling discovery"))?;
        let mut url = connection::websocket_url(uri)?;
        url.path_segments_mut()
            .map_err(|_| Error::Invalid("legacy WebSocket path"))?
            .pop_if_empty()
            .extend(["ws", "v1.0", "signaling", &network_id.to_string()]);
        let authorization = self.authorize().await?;
        Ok(ConnectionRequest {
            url,
            authorization,
            ping_interval: connection::ping_interval(None)?,
            legacy_network_id: Some(network_id),
        })
    }

    /// Rejects only the exact issuance after a signaling upgrade returns HTTP 401.
    /// A delayed failure or an upgrade from another account cannot evict its replacement.
    pub fn reject_messaging(&mut self, request: &ConnectionRequest) -> bool {
        self.reject(&request.authorization)
    }
}
