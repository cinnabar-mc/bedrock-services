//! Discovered persona and showcased screenshot reads on one Minecraft credential owner.

use super::{Minecraft, append, validate_service_url};
use crate::{Error, http::Response, xbox::social::validate_xuid};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

/// Largest showcased-image metadata list retained from one bounded response.
pub const MAX_SHOWCASED_IMAGES: usize = 1024;

/// Source-backed persona image subtype; arbitrary request paths are not accepted.
#[derive(Clone, Copy)]
pub enum ImageKind {
    /// Rendered head.
    Head,
    /// Rendered full character.
    Avatar,
}

impl ImageKind {
    /// Chooses one fixed persona path suffix.
    fn path(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Avatar => "avatar",
        }
    }
}

/// Bounded response bytes, requiring actual image decoding before display or cache admission.
/// The service Content-Type is metadata, not a guarantee of supported/valid image framing.
pub struct ImageBody {
    /// Original response bytes; no disk cache or image codec is owned by this SDK.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Optional declared media type, without logging raw response data.
    pub content_type: Option<String>,
    /// Optional opaque image validator, distinct from an account or world identity.
    pub etag: Option<String>,
}

/// Showcased screenshot metadata. No request ever follows this response-supplied URL.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShowcasedImage {
    /// Service image identity.
    #[serde(default)]
    pub id: String,
    /// Explicit featured state; absent state never selects a featured image.
    pub is_featured: Option<bool>,
    /// Original modification timestamp, retaining unknown future formats.
    pub last_modified: Option<String>,
    /// Original capture timestamp.
    pub taken_time: Option<String>,
    /// Display/download metadata, not a credential destination.
    #[serde(default)]
    pub url: String,
}

/// One successful showcase response, separate from the local screenshot count.
pub struct Gallery {
    /// Valid image metadata in original service order, including unfeatured images.
    pub images: Vec<ShowcasedImage>,
    /// Malformed metadata rows skipped without discarding valid neighbors.
    pub malformed_items: usize,
}

/// Borrows the existing Minecraft session, discovery, client and credential cache.
pub struct Profile<'a> {
    pub(super) minecraft: &'a mut Minecraft,
}

impl Profile<'_> {
    /// Reads bounded rendered persona bytes for a canonical Xbox identity.
    /// Callers must decode/validate the image before displaying or caching it.
    ///
    /// # Errors
    /// Returns invalid identity/discovery, bounded acquisition/HTTP or redacted status failures.
    pub async fn image(&mut self, xuid: &str, kind: ImageKind) -> Result<ImageBody, Error> {
        crate::http::call::run(async {
            validate_xuid(xuid)?;
            let url = self
                .destination(&["api", "v1.0", "profile", "xuid", xuid, "image", kind.path()])
                .await?;
            let response = self
                .read(
                    url,
                    "image/*",
                    crate::http::SERVICE_RESPONSE_LIMIT,
                    crate::http::retry::Policy::Service,
                )
                .await?;
            Ok(ImageBody {
                content_type: header(&response, reqwest::header::CONTENT_TYPE),
                etag: header(&response, reqwest::header::ETAG),
                bytes: response.body,
            })
        })
        .await
    }

    /// Reads showcase metadata from the discovered persona origin without fetching its images.
    /// Successful empty metadata is distinct from a failed lookup and from local gallery size.
    ///
    /// # Errors
    /// Returns invalid identity/discovery, missing envelope, resource bounds or redacted HTTP failures.
    pub async fn gallery(&mut self, xuid: &str) -> Result<Gallery, Error> {
        crate::http::call::run(async {
            validate_xuid(xuid)?;
            let url = self
                .destination(&["api", "v1.0", "gallery", "xuid", xuid])
                .await?;
            let response = self
                .read(
                    url,
                    "application/json",
                    crate::http::RESPONSE_LIMIT,
                    crate::http::retry::Policy::Single,
                )
                .await?;
            if response.status != StatusCode::OK {
                return Err(Error::Status {
                    status: response.status,
                    xerr: None,
                });
            }
            #[derive(Deserialize)]
            struct Result {
                #[serde(default, rename = "showcasedImages")]
                images: Option<Vec<Value>>,
            }
            #[derive(Deserialize)]
            struct Envelope {
                result: Option<Result>,
            }
            let rows = response
                .json::<Envelope>()?
                .result
                .ok_or(Error::Invalid("gallery result"))?
                .images
                .unwrap_or_default();
            if rows.len() > MAX_SHOWCASED_IMAGES {
                return Err(Error::Invalid("gallery image count"));
            }
            let mut gallery = Gallery {
                images: Vec::new(),
                malformed_items: 0,
            };
            for row in rows {
                match serde_json::from_value::<ShowcasedImage>(row) {
                    Ok(image) if image.url.is_empty() || valid_image_url(&image.url) => {
                        gallery.images.push(image)
                    }
                    _ => gallery.malformed_items += 1,
                }
            }
            Ok(gallery)
        })
        .await
    }

    /// Resolves only the optional discovered persona origin, preserving its path prefix.
    async fn destination(&mut self, path: &[&str]) -> Result<Url, Error> {
        self.minecraft.discover().await?;
        let uri = self
            .minecraft
            .environments
            .as_ref()
            .and_then(|environments| environments.persona.as_ref())
            .and_then(|environment| environment.get("prod"))
            .and_then(|environment| environment.get("serviceUri"))
            .and_then(Value::as_str)
            .ok_or(Error::Invalid("missing persona discovery"))?;
        validate_service_url(uri)?;
        append(uri, path)
    }

    /// Applies the concrete read policy with the current issuance and never follows response URLs.
    async fn read(
        &mut self,
        url: Url,
        accept: &'static str,
        response_limit: usize,
        policy: crate::http::retry::Policy,
    ) -> Result<Response, Error> {
        let token = self.minecraft.authorize().await?;
        let request = self
            .minecraft
            .http
            .request(Method::GET, url.as_str())
            .header("authorization", token.header_value()?)
            .header("accept", accept)
            .build()?;
        let response = self
            .minecraft
            .http
            .send_retrying_with_limit(request, policy, response_limit)
            .await?;
        if response.status == StatusCode::UNAUTHORIZED {
            self.minecraft.reject(&token);
        }
        if !response.status.is_success() {
            return Err(Error::Status {
                status: response.status,
                xerr: None,
            });
        }
        Ok(response)
    }
}

/// Retains only valid textual response metadata, without treating it as authority.
fn header(response: &Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Admits HTTPS display metadata without credentials; it is never an authenticated fetch target.
fn valid_image_url(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

#[cfg(test)]
mod tests;
