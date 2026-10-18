use reqwest::StatusCode;

/// An authentication failure containing no credential or response-body text.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP transport failed; URLs are removed from the underlying error.
    #[error("authentication HTTP request failed")]
    Http(#[source] reqwest::Error),
    /// The server rejected the request, optionally with an Xbox numeric code.
    #[error("authentication service returned {status} (Xbox code {xerr:?})")]
    Status {
        /// HTTP response status.
        status: StatusCode,
        /// Parsed numeric X-Err header, when supplied.
        xerr: Option<u32>,
    },
    /// An encoded or decoded value violates the service contract.
    #[error("invalid authentication data: {0}")]
    Invalid(&'static str),
    /// A response exceeded its acquisition or concrete service byte budget.
    #[error("authentication response exceeds the byte limit")]
    ResponseTooLarge,
    /// A timestamp cannot be represented by the platform or wire format.
    #[error("authentication timestamp is out of range")]
    TimeRange,
    /// The user must start a new device-code attempt.
    #[error("device-code authorization has expired or completed")]
    DeviceCodeExpired,
    /// Device-code authorization was declined.
    #[error("device-code authorization was declined")]
    AuthorizationDeclined,
    /// OAuth refresh requires a fresh interactive sign-in.
    #[error("Microsoft sign-in must be renewed")]
    SignInRequired,
}

impl From<reqwest::Error> for Error {
    /// Retains the transport cause while excluding potentially sensitive URLs.
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error.without_url())
    }
}
