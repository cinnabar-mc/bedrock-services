//! Bounded retry decisions for explicitly replayable acquisition and title updates.

use super::{REQUEST_TIMEOUT, Response};
use crate::Error;
use reqwest::{Request, StatusCode};
use std::{error::Error as _, io, time::SystemTime};
use tokio::time::{Duration, Instant};

/// Concrete owners opt in; ordinary HTTP and unrelated mutations remain single-dispatch.
#[derive(Clone, Copy)]
pub(crate) enum Policy {
    Discovery,
    Credential,
    Presence,
}

/// Retains the first cutoff across attempts without spawning any work on cancellation.
pub(crate) struct Retry {
    policy: Policy,
    deadline: Instant,
    attempts: u8,
}

impl Retry {
    /// Captures the existing HTTP budget once for the selected operation.
    pub(crate) fn new(policy: Policy) -> Self {
        Self {
            policy,
            deadline: Instant::now() + REQUEST_TIMEOUT,
            attempts: 0,
        }
    }

    /// Charges one attempt and restricts its original request timeout to the remaining budget.
    pub(crate) fn begin(&mut self, request: &mut Request) {
        self.attempts += 1;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let timeout = request.timeout().copied().unwrap_or(REQUEST_TIMEOUT);
        *request.timeout_mut() = Some(timeout.min(remaining));
    }

    /// Waits only when the complete server-requested delay fits before the first cutoff.
    pub(crate) async fn wait(&self, result: &Result<Response, Error>, utc: SystemTime) -> bool {
        let maximum = match self.policy {
            Policy::Discovery => 2,
            Policy::Credential => 5,
            Policy::Presence => 3,
        };
        if self.attempts == 0 || self.attempts >= maximum {
            return false;
        }
        let retry_after = match result {
            Ok(response) => {
                let status = response.status;
                let retryable = match self.policy {
                    Policy::Presence => matches!(
                        status,
                        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                    ),
                    _ => {
                        status == StatusCode::REQUEST_TIMEOUT
                            || status == StatusCode::TOO_MANY_REQUESTS
                            || status.is_server_error()
                            || status.as_u16() == 999
                    }
                };
                if !retryable {
                    return false;
                }
                if matches!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                ) {
                    match response_delay(response, utc) {
                        Ok(delay) => delay,
                        Err(()) => return false,
                    }
                } else {
                    None
                }
            }
            Err(error) => {
                if matches!(self.policy, Policy::Presence) || !transient(error) {
                    return false;
                }
                None
            }
        };
        let delay = match self.policy {
            Policy::Presence => retry_after.unwrap_or(Duration::from_secs(5)),
            _ => Duration::from_secs(1 << (self.attempts - 1)).max(retry_after.unwrap_or_default()),
        };
        let Some(next) = Instant::now().checked_add(delay) else {
            return false;
        };
        if next >= self.deadline {
            return false;
        }
        tokio::time::sleep_until(next).await;
        Instant::now() < self.deadline
    }
}

/// Accepts one positive Retry-After without using an untrusted clock to retry early.
fn response_delay(response: &Response, utc: SystemTime) -> Result<Option<Duration>, ()> {
    let mut values = response.headers.get_all("retry-after").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    if values.next().is_some() {
        return Err(());
    }
    let delay = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        // An overflowing positive delay cannot authorize an earlier fallback retry.
        Duration::from_secs(value.parse().map_err(|_| ())?)
    } else {
        let Ok(date) = httpdate::parse_http_date(value) else {
            return Ok(None);
        };
        date.duration_since(utc).unwrap_or_default()
    };
    Ok((!delay.is_zero()).then_some(delay))
}

/// Keeps TLS validation, HTTP/JSON decoding and non-transport failures terminal.
fn transient(error: &Error) -> bool {
    let Error::Http(error) = error else {
        return false;
    };
    if error.is_timeout() {
        return true;
    }
    let mut source = error.source();
    let mut retryable = false;
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<io::Error>() {
            match error.kind() {
                io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::TimedOut => retryable = true,
                io::ErrorKind::InvalidData
                | io::ErrorKind::InvalidInput
                | io::ErrorKind::PermissionDenied => return false,
                _ => {}
            }
        }
        source = error.source();
    }
    retryable
}
