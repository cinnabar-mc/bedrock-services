//! Short, process-local NSAL failure suppression; canceled futures never install an entry.

use crate::Error;
use std::time::Duration;
use tokio::time::Instant;

const LIFETIME: Duration = Duration::from_secs(15);

pub(super) struct Failure {
    until: Instant,
    error: Error,
    transient: bool,
}

impl Failure {
    /// Retains a redacted replay of a completed failure for the original 15-second window.
    pub(super) fn new(error: &Error, now: Instant, replayed: Option<bool>) -> Self {
        Self {
            until: now + LIFETIME,
            error: replay(error),
            transient: replayed.unwrap_or_else(|| crate::http::retry::transient(error)),
        }
    }

    /// Returns the cached failure strictly before its monotonic retry deadline.
    pub(super) fn get(&self, now: Instant) -> Option<Error> {
        (now < self.until).then(|| replay(&self.error))
    }

    /// Retains the original transport classification even when its redacted replay cannot be cloned.
    pub(super) fn transient(&self) -> bool {
        self.transient
    }
}

/// Preserves service codes and actionable signup state without retaining transport URLs or bodies.
fn replay(error: &Error) -> Error {
    match error {
        Error::Status { status, xerr } => Error::Status {
            status: *status,
            xerr: *xerr,
        },
        Error::AccountCreationRequired(challenge) => {
            Error::AccountCreationRequired(challenge.duplicate())
        }
        Error::Invalid(reason) => Error::Invalid(reason),
        Error::ResponseTooLarge => Error::ResponseTooLarge,
        Error::TimeRange => Error::TimeRange,
        Error::DeviceCodeExpired => Error::DeviceCodeExpired,
        Error::AuthorizationDeclined => Error::AuthorizationDeclined,
        Error::SignInRequired => Error::SignInRequired,
        // reqwest errors are not cloneable. Replays expose only a stable redacted classification.
        Error::Http(_) => Error::Invalid("cached title-data transport failure"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http::Http,
        oauth::Credentials,
        xbox::{Account, Config, test_support},
    };
    use serde_json::json;
    use std::time::UNIX_EPOCH;

    /// Uses the real account constructor with only synthetic credentials and a loopback peer.
    fn account(address: std::net::SocketAddr) -> Account {
        let config = Config::default();
        let credentials = Credentials::from_tokens(
            config.client_id.clone(),
            "access".into(),
            "refresh".into(),
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .unwrap();
        Account::new(Http::fixture(address), config, credentials).unwrap()
    }

    /// Cache hits preserve status/X-Err and cannot slide the exact 15-second boundary.
    #[tokio::test(start_paused = true)]
    async fn failure_window_is_monotonic_and_does_not_slide() {
        let failure = Failure::new(
            &Error::Status {
                status: reqwest::StatusCode::UNAUTHORIZED,
                xerr: Some(0x8015_DC0E),
            },
            Instant::now(),
            None,
        );
        for _ in 0..14 {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(matches!(
                failure.get(Instant::now()),
                Some(Error::Status {
                    xerr: Some(0x8015_DC0E),
                    ..
                })
            ));
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(failure.get(Instant::now()).is_none());
    }

    /// Server Date changes do not bypass backoff, and default-title failures expire independently.
    #[tokio::test]
    async fn default_title_failure_reuses_status_until_retry_deadline() {
        let mut hit = 0;
        let (address, server) = test_support::fixture(
            move |target, _, _| {
                assert_eq!(target, "/nsal");
                hit += 1;
                if hit == 1 {
                    (503, json!({"diagnostic":"SENSITIVE"}))
                } else {
                    (200, json!({"EndPoints":[]}))
                }
            },
            2,
        )
        .await;
        let mut account = account(address);
        assert!(matches!(
            account.ensure_title_data().await,
            Err(Error::Status {
                status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                ..
            })
        ));
        account
            .http
            .set_fixture_time(UNIX_EPOCH + Duration::from_secs(4_000_000_000));
        account.advance_fixture_time(Duration::from_secs(14));
        let error = account.ensure_title_data().await.err().unwrap();
        assert!(matches!(
            error,
            Error::Status {
                status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
        account.advance_fixture_time(Duration::from_secs(1));
        account.ensure_title_data().await.unwrap();
        server.await.unwrap();
        assert!(account.title_failures[0].is_none());
    }

    /// Dropping a request after dispatch does not poison the next caller's title load.
    #[tokio::test]
    async fn canceled_title_request_does_not_install_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            test_support::read_request(&mut stream).await;
            seen_tx.send(()).unwrap();
            cancel_rx.await.unwrap();
            drop(stream);
            let (mut stream, _) = listener.accept().await.unwrap();
            test_support::read_request(&mut stream).await;
            test_support::write_response(&mut stream, 200, vec![], br#"{"EndPoints":[]}"#).await;
        });
        let mut account = account(address);
        {
            let load = account.ensure_title_data();
            tokio::pin!(load);
            tokio::select! {
                result = &mut load => panic!("held title load completed: {result:?}"),
                seen = seen_rx => seen.unwrap(),
            }
        }
        assert!(account.title_failures.iter().all(Option::is_none));
        cancel_tx.send(()).unwrap();
        account.ensure_title_data().await.unwrap();
        server.await.unwrap();
    }
}
