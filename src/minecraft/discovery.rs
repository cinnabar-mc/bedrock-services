//! Shared anonymous discovery, scoped to a URL and the caller's HTTP transport.

use super::{Discovery, Environments, ResultBody, validate_service_url};
use crate::{
    Error,
    http::{Http, call, retry::Policy},
    playfab,
};
use reqwest::{Client, Method};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Instant, SystemTime},
};
use tokio::sync::watch;
use url::Url;

type Outcome = Result<Acquired, Arc<Error>>;
type Key = (usize, String);

#[derive(Clone)]
pub(super) struct Acquired {
    pub environments: Arc<Environments>,
    pub date: Option<SystemTime>,
    pub clock: Option<(SystemTime, Instant)>,
}

struct Entry {
    client: Weak<Client>,
    outcome: watch::Receiver<Option<Outcome>>,
}

/// Returns the short-held lookup registry; no network operation runs under its lock.
fn cache() -> &'static Mutex<HashMap<Key, Entry>> {
    static CACHE: OnceLock<Mutex<HashMap<Key, Entry>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// Waits for one bounded lookup, whose lifetime is independent of any caller waiting for it.
pub(super) async fn resolve(http: &Http, url: Url) -> Result<Acquired, Error> {
    let key = (
        Arc::as_ptr(http.transport()) as usize,
        url.as_str().to_owned(),
    );
    let (mut receiver, sender) = {
        let mut cache = cache()
            .lock()
            .map_err(|_| Error::Invalid("discovery cache"))?;
        let entry = cache.get(&key).filter(|entry| {
            entry.outcome.borrow().is_some() || entry.outcome.has_changed().is_ok()
        });
        if let Some(entry) = entry {
            (entry.outcome.clone(), None)
        } else {
            cache.retain(|_, entry| entry.client.strong_count() != 0);
            let (sender, receiver) = watch::channel(None);
            cache.insert(
                key.clone(),
                Entry {
                    client: Arc::downgrade(http.transport()),
                    outcome: receiver.clone(),
                },
            );
            (receiver, Some(sender))
        }
    };
    if let Some(sender) = sender {
        let mut http = http.detached();
        let published = receiver.clone();
        let operation = async move {
            let outcome = call::run(fetch(&mut http, url)).await.map_err(Arc::new);
            if outcome.is_err()
                && let Ok(mut cache) = cache().lock()
                && cache
                    .get(&key)
                    .is_some_and(|entry| entry.outcome.same_channel(&published))
            {
                cache.remove(&key);
            }
            sender.send_replace(Some(outcome));
        };
        #[cfg(test)]
        let operation = crate::http::retry::inherit_retry_clock(operation);
        tokio::spawn(operation);
    }
    loop {
        if let Some(outcome) = receiver.borrow_and_update().clone() {
            return outcome.map_err(replay);
        }
        receiver
            .changed()
            .await
            .map_err(|_| Error::Invalid("interrupted discovery lookup"))?;
    }
}

/// Fetches and validates required routes before admitting immutable metadata to the cache.
async fn fetch(http: &mut Http, url: Url) -> Result<Acquired, Error> {
    let request = http
        .request(Method::GET, url.as_str())
        .header("content-type", "application/json")
        .build()?;
    let response = http.send_retrying(request, Policy::Discovery).await?;
    response.success()?;
    let environments = response
        .json::<ResultBody<Discovery>>()?
        .result
        .service_environments;
    validate_service_url(&environments.auth.prod.service_uri)?;
    playfab::login_url(&environments.auth.prod.play_fab_title_id)?;
    Ok(Acquired {
        environments: Arc::new(environments),
        date: response
            .headers
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok()),
        clock: http.clock_sample(),
    })
}

/// Keeps ordinary status/validation contracts while sharing noncloneable transport causes by source.
fn replay(error: Arc<Error>) -> Error {
    match &*error {
        Error::DeadlineExceeded => Error::DeadlineExceeded,
        Error::Status { status, xerr } => Error::Status {
            status: *status,
            xerr: *xerr,
        },
        Error::Invalid(reason) => Error::Invalid(reason),
        Error::ResponseTooLarge => Error::ResponseTooLarge,
        _ => Error::Shared(error),
    }
}

#[cfg(test)]
mod tests;
