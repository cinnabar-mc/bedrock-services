//! Bounded Realms version negotiation, driven by the HTTP edge's time.

use crate::http::Response;
use serde::Deserialize;
use std::time::{Duration, SystemTime};

const MAX_PATCH_FALLBACK: u32 = 24;
const SEARCH_COOLDOWN: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub(crate) struct State {
    pub accepted_version: Option<String>,
    failed_at: Option<SystemTime>,
}

impl State {
    /// A failed search suppresses further walks until its cooldown has elapsed.
    pub fn may_search(&self, now: SystemTime) -> bool {
        self.failed_at.is_none_or(|failed| {
            now.duration_since(failed)
                .is_ok_and(|elapsed| elapsed >= SEARCH_COOLDOWN)
        })
    }

    /// Records one failed walk without consulting a clock inside negotiation state.
    pub fn failed(&mut self, now: SystemTime) {
        self.failed_at = Some(now);
    }

    /// Reuses an accepted build for subsequent borrows of the same service owner.
    pub fn accepted(&mut self, version: String) {
        self.accepted_version = Some(version);
        self.failed_at = None;
    }
}

/// Recognizes the specific service reason that permits a Client-Version search.
pub(super) fn rejected(response: &Response) -> bool {
    #[derive(Deserialize)]
    struct Rejection {
        reason: String,
    }
    response.status == reqwest::StatusCode::BAD_REQUEST
        && response
            .json::<Rejection>()
            .is_ok_and(|value| value.reason == "unknown_client_version")
}

/// Walks at most 24 patch revisions below the preferred build, ignoring its build suffix.
pub(super) fn candidates(version: &str) -> Vec<String> {
    let mut fields = version.split('.');
    let mut parsed = [0_u32; 3];
    for field in &mut parsed {
        let Some(value) = fields.next().and_then(|value| value.parse().ok()) else {
            return vec![version.to_owned()];
        };
        *field = value;
    }
    let [major, minor, patch] = parsed;
    (0..=patch.min(MAX_PATCH_FALLBACK))
        .map(|offset| format!("{major}.{minor}.{}", patch - offset))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// Bounds fallback and cools failed walks without clock reads or sleeping in state logic.
    #[test]
    fn patch_search_is_bounded_and_failure_cooldown_uses_supplied_time() {
        let candidates = candidates("1.26.60.2");
        assert_eq!(candidates.len(), 25);
        assert_eq!(candidates.first().unwrap(), "1.26.60");
        assert_eq!(candidates.last().unwrap(), "1.26.36");
        assert_eq!(super::candidates("1.26.1"), ["1.26.1", "1.26.0"]);
        let mut state = State::default();
        state.failed(UNIX_EPOCH + SEARCH_COOLDOWN);
        assert!(!state.may_search(UNIX_EPOCH));
        assert!(!state.may_search(UNIX_EPOCH + SEARCH_COOLDOWN));
        assert!(state.may_search(UNIX_EPOCH + SEARCH_COOLDOWN * 2));
        state.accepted("1.26.59".into());
        assert!(state.may_search(UNIX_EPOCH));
    }
}
