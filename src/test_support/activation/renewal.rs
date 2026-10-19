//! One opt-in second mint and correlated TURN response on the original activation owners.

use super::*;

pub(super) const REFRESH_SECONDS: u64 = 600;

#[derive(Default)]
pub(super) struct Observed {
    pub(super) minted_public_key: Option<Vec<u8>>,
    pub(super) original_turn_request: Option<u64>,
    pub(super) refreshed_turn_request: Option<u64>,
}

/// Actual optional renewal requests observed before every original fixture task joined.
pub struct HostedRenewalObservation {
    /// Original creation, invitation and physical socket retirement observations.
    pub activation: HostedActivationObservation,
    /// Public SPKI actually received again in the second mint request on the same account.
    pub renewed_public_key: Vec<u8>,
    /// Original TURN request ID parsed from the same protected WebSocket.
    pub original_turn_request: u64,
    /// Distinct fresh TURN request ID parsed from that original WebSocket's single reader.
    pub refreshed_turn_request: u64,
}

impl Peer {
    /// Reuses original cancellation-safe task joining before consuming actual optional observations.
    pub(in crate::test_support) async fn finish_renewal(
        &mut self,
        http: &mut JoinHandle<()>,
    ) -> HostedRenewalObservation {
        let activation = self.finish(http).await;
        let observed = self
            .state
            .lock()
            .unwrap()
            .renewal
            .take()
            .expect("public activation renewal scenario");
        HostedRenewalObservation {
            activation,
            renewed_public_key: observed.minted_public_key.expect("actual second mint"),
            original_turn_request: observed.original_turn_request.expect("actual initial TURN"),
            refreshed_turn_request: observed.refreshed_turn_request.expect("actual fresh TURN"),
        }
    }
}

#[cfg(test)]
mod tests;
