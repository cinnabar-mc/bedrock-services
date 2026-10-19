//! Fixed original/fresh/restored proof sequence and independent signed directory oracle.

mod activity;
mod publication;
mod revocation;
mod unchanged;

use crate::xbox::{
    XBOX_RELYING_PARTY, mpsd,
    mpsd::test_support::{DIRECTORY_CONTRACT, SIGNED_HEADERS, header, verify},
    test_support::{fixture_headers, token},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::task::JoinHandle;
use uuid::Uuid;

pub(super) const HOST_XUID: &str = "123";
pub(super) const CONNECTION: Uuid = Uuid::from_u128(0x7001);
const DATE: &str = "Sun, 18 Oct 2026 12:00:00 GMT";
const HTTP_EXCHANGES: usize = 14;

#[derive(Clone)]
pub(super) struct Scenario(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    proof: Option<Value>,
    reference: Option<mpsd::Reference>,
    subscription: Option<Uuid>,
    peer: Option<String>,
    rta_headers: Vec<String>,
    revocation: bool,
    activity: Option<activity::Activity>,
    unchanged: bool,
}

impl Scenario {
    /// Identifies only the finite sibling scenario that exercises a real directory refresh.
    pub(super) fn revocation(&self) -> bool {
        let state = self.0.lock().unwrap();
        state.revocation && !state.unchanged
    }

    /// Selects only a signed conditional 304 after an actual RTA resync.
    pub(super) fn unchanged(&self) -> bool {
        self.0.lock().unwrap().unchanged
    }

    /// Identifies only the explicit finite activity/invite sibling.
    pub(super) fn activity(&self) -> bool {
        self.0.lock().unwrap().activity.is_some()
    }

    /// Identifies the explicit first-creation sibling without changing other finite scenarios.
    pub(super) fn publication(&self) -> bool {
        self.0
            .lock()
            .unwrap()
            .activity
            .as_ref()
            .is_some_and(|mode| mode.publication.is_some())
    }

    /// Borrows expected public create metadata; it never creates a Session or account authority.
    pub(super) fn publication_metadata(&self) -> (std::num::NonZeroU32, Value) {
        let state = self.0.lock().unwrap();
        let mode = state.activity.as_ref().unwrap();
        (mode.max_members, mode.publication.as_ref().unwrap().clone())
    }

    /// Installs only public title-selected locator/member metadata before its first directory read.
    pub(super) fn configure(&self, reference: &mpsd::Reference, subscription: Uuid, peer: &str) {
        assert!(!subscription.is_nil());
        crate::xbox::social::validate_xuid(peer).unwrap();
        assert_ne!(peer, HOST_XUID);
        let mut state = self.0.lock().unwrap();
        assert!(state.reference.is_none());
        state.reference = Some(reference.clone());
        state.subscription = Some(subscription);
        state.peer = Some(peer.to_owned());
    }

    /// Installs the actual upgrade's final policy headers before acquiring its protected fields.
    pub(super) fn rta_headers(&self, headers: Vec<String>) {
        self.0.lock().unwrap().rta_headers = headers;
    }

    /// Copies only original public EC coordinates for an independent signature oracle.
    pub(super) fn proof(&self) -> Value {
        self.0.lock().unwrap().proof.clone().unwrap()
    }
}

/// Starts exactly the original account/host/write, fresh account, restore and leave exchanges.
pub(super) async fn start() -> (SocketAddr, JoinHandle<()>, Scenario) {
    start_scenario(false, None, None, false).await
}

/// Reuses the original eight acquisition/acknowledgment exchanges before one revoke and leave.
pub(super) async fn start_revocation() -> (SocketAddr, JoinHandle<()>, Scenario) {
    start_scenario(true, None, None, false).await
}

/// Adds the selected build's single unauthenticated discovery read to the fixed revocation sequence.
pub(super) async fn start_world(version: &str) -> (SocketAddr, JoinHandle<()>, Scenario) {
    start_scenario(true, Some(version.to_owned()), None, false).await
}

/// Adds only the original membership's signed activity/invite and conditional cleanup sequence.
pub(super) async fn start_activity(
    max_members: std::num::NonZeroU32,
    title_id: String,
) -> (SocketAddr, JoinHandle<()>, Scenario) {
    assert!(usize::try_from(max_members.get()).is_ok_and(|limit| limit <= mpsd::MAX_MEMBERS));
    assert!(
        title_id
            .parse::<u32>()
            .is_ok_and(|id| id != 0 && id.to_string() == title_id)
    );
    start_scenario(
        false,
        None,
        Some(activity::Activity {
            max_members,
            title_id,
            publication: None,
        }),
        false,
    )
    .await
}

/// Reuses the actual protected acquisition before one conditional create/activity/invite sequence.
pub(super) async fn start_publication(
    max_members: std::num::NonZeroU32,
    title_id: String,
    properties: Value,
) -> (SocketAddr, JoinHandle<()>, Scenario) {
    assert!(usize::try_from(max_members.get()).is_ok_and(|limit| limit <= mpsd::MAX_MEMBERS));
    assert!(
        title_id
            .parse::<u32>()
            .is_ok_and(|id| id != 0 && id.to_string() == title_id)
    );
    assert!(properties.is_object());
    start_scenario(
        false,
        None,
        Some(activity::Activity {
            max_members,
            title_id,
            publication: Some(properties),
        }),
        false,
    )
    .await
}

/// Keeps the original eight exchanges before one unchanged refresh and exact leave.
pub(super) async fn start_unchanged() -> (SocketAddr, JoinHandle<()>, Scenario) {
    start_scenario(true, None, None, true).await
}

/// Selects only fixed sequences; original fourteen exchange assertions stay shared.
async fn start_scenario(
    revocation: bool,
    world_version: Option<String>,
    activity: Option<activity::Activity>,
    unchanged: bool,
) -> (SocketAddr, JoinHandle<()>, Scenario) {
    let scenario = Scenario(Arc::new(Mutex::new(State {
        revocation,
        activity,
        unchanged,
        ..Default::default()
    })));
    let state = scenario.clone();
    let mut step = 0;
    let mut fresh_proof = None;
    let mut snapshot = Value::Null;
    let world = world_version.is_some();
    let activity = scenario.activity();
    let publication = scenario.publication();
    let (address, task) = fixture_headers(move |target, headers, body| {
        step += 1;
        let mut response_headers = vec![("Date", DATE)];
        let mut status = 200;
        if let Some(version) = &world_version && step == 9 {
            assert_eq!(target, format!("/api/v1.0/discovery/MinecraftPE/builds/{version}"));
            assert!(headers.starts_with("GET "));
            assert!(header(headers, "authorization").is_empty());
            assert!(header(headers, "signature").is_empty());
            assert_eq!(header(headers, "user-agent"), crate::minecraft::USER_AGENT);
            assert!(body.is_empty());
            return (200, response_headers, json!({"result":{"serviceEnvironments":{"auth":{"prod":{
                "serviceUri":"https://hosted-world-service.invalid/",
                "playFabTitleId":"AB12", "issuer":super::HOSTED_WORLD_ISSUER
            }}}}}));
        }
        if publication && step > 6 {
            return publication::respond(step, target, headers, body, &state, &mut snapshot);
        }
        if unchanged && step > 8 {
            return unchanged::respond(step, target, headers, body, &state);
        }
        if activity && step > 8 {
            return activity::respond(step, target, headers, body, &state);
        }
        if revocation && step > 8 {
            return revocation::respond(step - usize::from(world), target, headers, body, &state, &mut snapshot);
        }
        let response = match step {
            1 | 9 => {
                assert_eq!(target, "/device-token");
                let value: Value = serde_json::from_slice(body).unwrap();
                let proof = value["Properties"]["ProofKey"].clone();
                verify(target, headers, body, &proof, &[]);
                if step == 1 { state.0.lock().unwrap().proof = Some(proof); }
                else { assert_ne!(proof, state.proof()); fresh_proof = Some(proof); }
                token("device", false)
            }
            2 | 10 | 12 => {
                assert_eq!(target, "/nsal");
                assert!(headers.starts_with("GET "));
                assert!(header(headers, "authorization").is_empty());
                assert!(header(headers, "signature").is_empty());
                json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn",
                    "RelyingParty":XBOX_RELYING_PARTY,"SignaturePolicyIndex":0}],
                    "SignaturePolicies":[{"Version":1}]})
            }
            3 | 11 => {
                assert_eq!(target, "/sisu");
                let proof = if step == 3 { state.proof() } else { fresh_proof.clone().unwrap() };
                verify(target, headers, body, &proof, &[]);
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value["ProofKey"], proof);
                assert_eq!(value["AccessToken"], "t=synthetic-access");
                json!({"TitleToken":token("title",false),"UserToken":token("user",false),
                    "AuthorizationToken":token("xbox",true)})
            }
            4 | 13 => {
                assert_eq!(target, "/nsal-current");
                assert_eq!(header(headers, "authorization"), "XBL3.0 x=synthetic;xbox");
                verify(target, headers, body, &state.proof(), &[]);
                json!({"EndPoints":[
                    {"Protocol":"https","Host":"rta.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rta","SignaturePolicyIndex":0},
                    {"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn","RelyingParty":"rp://mpsd","SignaturePolicyIndex":1}],
                    "SignaturePolicies":[{"Version":1,"ExtraHeaders":state.0.lock().unwrap().rta_headers},
                        {"Version":1,"ExtraHeaders":SIGNED_HEADERS}]})
            }
            5 | 6 => {
                assert_eq!(target, "/xsts");
                verify(target, headers, body, &state.proof(), &[]);
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value["RelyingParty"], if step == 5 { "rp://rta" } else { "rp://mpsd" });
                token(if step == 5 { "rta" } else { "directory" }, true)
            }
            7 | 8 | 14 => {
                verify(target, headers, body, &state.proof(), SIGNED_HEADERS);
                assert_eq!(header(headers, "authorization"), "XBL3.0 x=synthetic;directory");
                assert_eq!(header(headers, "x-xbl-contract-version"), DIRECTORY_CONTRACT);
                let state = state.0.lock().unwrap();
                let reference = state.reference.as_ref().unwrap();
                let mut url = url::Url::parse("http://127.0.0.1").unwrap();
                url.path_segments_mut().unwrap().extend([
                    "serviceconfigs", &reference.service_config_id().to_string(), "sessionTemplates",
                    reference.template_name(), "sessions", reference.name(),
                ]);
                assert_eq!(target, url.path());
                match step {
                    7 => {
                        assert!(headers.starts_with("GET "));
                        assert!(body.is_empty());
                        snapshot = json!({"branch":Uuid::from_u128(0x7002), "changeNumber":1,
                            "sessionRef":reference, "properties":{"custom":{}},
                            "members":{
                                "me":{"constants":{"system":{"xuid":HOST_XUID}},"properties":{"system":{
                                    "active":true,"connection":CONNECTION,"subscription":{"id":state.subscription.unwrap()}}}},
                                "1":{"constants":{"system":{"xuid":state.peer.as_ref().unwrap()}},
                                    "properties":{"system":{"active":true}}}}});
                        if let Some(activity) = &state.activity {
                            snapshot["constants"] = json!({"system":{"maxMembersCount":activity.max_members.get()}});
                        }
                        response_headers.push(("ETag", "\"host-original\""));
                        snapshot.clone()
                    }
                    8 => {
                        assert!(headers.starts_with("PUT "));
                        assert_eq!(header(headers, "if-match"), "\"host-original\"");
                        assert_eq!(body.last(), Some(&b'\n'));
                        let value: Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(value.as_object().unwrap().len(), 1);
                        assert_eq!(value["properties"].as_object().unwrap().len(), 1);
                        snapshot["properties"]["custom"] = value["properties"]["custom"].clone();
                        snapshot["changeNumber"] = json!(2);
                        response_headers.push(("ETag", "\"host-acknowledged\""));
                        snapshot.clone()
                    }
                    14 => {
                        assert!(headers.starts_with("PUT "));
                        assert_eq!(header(headers, "if-match"), "\"host-acknowledged\"");
                        assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"members":{"me":null}}));
                        status = 204;
                        Value::Null
                    }
                    _ => unreachable!(),
                }
            }
            _ => panic!("unexpected hosted authority exchange"),
        };
        (status, response_headers, response)
    }, if publication { publication::HTTP_EXCHANGES } else if activity { activity::HTTP_EXCHANGES } else if revocation { 10 + usize::from(world) } else { HTTP_EXCHANGES }).await;
    (address, task, scenario)
}
