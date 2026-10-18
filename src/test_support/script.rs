//! Fixed original/fresh/restored proof sequence and independent signed directory oracle.

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
const HTTP_EXCHANGES: usize = 13;

#[derive(Clone)]
pub(super) struct Scenario(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    proof: Option<Value>,
    reference: Option<mpsd::Reference>,
    subscription: Option<Uuid>,
    peer: Option<String>,
    rta_headers: Vec<String>,
}

impl Scenario {
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
    let scenario = Scenario(Arc::new(Mutex::new(State::default())));
    let state = scenario.clone();
    let mut step = 0;
    let mut fresh_proof = None;
    let mut snapshot = Value::Null;
    let (address, task) = fixture_headers(move |target, headers, body| {
        step += 1;
        let mut response_headers = vec![("Date", DATE)];
        let mut status = 200;
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
            4 => {
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
            7 | 8 | 13 => {
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
                    13 => {
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
    }, HTTP_EXCHANGES).await;
    (address, task, scenario)
}
