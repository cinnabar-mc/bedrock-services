//! Actual conditional create, original-bound refresh/write and shared activity/invite cleanup.

use super::*;

pub(super) const HTTP_EXCHANGES: usize = 13;

/// Derives the complete service snapshot from the actual signed creation body rather than injected capacity.
pub(super) fn respond(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    scenario: &Scenario,
    snapshot: &mut Value,
) -> (u16, Vec<(&'static str, &'static str)>, Value) {
    if step >= 10 {
        return activity::respond(step - 1, target, headers, body, scenario);
    }
    verify(target, headers, body, &scenario.proof(), SIGNED_HEADERS);
    assert_eq!(
        header(headers, "authorization"),
        "XBL3.0 x=synthetic;directory"
    );
    assert_eq!(
        header(headers, "x-xbl-contract-version"),
        DIRECTORY_CONTRACT
    );
    let state = scenario.0.lock().unwrap();
    let reference = state.reference.as_ref().unwrap();
    let mut url = url::Url::parse("http://127.0.0.1").unwrap();
    url.path_segments_mut().unwrap().extend([
        "serviceconfigs",
        &reference.service_config_id().to_string(),
        "sessionTemplates",
        reference.template_name(),
        "sessions",
        reference.name(),
    ]);
    assert_eq!(target, url.path());
    let mut response_headers = vec![("Date", DATE)];
    match step {
        7 => {
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-none-match"), "*");
            assert!(header(headers, "if-match").is_empty());
            assert_eq!(body.last(), Some(&b'\n'));
            let actual: Value = serde_json::from_slice(body).unwrap();
            let mode = state.activity.as_ref().unwrap();
            let properties = mode.publication.as_ref().unwrap();
            assert_eq!(
                actual["constants"],
                json!({"system":{"maxMembersCount":mode.max_members.get()}})
            );
            assert_eq!(
                actual["properties"],
                json!({"system":{
                "joinRestriction":"followed", "readRestriction":"followed", "closed":false,
            }, "custom":properties})
            );
            assert_eq!(actual["members"].as_object().unwrap().len(), 1);
            assert_eq!(
                actual["members"]["me"]["constants"]["system"]["xuid"],
                HOST_XUID
            );
            assert_eq!(
                actual["members"]["me"]["properties"]["system"]["active"],
                true
            );
            assert_eq!(
                actual["members"]["me"]["properties"]["system"]["connection"],
                json!(CONNECTION)
            );
            assert_eq!(
                Uuid::parse_str(
                    actual["members"]["me"]["properties"]["system"]["subscription"]["id"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
                state.subscription.unwrap()
            );
            *snapshot = actual;
            snapshot["branch"] = json!(Uuid::from_u128(0x7002));
            snapshot["changeNumber"] = json!(1);
            snapshot["sessionRef"] = json!(reference);
            snapshot["members"]["1"] = json!({"constants":{"system":{"xuid":state.peer.as_ref().unwrap()}},
                "properties":{"system":{"active":true}}});
            response_headers.push(("ETag", "\"host-created\""));
            (201, response_headers, snapshot.clone())
        }
        8 => {
            assert!(headers.starts_with("GET "));
            assert!(body.is_empty());
            assert_eq!(header(headers, "if-none-match"), "\"host-created\"");
            (304, response_headers, Value::Null)
        }
        9 => {
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-match"), "\"host-created\"");
            assert!(header(headers, "if-none-match").is_empty());
            assert_eq!(body.last(), Some(&b'\n'));
            let actual: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(actual.as_object().unwrap().len(), 1);
            assert_eq!(actual["properties"].as_object().unwrap().len(), 1);
            let custom = &actual["properties"]["custom"];
            let original = &snapshot["properties"]["custom"];
            let mut without_nonces = custom.clone();
            without_nonces["nonces"] = original["nonces"].clone();
            assert_eq!(
                &without_nonces, original,
                "nonce publication must preserve the original route"
            );
            assert!(
                !custom["nonces"][state.peer.as_deref().unwrap()]
                    .as_str()
                    .unwrap()
                    .is_empty()
            );
            snapshot["properties"]["custom"] = custom.clone();
            snapshot["changeNumber"] = json!(2);
            response_headers.push(("ETag", "\"host-acknowledged\""));
            (200, response_headers, snapshot.clone())
        }
        _ => panic!("unexpected hosted conditional-publication exchange"),
    }
}
