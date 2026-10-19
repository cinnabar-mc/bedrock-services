//! One opt-in original-session activity/invitation exchange and exact conditional retirement.

use super::*;
use std::num::NonZeroU32;

pub(super) const HTTP_EXCHANGES: usize = 12;

pub(super) struct Activity {
    pub(super) max_members: NonZeroU32,
    pub(super) title_id: String,
    pub(super) publication: Option<Value>,
}

/// Independently checks transmitted original proof, handle metadata, validator and leave bytes.
pub(super) fn respond(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    scenario: &Scenario,
) -> (u16, Vec<(&'static str, &'static str)>, Value) {
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
    let activity = state.activity.as_ref().unwrap();
    let peer = state.peer.as_ref().unwrap();
    match step {
        9 | 10 => {
            assert_eq!(target, "/handles");
            assert!(headers.starts_with("POST "));
            assert!(header(headers, "if-match").is_empty());
            assert!(header(headers, "if-none-match").is_empty());
            assert_eq!(body.last(), Some(&b'\n'));
            let value: Value = serde_json::from_slice(body).unwrap();
            if step == 9 {
                assert_eq!(
                    value,
                    json!({"type":"activity", "version":1, "sessionRef":reference})
                );
                (201, vec![("Date", DATE)], Value::Null)
            } else {
                assert_eq!(
                    value,
                    json!({"type":"invite", "version":1, "sessionRef":reference,
                    "invitedXuid":peer, "inviteAttributes":{"titleId":activity.title_id}})
                );
                (
                    201,
                    vec![("Date", DATE)],
                    json!({"id":Uuid::from_u128(0x7010),
                    "senderXuid":HOST_XUID, "invitedXuid":peer, "sessionRef":reference}),
                )
            }
        }
        11 | 12 => {
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
            if step == 11 {
                assert!(headers.starts_with("GET "));
                assert!(body.is_empty());
                assert_eq!(header(headers, "if-none-match"), "\"host-acknowledged\"");
                (304, vec![("Date", DATE)], Value::Null)
            } else {
                assert!(headers.starts_with("PUT "));
                assert_eq!(header(headers, "if-match"), "\"host-acknowledged\"");
                assert_eq!(
                    serde_json::from_slice::<Value>(body).unwrap(),
                    json!({"members":{"me":null}})
                );
                (204, vec![("Date", DATE)], Value::Null)
            }
        }
        _ => panic!("unexpected hosted activity exchange"),
    }
}
