//! Two fixed catalog pages on the original acquired Minecraft authorization.

use super::*;

pub(super) const FIRST_SEARCH: usize = 9;
pub(super) const HTTP_EXCHANGES: usize = FIRST_SEARCH + 1;

/// Checks actual continuation requests before returning ordered duplicate and hidden neighbors.
pub(super) fn respond(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    state: &State,
) -> (u16, Vec<(&'static str, &'static str)>, Value) {
    assert_eq!(target, "/api/v2.0/discovery/blob/client");
    assert!(headers.starts_with("POST "));
    assert!(state.session_id.is_some());
    assert_eq!(header(headers, "authorization"), service_header());
    assert_eq!(header(headers, "accept"), "application/json");
    assert_eq!(header(headers, "accept-language"), "en-US");
    assert!(header(headers, "signature").is_empty());
    assert!(header(headers, "session-id").is_empty());
    let query: Value = serde_json::from_slice(body).unwrap();
    let page = match step {
        FIRST_SEARCH => {
            assert_eq!(query, json!({}));
            json!({"ContinuationToken":"page-two","Items":[
                {"Id":"first","ContentType":"3PP_V2.0","Title":{"en-US":"First"},
                 "DisplayProperties":{"url":"first.example.test","port":19132,"rank":2}},
                {"Id":"hidden","IsHidden":true,"ContentType":"3PP_V2.0","Title":{"en-US":"Hidden"},
                 "DisplayProperties":{"url":"hidden.example.test","port":19132,"rank":99}}
            ]})
        }
        HTTP_EXCHANGES => {
            assert_eq!(query, json!({"ContinuationToken":"page-two"}));
            json!({"Items":[
                {"Id":"replacement","ContentType":"3PP_V2.0","Title":{"en-US":"Replacement"},
                 "DisplayProperties":{"url":"first.example.test","port":19132,"rank":9}},
                {"Id":"second","ContentType":"3PP_V2.0","Title":{"en-US":"Second"},
                 "DisplayProperties":{"url":"second.example.test","port":19132,"rank":1}},
                {"Id":"gathering","ContentType":"3PP_V2.0","Title":{"en-US":"Gathering"},
                 "DisplayProperties":{"experienceId":Uuid::from_u128(17),"rank":0}},
                {"Id":"future","ContentType":"FUTURE","Title":{"en-US":"Future"}}
            ]})
        }
        _ => panic!("unexpected catalog request"),
    };
    (200, Vec::new(), json!({"data":page}))
}
