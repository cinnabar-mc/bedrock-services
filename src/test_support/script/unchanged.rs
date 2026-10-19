//! Signed conditional unchanged refresh and exact original-binding leave.

use super::*;

/// Verifies both final wire requests without changing the original acknowledged snapshot or validator.
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
    match step {
        9 => {
            assert!(headers.starts_with("GET "));
            assert!(body.is_empty());
            assert_eq!(header(headers, "if-none-match"), "\"host-acknowledged\"");
            (304, vec![("Date", DATE)], Value::Null)
        }
        10 => {
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-match"), "\"host-acknowledged\"");
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!({"members":{"me":null}})
            );
            (204, vec![("Date", DATE)], Value::Null)
        }
        _ => panic!("unexpected hosted unchanged-refresh exchange"),
    }
}
