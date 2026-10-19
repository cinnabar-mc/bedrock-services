//! Fixed conditional occupancy writes on the exact original published document.

use super::*;
use crate::xbox::mpsd::test_support::header;

const VALIDATORS: [&str; 5] = [
    "\"host-acknowledged\"",
    "\"visitor-one\"",
    "\"visitor-two\"",
    "\"visitor-one-retired\"",
    "\"visitors-retired\"",
];

/// Checks each original conditional write and advances only its actual decoded response validator.
pub(in super::super) fn respond(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    state: &mut State,
) -> (u16, Vec<(&'static str, &'static str)>, Value) {
    super::super::script::verify_directory(target, headers, body, state);
    super::super::script::verify_target(target, state);
    let index = state.visitors.as_ref().unwrap().writes;
    match step {
        18..=21 => {
            assert_eq!(index, step - 18);
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-match"), VALIDATORS[index]);
            assert!(header(headers, "if-none-match").is_empty());
            let actual: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(actual.as_object().unwrap().len(), 1);
            assert_eq!(actual["properties"].as_object().unwrap().len(), 1);
            let custom = &actual["properties"]["custom"];
            let original = &state.snapshot["properties"]["custom"];
            let mut expected = original.clone();
            expected["MemberCount"] = json!(OCCUPANCY[index]);
            assert_eq!(custom, &expected);
            state.snapshot["properties"]["custom"] = custom.clone();
            state.snapshot["changeNumber"] = json!(3 + index);
            state.visitors.as_mut().unwrap().writes += 1;
            (
                200,
                vec![("ETag", VALIDATORS[index + 1])],
                state.snapshot.clone(),
            )
        }
        22 => {
            assert_eq!(index, OCCUPANCY.len());
            assert!(headers.starts_with("GET ") && body.is_empty());
            assert_eq!(header(headers, "if-none-match"), VALIDATORS[index]);
            (304, Vec::new(), Value::Null)
        }
        23 => {
            assert_eq!(index, OCCUPANCY.len());
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-match"), VALIDATORS[index]);
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!({"members":{"me":null}})
            );
            (204, Vec::new(), Value::Null)
        }
        _ => panic!("unexpected fixed visitor occupancy exchange"),
    }
}
