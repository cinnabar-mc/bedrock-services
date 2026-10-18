use super::*;
use crate::xbox::mpsd::tests::signed_service_script;
use serde_json::json;

/// Verifies real signed batches, exact user identity and original numeric values without zero fallbacks.
#[tokio::test]
async fn statistics_read_preserves_precision_absence_and_requested_identity() {
    let scid = Uuid::from_u128(7);
    let (mut account, address, server) = signed_service_script(
        "1",
        true,
        move |step, path, headers, body| {
            assert_eq!(path, "/batch?operation=read");
            assert!(headers.starts_with("POST "));
            let agents = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .map(|(_, value)| value.trim())
                .collect::<Vec<_>>();
            assert_eq!(agents, [USER_AGENT]);
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains(&format!("user-agent: {}", USER_AGENT.to_ascii_lowercase()))
            );
            assert!(headers.to_ascii_lowercase().contains(&format!(
                "accept-language: {}",
                super::super::DEFAULT_LANGUAGE.to_ascii_lowercase()
            )));
            let request: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(request["requestedusers"], json!(["123"]));
            assert_eq!(
                request["requestedscids"],
                json!([{"scid":scid,"requestedstats":["Exact", "Zero", "Missing"]}])
            );
            match step {
                1 => (
                    200,
                    vec![],
                    json!({"users":[null,{"xuid":123,"scids":[{"scid":scid,"stats":[
                    {"statname":"Exact","type":"Integer","value":9_007_199_254_740_993_u64},
                    {"statname":"Zero","type":"Double","value":"0"},
                    {"statname":"Missing","type":"FutureType"}]}]}]}),
                ),
                2 => (200, vec![], json!({"users":[{"xuid":"999"}]})),
                3 => (200, vec![], json!({"users":null})),
                4 => (403, vec![], json!({"diagnostic":"SENSITIVE-service-data"})),
                _ => unreachable!(),
            }
        },
        4,
    )
    .await;
    let mut statistics = account.statistics();
    statistics.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let selection = [Selection {
        service_config_id: scid,
        names: vec!["Exact".into(), "Zero".into(), "Missing".into()],
    }];
    assert!(statistics.read(&["../invalid"], &selection).await.is_err());
    assert!(statistics.read(&["123"], &[]).await.is_err());
    let batch = statistics.read(&["123"], &selection).await.unwrap();
    assert_eq!(batch.malformed_users, 1);
    assert_eq!(batch.users.len(), 1);
    assert_eq!(batch.users[0].xuid, "123");
    let values = &batch.users[0].configurations[0].statistics;
    assert_eq!(values[0].raw_value(), Some("9007199254740993"));
    assert_eq!(
        values[0].non_negative_number().as_deref(),
        Some("9007199254740993")
    );
    assert_eq!(values[1].non_negative_number().as_deref(), Some("0"));
    assert!(values[2].non_negative_number().is_none());
    for _ in 0..3 {
        let error = statistics.read(&["123"], &selection).await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    server.await.unwrap();
}

/// Raw decimal digits survive serde and numeric admission; invalid values remain absent.
#[test]
fn statistics_numeric_text_is_not_rounded_by_json_decoding() {
    let value: Statistic =
        serde_json::from_str(r#"{"value":1234567890.1234567890123456789}"#).unwrap();
    assert_eq!(
        value.non_negative_number().as_deref(),
        Some("1234567890.1234567890123456789")
    );
    for encoded in ["null", "-1", "1e999", r#""NaN""#, "{}", r#""-Infinity""#] {
        let value: Statistic = serde_json::from_str(&format!("{{\"value\":{encoded}}}")).unwrap();
        assert!(value.non_negative_number().is_none());
    }
}
