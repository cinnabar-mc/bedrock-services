use super::*;
use crate::xbox::mpsd::tests::signed_service_script;
use serde_json::json;

/// Requested entry count does not cap valid descriptions to acquisition's smaller byte bound.
#[tokio::test]
async fn profile_service_body_above_default_limit_preserves_achievement_page() {
    let description = "d".repeat(crate::http::RESPONSE_LIMIT / MAX_PAGE_ITEMS + 128);
    let entries = (0..MAX_PAGE_ITEMS)
        .map(|index| {
            json!({
                "id":format!("original-{index}"),"serviceConfigId":"original-service",
                "description":description,"progressState":"Achieved",
            })
        })
        .collect::<Vec<_>>();
    let response = json!({"achievements":entries,"pagingInfo":{
        "continuationToken":"original-next","totalRecords":MAX_PAGE_ITEMS,
    }});
    let bytes = serde_json::to_vec(&response).unwrap();
    assert!(bytes.len() > crate::http::RESPONSE_LIMIT);
    assert!(bytes.len() < 2 * crate::http::RESPONSE_LIMIT);
    let mut response = Some(response);
    let (mut account, address, server) = signed_service_script(
        "2",
        true,
        move |_, path, headers, body| {
            assert!(headers.starts_with("GET "));
            assert!(body.is_empty());
            let url = Url::parse(&format!("http://fixture{path}")).unwrap();
            assert_eq!(
                percent_encoding::percent_decode_str(url.path())
                    .decode_utf8()
                    .unwrap(),
                "/users/xuid(123)/achievements"
            );
            let query = url
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(query["titleId"], "7");
            assert_eq!(query["maxItems"], MAX_PAGE_ITEMS.to_string());
            assert!(!query.contains_key("continuationToken"));
            (200, vec![], response.take().unwrap())
        },
        1,
    )
    .await;
    let mut achievements = account.achievements();
    achievements.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), achievements.page(7, ""))
        .await
        .unwrap();
    if result.is_err() {
        server.abort();
    }
    let served = server.await;
    let page = result
        .unwrap_or_else(|error| panic!("valid in-bound achievement response rejected: {error:?}"));
    served.unwrap();
    assert_eq!(page.owner_xuid, "123");
    assert_eq!(page.malformed_items, 0);
    assert_eq!(page.achievements.len(), MAX_PAGE_ITEMS);
    assert_eq!(page.continuation, "original-next");
    assert_eq!(
        page.total_records,
        Some(u64::try_from(MAX_PAGE_ITEMS).unwrap())
    );
    for (index, achievement) in page.achievements.iter().enumerate() {
        assert_eq!(achievement.id, format!("original-{index}"));
        assert_eq!(achievement.description, description);
        assert_eq!(achievement.progress_state.as_deref(), Some("Achieved"));
    }
}

/// Uses the real signed service owner for pagination order, original continuations and malformed neighbors.
#[tokio::test]
async fn achievement_collection_preserves_order_and_refuses_nonadvancing_pages() {
    let (mut account, address, server) = signed_service_script("2", true,
        move |step, path, headers, body| {
            assert!(headers.starts_with("GET "));
            assert!(body.is_empty());
            let url = Url::parse(&format!("http://fixture{path}")).unwrap();
            assert_eq!(percent_encoding::percent_decode_str(url.path()).decode_utf8().unwrap(), "/users/xuid(123)/achievements");
            let query = url.query_pairs().collect::<std::collections::HashMap<_,_>>();
            assert_eq!(query["titleId"], "7");
            assert_eq!(query["maxItems"], MAX_PAGE_ITEMS.to_string());
            let achievement = |id: &str| json!({"id":id,"serviceConfigId":"fixture","name":id,
                "progressState":"FutureState","rewards":[{"type":"Gamerscore","value":"not-a-score"}],
                "progression":{"timeUnlocked":"unknown-future-time"}});
            match step {
                1 | 3 => { assert!(!query.contains_key("continuationToken"));
                    (200, vec![], json!({"achievements":[achievement("first"),null,{"id":""}],
                        "pagingInfo":{"continuationToken":"opaque + / &","totalRecords":3}})) }
                2 => { assert_eq!(query["continuationToken"], "opaque + / &");
                    (200, vec![], json!({"achievements":[achievement("first"),achievement("second")],"pagingInfo":{}})) }
                4 => (200, vec![], json!({"achievements":[],"pagingInfo":{"continuationToken":"opaque + / &"}})),
                5 => (200, vec![], json!({"pagingInfo":{}})),
                6 => (403, vec![], json!({"diagnostic":"SENSITIVE-service-body"})),
                _ => unreachable!(),
            }
        }, 6).await;
    let mut achievements = account.achievements();
    achievements.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    assert!(achievements.page(0, "").await.is_err());
    assert!(
        achievements
            .page(7, &"x".repeat(MAX_CONTINUATION_BYTES + 1))
            .await
            .is_err()
    );
    let collection = achievements.all(7).await.unwrap();
    assert_eq!(collection.owner_xuid, "123");
    assert_eq!(collection.malformed_items, 2);
    assert_eq!(
        collection
            .achievements
            .iter()
            .map(|value| value.id.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_eq!(
        collection.achievements[0].progress_state.as_deref(),
        Some("FutureState")
    );
    assert_eq!(
        collection.achievements[0].rewards[0].value.as_deref(),
        Some("not-a-score")
    );
    assert!(matches!(
        achievements.all(7).await,
        Err(Error::Invalid("achievement continuation did not advance"))
    ));
    for _ in 0..2 {
        let error = achievements.page(7, "").await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    server.await.unwrap();
}
