use super::*;
use crate::{
    minecraft::{
        USER_AGENT,
        test_support::{authorization, services},
    },
    xbox::test_support::fixture_bytes,
};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

/// Actual authorized refresh/report requests advance only fully decoded continuations.
#[tokio::test]
async fn player_messaging_refresh_reports_retain_session_continuation_and_locale() {
    let mut step = 0;
    let mut session = None;
    let (address, server) = fixture_bytes(move |path, headers, bytes| {
        step += 1;
        let headers = headers.to_ascii_lowercase();
        assert!(headers.contains(&format!("user-agent: {USER_AGENT}")));
        if step == 1 {
            assert!(headers.starts_with("get "));
            assert_eq!(path, "/api/v1.0/discovery/MinecraftPE/builds/1.26.50");
            assert!(!headers.contains("authorization:"));
            let host = headers.lines().find_map(|line| line.strip_prefix("host: ")).unwrap();
            return (200, vec![], json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
                "messaging":{"prod":{"serviceUri":format!("http://{host}/prefix")}}
            }}}).to_string().into_bytes());
        }
        assert!(headers.starts_with("post "));
        assert!(headers.contains("authorization: mctoken original."));
        assert!(headers.contains("accept: application/json"));
        assert!(headers.contains("content-type: application/json"));
        assert!(!headers.contains("signature:"));
        let body: Value = serde_json::from_slice(bytes).unwrap();
        let header_session = headers.lines().find_map(|line| line.strip_prefix("session-id: ")).unwrap();
        let expected = session.get_or_insert_with(|| header_session.to_owned());
        assert_eq!(header_session, expected.as_str());
        assert!(!Uuid::parse_str(header_session).unwrap().is_nil());
        if step <= 5 { assert!(headers.contains("accept-language: pt-br")); }
        else { assert!(!headers.contains("accept-language:")); }
        if step == 4 || step == 6 {
            assert_eq!(path, "/prefix/api/v1.0/messages/event");
            assert_eq!(body["SessionId"], expected.as_str());
            assert!(body.get("sessionId").is_none());
            assert_eq!(body["continuationToken"], if step == 4 { "c-1" } else { "c-2" });
            let event = &body["events"][0];
            assert_eq!(event["sessionId"], expected.as_str());
            if step == 4 {
                assert_eq!(event["eventType"], "Click");
                assert_eq!(event["eventDateTime"], "1970-01-01T00:00:01.234Z");
                assert_eq!(event["instanceId"], "i1");
                assert_eq!(event["reportId"], "r1");
                assert_eq!(event["buttonId"], "primary");
            } else {
                assert_eq!(event["eventType"], "ReadAll");
                for key in ["instanceId", "reportId", "buttonId"] { assert!(event.get(key).is_none()); }
            }
            return (204, vec![], Vec::new());
        }
        assert_eq!(path, "/prefix/api/v1.0/session/refresh");
        assert_eq!(body["sessionId"], expected.as_str());
        assert!(body.get("SessionId").is_none());
        assert_eq!(body["continuationToken"], if step == 2 { "" } else { "c-1" });
        if step == 3 {
            return (200, vec![], br#"{"result":{"continuationToken":"must-not-commit","messages":{}}}"#.to_vec());
        }
        (200, vec![], json!({"result":{
            "continuationToken": if step == 2 { "c-1" } else { "c-2" },
            "messages":[null,{"id":"m1","instanceId":"i1","reportId":"r1","surface":"InboxMessage","template":"Text",
                "messageText":{"header":"Hello","body":null,"bannerText":"New"},
                "images":{"hero":{"url":"https://images.example.test/art.png","imageSize":{"width":64,"height":32}},"absent":null},
                "colors":{"ribbon":{"hexColor":{"r":255,"g":128,"b":0}}},
                "messageItemList":[
                    {"saleBanner":"50% off", "footerHeader":"Lower header", "footerBody":"Lower body", "footerCTA":{"caption":"Lower CTA"}},
                    {"saleBanner":{"future":true}, "FooterHeader":"Upper header", "FooterBody":"Upper body", "FooterCTA":{"caption":"Upper CTA"}},null],
                "style":{"unused":[1,2,3]},"unknown":{"ignored":true}}],
            "inboxSummary":{"totalNumberOfMessages":30,"categories":[{"totalNumberOfMessages":30,
                "totalNumberOfUnreadMessages":-1,"categoryInfo":{"type":"News","name":"News"},"messages":[]}]},
            "inboxSettings":{"padding":"x".repeat(crate::http::RESPONSE_LIMIT + 1)}
        }}).to_string().into_bytes())
    }, 6).await;
    let mut services = services(address);
    let original = Arc::clone(services.authorization.as_ref().unwrap());
    let auth_session = services.session_id();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut messaging = services.player_messaging();
        assert_ne!(messaging.session_id(), auth_session);
        assert!(messaging.refresh("bad\r\nSENSITIVE: x").await.is_err());
        assert!(messaging.report_events("", &[]).await.is_err());
        assert!(
            messaging
                .report_events("", &[Event::default()])
                .await
                .is_err()
        );
        let first = messaging.refresh("pt-BR").await.unwrap();
        assert_eq!(first.messages.len(), 2);
        assert!(first.messages[0].id.is_empty());
        let message = &first.messages[1];
        assert_eq!(message.text.header, "Hello");
        assert!(message.text.body.is_empty());
        assert_eq!(message.images["hero"].size.width, 64);
        assert!(message.images["absent"].url.is_empty());
        assert_eq!(message.colors["ribbon"].rgb.g, 128);
        assert_eq!(message.items[0].sale_banner_text(), "50% off");
        assert!(message.items[1].sale_banner_text().is_empty());
        assert!(message.items[2].button.text.is_empty());
        assert_eq!(message.items[0].footer_header, "Lower header");
        assert_eq!(message.items[0].footer_body, "Lower body");
        assert_eq!(
            serde_json::from_str::<Value>(message.items[0].footer_cta.as_ref().unwrap().get())
                .unwrap()["caption"],
            "Lower CTA"
        );
        assert_eq!(message.items[1].footer_header, "Upper header");
        assert_eq!(message.items[1].footer_body, "Upper body");
        assert_eq!(
            serde_json::from_str::<Value>(message.items[1].footer_cta.as_ref().unwrap().get())
                .unwrap()["caption"],
            "Upper CTA"
        );
        assert_eq!(first.inbox_summary.total, 30);
        assert_eq!(first.inbox_summary.categories[0].unread, -1);
        assert!(messaging.refresh("pt-BR").await.is_err());
        messaging
            .report_events(
                "pt-BR",
                &[Event {
                    event_type: "Click",
                    time: Some(UNIX_EPOCH + Duration::from_millis(1234)),
                    instance_id: "i1",
                    report_id: "r1",
                    button_id: "primary",
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            messaging.refresh("pt-BR").await.unwrap().continuation_token,
            "c-2"
        );
        messaging
            .report_events(
                "",
                &[Event {
                    event_type: "ReadAll",
                    ..Default::default()
                }],
            )
            .await
            .unwrap();
    })
    .await;
    if result.is_err() {
        server.abort();
    }
    let served = server.await;
    result.unwrap();
    served.unwrap();
    assert!(Arc::ptr_eq(
        &original,
        services.authorization.as_ref().unwrap()
    ));
}

/// Optional discovery cannot redirect credentials; 401 rejects only the actual cached issuance.
#[tokio::test]
async fn player_messaging_discovery_and_exact_rejection_preserve_account_ownership() {
    for environment in [
        Value::Null,
        json!({"prod":{"serviceUri":"http://SENSITIVE.invalid"}}),
    ] {
        let (address, server) = fixture_bytes(move |_, headers, _| {
            let headers = headers.to_ascii_lowercase();
            assert!(!headers.contains("authorization:"));
            let host = headers.lines().find_map(|line| line.strip_prefix("host: ")).unwrap();
            (200, vec![], json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},"messaging":environment
            }}}).to_string().into_bytes())
        }, 1).await;
        let mut services = services(address);
        let original = Arc::clone(services.authorization.as_ref().unwrap());
        let error = services.player_messaging().refresh("").await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
        assert!(services.environment.is_some());
        assert!(Arc::ptr_eq(&original, &services.authorize().await.unwrap()));
        server.await.unwrap();
    }
    let mut step = 0;
    let (address, server) = fixture_bytes(move |_, headers, _| {
        step += 1;
        if step == 1 {
            let headers = headers.to_ascii_lowercase();
            let host = headers.lines().find_map(|line| line.strip_prefix("host: ")).unwrap();
            (200, vec![], json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
                "messaging":{"prod":{"serviceUri":format!("http://{host}")}}
            }}}).to_string().into_bytes())
        } else {
            assert!(headers.to_ascii_lowercase().contains("authorization: mctoken original."));
            (401, vec![], b"SENSITIVE refusal".to_vec())
        }
    }, 2).await;
    let mut services = services(address);
    let original = Arc::clone(services.authorization.as_ref().unwrap());
    let error = services.player_messaging().refresh("").await.err().unwrap();
    assert!(matches!(
        error,
        Error::Status {
            status: StatusCode::UNAUTHORIZED,
            ..
        }
    ));
    assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    assert!(services.authorization.is_none());
    services.authorization = Some(authorization("replacement"));
    assert!(!services.reject(&original));
    server.await.unwrap();
}
