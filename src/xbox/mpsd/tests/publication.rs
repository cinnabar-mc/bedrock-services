use super::*;
use tokio::sync::oneshot;

/// Supplies only generic directory metadata; Minecraft title policy stays outside the SDK.
fn publication(binding: Binding) -> Publish {
    Publish {
        binding,
        member: MemberData::default(),
        constants: None,
        properties: None,
        join: Restriction::Followed,
        read: Restriction::Followed,
    }
}

/// Supplies a complete snapshot with the exact original active connection and subscription.
fn bound_snapshot(binding: Binding) -> Value {
    let mut value = snapshot(1);
    value["members"]["me"]["properties"]["system"] = json!({
        "active":true,"connection":binding.connection,"subscription":{"id":binding.subscription}
    });
    value
}

#[tokio::test]
async fn bound_properties_require_the_original_member_and_a_concrete_validator() {
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let reference = Reference::new(Uuid::from_u128(7), "Lobby".into(), "original".into()).unwrap();
    let (mut account, address, server) = script(
        true,
        move |step, _, headers, body| match step {
            1 => {
                assert!(headers.starts_with("GET "));
                (200, vec![], bound_snapshot(binding))
            }
            2 => {
                assert!(headers.starts_with("GET "));
                let replacement = Binding::new(binding.connection, Uuid::from_u128(4)).unwrap();
                (
                    200,
                    vec![("ETag", "\"replacement\"")],
                    bound_snapshot(replacement),
                )
            }
            3 => {
                assert!(headers.starts_with("GET "));
                (200, vec![("ETag", "\"original\"")], bound_snapshot(binding))
            }
            4 | 5 => {
                assert!(headers.starts_with("PUT "));
                assert_eq!(header(headers, "if-match"), "\"original\"");
                assert_eq!(
                    serde_json::from_slice::<Value>(body).unwrap(),
                    json!({"properties":{"custom":{"nonce":"synthetic"}}})
                );
                if step == 4 {
                    (200, vec![("ETag", "\"original\"")], bound_snapshot(binding))
                } else {
                    (412, vec![], Value::Null)
                }
            }
            _ => panic!("a refused conditional property write reached HTTP"),
        },
        5,
    )
    .await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let custom = json!({"nonce":"synthetic"});
    let mut session = directory.read(&reference).await.unwrap();
    assert!(matches!(
        directory
            .set_properties_bound(&mut session, binding, &custom)
            .await,
        Err(Error::Invalid("session property validator"))
    ));
    assert!(!session.needs_sync());
    let mut session = directory.read(&reference).await.unwrap();
    assert!(matches!(
        directory
            .set_properties_bound(&mut session, binding, &custom)
            .await,
        Err(Error::Invalid("session property binding"))
    ));
    assert!(!session.needs_sync());
    let mut session = directory.read(&reference).await.unwrap();
    assert_eq!(
        directory
            .set_properties_bound(&mut session, binding, &custom)
            .await
            .unwrap(),
        Update::Updated
    );
    assert_eq!(
        directory
            .set_properties_bound(&mut session, binding, &custom)
            .await
            .unwrap(),
        Update::PreconditionFailed
    );
    assert!(session.needs_sync());
    assert!(matches!(
        directory
            .set_properties_bound(&mut session, binding, &custom)
            .await,
        Err(Error::SyncRequired)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn retained_publication_recovers_only_its_original_membership_after_canceled_dispatch() {
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let reference = Reference::new(Uuid::from_u128(7), "Lobby".into(), "original".into()).unwrap();
    let (observed, mut observation) = oneshot::channel();
    let mut observed = Some(observed);
    let (mut account, address, server) = script(true, move |step, path, headers, body| {
        assert_eq!(path, "/serviceconfigs/00000000-0000-0000-0000-000000000007/sessionTemplates/Lobby/sessions/original");
        match step {
            1 => {
                assert!(headers.starts_with("PUT "));
                assert_eq!(header(headers, "if-none-match"), "*");
                let value: Value = serde_json::from_slice(body).unwrap();
                assert_eq!(value["members"]["me"]["constants"]["system"]["xuid"], "123");
                observed.take().unwrap().send(()).unwrap();
                (201, vec![("ETag", "\"created\"")], bound_snapshot(binding))
            }
            2 => {
                assert!(headers.starts_with("GET "));
                (404, vec![], Value::Null)
            }
            3 => {
                assert!(headers.starts_with("GET "));
                let replacement = Binding::new(Uuid::from_u128(4), binding.subscription).unwrap();
                (200, vec![("ETag", "\"replacement\"")], bound_snapshot(replacement))
            }
            4 => (200, vec![], bound_snapshot(binding)),
            5 => {
                assert!(headers.starts_with("GET "));
                assert_eq!(header(headers, "if-none-match"), "");
                (200, vec![("ETag", "\"owned\"")], bound_snapshot(binding))
            }
            6 => {
                assert!(headers.starts_with("PUT "));
                assert_eq!(header(headers, "if-match"), "\"owned\"");
                assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), json!({"members":{"me":null}}));
                (204, vec![], Value::Null)
            }
            _ => panic!("publication was replayed"),
        }
    }, 6).await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let mut attempt = directory
        .publish_attempt(&reference, publication(binding))
        .unwrap();
    assert!(!attempt.needs_reconciliation());
    {
        let pending = directory.publish_retained(&mut attempt);
        tokio::pin!(pending);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = &mut observation => result.unwrap(),
                result = &mut pending => panic!("publication completed before cancellation: {}", result.is_ok()),
            }
        }).await.unwrap();
    }
    assert!(attempt.needs_reconciliation());
    assert!(matches!(
        directory.publish_retained(&mut attempt).await,
        Err(Error::PublishFinished)
    ));
    assert!(matches!(
        directory.reconcile_publish(&mut attempt).await,
        Err(Error::Status(404))
    ));
    assert!(attempt.needs_reconciliation());
    for _ in 0..2 {
        assert!(matches!(
            directory.reconcile_publish(&mut attempt).await,
            Err(Error::Invalid(_))
        ));
        assert!(attempt.needs_reconciliation());
    }
    let mut session = directory.reconcile_publish(&mut attempt).await.unwrap();
    assert!(!attempt.needs_reconciliation());
    assert!(session.reference().same(attempt.reference()));
    assert!(session.is_bound(attempt.binding()));
    assert!(matches!(
        directory.reconcile_publish(&mut attempt).await,
        Err(Error::PublishFinished)
    ));
    assert_eq!(
        directory
            .leave_bound(&mut session, attempt.binding())
            .await
            .unwrap(),
        Update::Closed
    );
    server.await.unwrap();
}

#[tokio::test]
async fn observed_publication_rejection_is_sealed_without_a_cleanup_obligation() {
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let reference = Reference::new(Uuid::from_u128(7), "Lobby".into(), "original".into()).unwrap();
    let (mut account, address, server) = script(
        true,
        |_, _, headers, _| {
            assert_eq!(header(headers, "if-none-match"), "*");
            (412, vec![], json!({"private":"not retained"}))
        },
        1,
    )
    .await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let mut attempt = directory
        .publish_attempt(&reference, publication(binding))
        .unwrap();
    assert!(matches!(
        directory.publish_retained(&mut attempt).await,
        Err(Error::Status(412))
    ));
    assert!(!attempt.needs_reconciliation());
    assert!(matches!(
        directory.publish_retained(&mut attempt).await,
        Err(Error::PublishFinished)
    ));
    assert!(matches!(
        directory.reconcile_publish(&mut attempt).await,
        Err(Error::PublishFinished)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn unpolled_and_cross_proof_publications_do_not_dispatch() {
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let reference = Reference::new(Uuid::from_u128(7), "Lobby".into(), "original".into()).unwrap();
    let mut original = account("127.0.0.1:1".parse().unwrap());
    let mut other = account("127.0.0.1:1".parse().unwrap());
    let mut directory = original.mpsd();
    let mut attempt = directory
        .publish_attempt(&reference, publication(binding))
        .unwrap();
    drop(directory.publish_retained(&mut attempt));
    assert!(!attempt.needs_reconciliation());
    assert!(matches!(
        other.mpsd().publish_retained(&mut attempt).await,
        Err(Error::WrongAccount)
    ));
    assert!(!attempt.needs_reconciliation());
}
