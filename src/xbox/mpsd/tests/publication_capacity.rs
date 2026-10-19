use super::*;
use std::num::NonZeroU32;

/// Supplies explicit creation policy without changing the caller's member or property defaults.
fn configuration(binding: Binding, max_members: Option<NonZeroU32>, custom: bool) -> Publish {
    Publish {
        binding,
        member: MemberData::default(),
        constants: custom.then(|| json!({"label":"kept","maxMembersCount":999})),
        max_members,
        properties: None,
        join: Restriction::Followed,
        read: Restriction::Followed,
    }
}

/// Actual signed requests retain the default bytes and keep service caps separate from title data.
#[tokio::test]
async fn publication_member_cap_is_signed_in_system_constants_and_preserves_default_bytes() {
    let scid = Uuid::from_u128(7);
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let (mut account, address, server) = script(
        true,
        move |step, path, headers, body| {
            assert_eq!(
                path,
                format!("/serviceconfigs/{scid}/sessionTemplates/Lobby/sessions/capacity-{step}")
            );
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-none-match"), "*");
            let mut expected = json!({
                "members":{"me":{
                    "constants":{"system":{"initialize":true,"xuid":"123"}},
                    "properties":{"system":{
                        "active":true,"connection":binding.connection,
                        "subscription":{"id":binding.subscription.to_string().to_uppercase(),
                            "changeTypes":["everything"]}
                    }}
                }},
                "properties":{"system":{
                    "closed":false,"joinRestriction":"followed","readRestriction":"followed"
                }}
            });
            match step {
                1 => {}
                2 => {
                    expected["constants"] =
                        json!({"custom":{"label":"kept","maxMembersCount":999}});
                }
                3 => {
                    expected["constants"] = json!({"system":{"maxMembersCount":2}});
                }
                4 => {
                    expected["constants"] = json!({
                        "custom":{"label":"kept","maxMembersCount":999},
                        "system":{"maxMembersCount":2}
                    });
                }
                _ => panic!("unexpected publication request"),
            }
            let mut expected = serde_json::to_vec(&expected).unwrap();
            expected.push(b'\n');
            assert_eq!(body, expected.as_slice());
            (201, vec![("ETag", "\"created\"")], snapshot(1))
        },
        4,
    )
    .await;
    let mut directory = account.mpsd();
    directory.fixture_base = Some(Url::parse(&format!("http://{address}")).unwrap());
    let cap = NonZeroU32::new(2).unwrap();
    for (index, (limit, custom)) in [
        (None, false),
        (None, true),
        (Some(cap), false),
        (Some(cap), true),
    ]
    .into_iter()
    .enumerate()
    {
        let reference =
            Reference::new(scid, "Lobby".into(), format!("capacity-{}", index + 1)).unwrap();
        directory
            .publish(&reference, configuration(binding, limit, custom))
            .await
            .unwrap();
    }
    server.await.unwrap();
}

/// A limit the SDK cannot retain is rejected while the intent is still purely local.
#[test]
fn publication_member_cap_is_bounded_before_account_or_service_io() {
    let mut account = account("127.0.0.1:1".parse().unwrap());
    let directory = account.mpsd();
    let binding = Binding::new(Uuid::from_u128(2), Uuid::from_u128(3)).unwrap();
    let reference = Reference::new(Uuid::from_u128(7), "Lobby".into(), "capacity".into()).unwrap();
    let maximum = u32::try_from(MAX_MEMBERS).unwrap();
    for limit in [1, maximum] {
        let config = configuration(binding, NonZeroU32::new(limit), false);
        assert!(directory.publish_attempt(&reference, config).is_ok());
    }
    let oversized = NonZeroU32::new(maximum.checked_add(1).unwrap()).unwrap();
    assert!(matches!(
        directory.publish_attempt(&reference, configuration(binding, Some(oversized), false)),
        Err(Error::Limit)
    ));
}
