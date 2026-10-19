use super::*;

/// Both visitors come from the signed read; revoking one preserves the other's original membership.
#[tokio::test]
async fn hosted_world_retains_the_second_actual_visitor_when_the_first_departs() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let HostedAuthority {
            mut account,
            identity,
            mut peer,
        } = HostedAuthority::acquire_world_two_visitors(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
        )
        .await;
        let reference =
            mpsd::Reference::new(Uuid::from_u128(7), "Fixture".into(), "Original".into()).unwrap();
        let HostedMembership {
            mut socket,
            subscription,
            binding,
            mut session,
        } = peer
            .host(
                &mut account,
                &reference,
                Uuid::from_u128(2),
                rta::Generation::new(7).unwrap(),
                "456",
            )
            .await;
        let original: Vec<_> = session
            .description()
            .members
            .values()
            .filter_map(|member| member.as_ref()?.xuid().map(str::to_owned))
            .collect();
        peer.set_properties_bound(
            &mut account,
            &mut session,
            binding,
            &json!({"synthetic":"two acknowledged visitors"}),
        )
        .await;
        account.discover().await.unwrap();
        peer.revoke_member_ready(&mut socket).await;
        let event = socket.drive().await.unwrap();
        let update = account.mpsd().sync(&mut session).await.unwrap();
        let retained = account.owns_rta(socket.connection())
            && session.is_bound(binding)
            && !session.description().members.contains_key("1")
            && session.description().members["2"]
                .as_ref()
                .and_then(mpsd::Member::xuid)
                == Some(HOSTED_WORLD_SECOND_VISITOR_XUID);
        peer.leave_bound(&mut account, &mut session, binding).await;
        peer.finish(&mut socket).await;
        assert_eq!(identity.xuid(), script::HOST_XUID);
        assert_eq!(original.len(), 3);
        assert!(original.iter().any(|xuid| xuid == "456"));
        assert!(original.iter().any(|xuid| xuid == HOSTED_WORLD_SECOND_VISITOR_XUID));
        assert!(retained && session.is_closed());
        assert!(matches!(event, rta::Event::Resync { subscriptions } if subscriptions.contains(&subscription)));
        assert_eq!(update, mpsd::Update::Updated);
    })
    .await
    .unwrap();
}
