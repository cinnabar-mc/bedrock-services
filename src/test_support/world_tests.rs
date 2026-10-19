use super::*;

/// The paired-world sibling adds discovery while preserving actual original signed binding and cleanup.
#[tokio::test]
async fn hosted_world_discovers_its_fixed_provider_without_replacing_original_authority() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let HostedAuthority {
            mut account,
            identity,
            mut peer,
        } = HostedAuthority::acquire_world(
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
        peer.set_properties_bound(
            &mut account,
            &mut session,
            binding,
            &json!({"synthetic":"acknowledged"}),
        )
        .await;
        let checkpoint = account.checkpoint().unwrap();
        account.discover().await.unwrap();
        account.discover().await.unwrap();
        let discovered = account.authorization_issuer().unwrap() == HOSTED_WORLD_ISSUER;
        let retained = account.checkpoint().unwrap().as_bytes() == checkpoint.as_bytes()
            && account.owns_rta(socket.connection())
            && session.is_bound(binding);
        peer.revoke_member_ready(&mut socket).await;
        let event = socket.drive().await.unwrap();
        let update = account.mpsd().sync(&mut session).await.unwrap();
        let revoked = !session.description().members.contains_key("1");
        peer.leave_bound(&mut account, &mut session, binding).await;
        peer.finish(&mut socket).await;
        assert_eq!(identity.xuid(), script::HOST_XUID);
        assert!(discovered && retained && revoked);
        assert!(matches!(event, rta::Event::Resync { subscriptions } if subscriptions.contains(&subscription)));
        assert_eq!(update, mpsd::Update::Updated);
    })
    .await
    .unwrap();
}
