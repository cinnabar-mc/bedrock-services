use super::*;

/// Exercises the real socket event, fresh Directory borrow, signed revoked snapshot and exact leave.
#[tokio::test]
async fn hosted_revocation_refreshes_through_the_original_account_owned_route() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let HostedAuthority {
            mut account,
            identity,
            mut peer,
        } = HostedAuthority::acquire_revocation(
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
        let original_change = session.description().change_number.unwrap();
        peer.revoke_member().await;
        let event = socket.drive().await.unwrap();
        let update = account.mpsd().sync(&mut session).await.unwrap();
        let newer = session.description().change_number.unwrap() > original_change;
        let removed = !session.description().members.contains_key("1");
        let original_owner = account.owns_rta(socket.connection()) && session.is_bound(binding);
        peer.leave_bound(&mut account, &mut session, binding).await;
        peer.finish(&mut socket).await;
        assert_eq!(identity.xuid(), script::HOST_XUID);
        assert!(matches!(event, rta::Event::Resync { subscriptions } if subscriptions.contains(&subscription)));
        assert_eq!(update, mpsd::Update::Updated);
        assert!(newer && removed && original_owner);
    })
    .await
    .unwrap();
}
