use super::*;

/// A real retained Resync and signed 304 preserve the same complete snapshot and original cleanup validator.
#[tokio::test]
async fn hosted_resync_keeps_original_acknowledged_snapshot_on_304() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let HostedAuthority {
            mut account,
            mut peer,
            ..
        } = HostedAuthority::acquire_unchanged(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
        )
        .await;
        let reference =
            mpsd::Reference::new(Uuid::from_u128(7), "Fixture".into(), "Original".into()).unwrap();
        let HostedMembership {
            mut socket,
            binding,
            mut session,
            ..
        } = peer
            .host(
                &mut account,
                &reference,
                Uuid::from_u128(2),
                rta::Generation::new(7).unwrap(),
                "456",
            )
            .await;
        let custom = json!({"nonces":{"456":"original-acknowledged-nonce"}});
        peer.set_properties_bound(&mut account, &mut session, binding, &custom)
            .await;
        peer.resync_unchanged_ready(&mut socket).await;
        let resync = matches!(socket.drive().await, Ok(rta::Event::Resync { .. }));
        let synchronized = account.mpsd().sync(&mut session).await;
        let same_custom = session
            .description()
            .properties
            .as_ref()
            .unwrap()
            .custom
            .as_ref()
            == Some(&custom);
        let bound = session.is_bound(binding) && account.owns_rta(socket.connection());
        peer.leave_bound(&mut account, &mut session, binding).await;
        peer.finish(&mut socket).await;
        assert!(resync, "the next actual retained event must be Resync");
        assert_eq!(synchronized.unwrap(), mpsd::Update::Unchanged);
        assert!(same_custom && bound);
        assert!(session.is_closed());
    })
    .await
    .unwrap();
}
