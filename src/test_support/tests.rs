use super::*;

/// Actual original/fresh/restored cryptographic owners, signed conditional acknowledgment and cleanup.
#[tokio::test]
async fn hosted_authority_retains_the_original_proof_across_checkpoint_restore() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let HostedAuthority {
            mut account,
            identity,
            mut peer,
        } = HostedAuthority::acquire(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
        )
        .await;
        assert_eq!(identity.xuid(), script::HOST_XUID);
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
        assert!(account.owns_rta(socket.connection()));
        assert!(session.is_bound(binding));
        peer.set_properties_bound(
            &mut account,
            &mut session,
            binding,
            &json!({"synthetic":"acknowledged"}),
        )
        .await;
        let checkpoint = account.checkpoint().unwrap();
        let (fresh, fresh_identity) = peer.fresh_account().await;
        assert_eq!(fresh_identity.xuid(), identity.xuid());
        assert!(!fresh.owns_rta(socket.connection()));
        let (mut restored, restored_identity) = peer.restore_account(checkpoint).await;
        assert_eq!(restored_identity.xuid(), identity.xuid());
        assert!(restored.owns_rta(socket.connection()));
        peer.leave_bound(&mut restored, &mut session, binding).await;
        peer.finish(&mut socket).await;
    })
    .await
    .unwrap();
}
