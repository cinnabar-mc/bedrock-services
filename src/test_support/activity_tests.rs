use super::*;
use std::num::NonZeroU32;

/// Actual signed activity/invite requests retain the original owner, route reference and cleanup binding.
#[tokio::test]
async fn hosted_activity_and_invitation_use_the_same_signed_membership() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cap = NonZeroU32::new(2).unwrap();
        let title = "42".to_owned();
        let HostedAuthority {
            mut account,
            identity,
            mut peer,
        } = HostedAuthority::acquire_activity(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            cap,
            title.clone(),
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
        let original_proof = account.owns_rta(socket.connection());
        let capacity = session
            .description()
            .constants
            .as_ref()
            .unwrap()
            .system
            .as_ref()
            .unwrap()["maxMembersCount"]
            .as_u64();
        peer.set_properties_bound(
            &mut account,
            &mut session,
            binding,
            &json!({"fixture":"acknowledged"}),
        )
        .await;
        let activity = account.mpsd().publish_activity(&session).await;
        let invited = account.mpsd().invite(&session, "456", &title).await;
        let synchronized = account.mpsd().sync(&mut session).await;
        peer.leave_bound(&mut account, &mut session, binding).await;
        peer.finish(&mut socket).await;
        assert!(original_proof);
        assert_eq!(capacity, Some(u64::from(cap.get())));
        activity.unwrap();
        let invited = invited.unwrap();
        assert!(!invited.id.is_nil());
        assert_eq!(invited.sender_xuid.as_deref(), Some(identity.xuid()));
        assert_eq!(invited.invited_xuid.as_deref(), Some("456"));
        assert_eq!(
            invited.reference().unwrap().name.as_deref(),
            Some(reference.name())
        );
        assert_eq!(synchronized.unwrap(), mpsd::Update::Unchanged);
        assert!(session.is_closed());
    })
    .await
    .unwrap();
}
