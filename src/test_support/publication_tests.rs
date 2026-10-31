use super::*;
use std::num::NonZeroU32;

/// The actual first signed create transmits capacity/route before the same nonce/activity/invitation lifetime.
#[tokio::test]
async fn hosted_publication_transmits_capacity_and_route_before_activity_and_invitation() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cap = NonZeroU32::new(2).unwrap();
        let title = "42".to_owned();
        let properties = json!({"MaxMemberCount":cap.get(), "nonces":{}, "SupportedConnections":[{
            "ConnectionType":7, "NetherNetId":9, "PmsgId":Uuid::from_u128(3),
        }]});
        let HostedAuthority {
            mut account,
            identity,
            mut peer,
        } = HostedAuthority::acquire_publication(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            cap,
            title.clone(),
            properties.clone(),
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
            .publish_host(
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
        let original_route = session
            .description()
            .properties
            .as_ref()
            .unwrap()
            .custom
            .as_ref()
            == Some(&properties);
        let created_refresh = account.mpsd().sync(&mut session).await;
        let mut acknowledged = properties;
        acknowledged["nonces"]["456"] = json!("original-peer-nonce");
        peer.set_properties_bound(&mut account, &mut session, binding, &acknowledged)
            .await;
        let activity = account.mpsd().publish_activity(&session).await;
        let invited = account.mpsd().invite(&session, "456", &title).await;
        let final_refresh = account.mpsd().sync(&mut session).await;
        peer.leave_bound(&mut account, &mut session, binding).await;
        peer.finish(&mut socket).await;
        assert!(original_proof && original_route);
        assert_eq!(capacity, Some(u64::from(cap.get())));
        assert_eq!(created_refresh.unwrap(), mpsd::Update::Unchanged);
        activity.unwrap();
        let invited = invited.unwrap();
        assert!(!invited.id.is_nil());
        assert_eq!(invited.sender_xuid.as_deref(), Some(identity.xuid()));
        assert_eq!(invited.invited_xuid.as_deref(), Some("456"));
        assert_eq!(
            invited.reference().unwrap().name.as_deref(),
            Some(reference.name())
        );
        assert_eq!(final_refresh.unwrap(), mpsd::Update::Unchanged);
        assert!(session.is_closed());
    })
    .await
    .unwrap();
}
