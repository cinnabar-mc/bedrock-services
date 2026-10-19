use super::*;
use crate::signaling::{Event, websocket::MessagingSocket};
use p384::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

/// Actual fresh mint and TURN requests retain the original account, sockets and conditional cleanup.
#[tokio::test]
async fn hosted_activation_renews_same_key_and_moves_fresh_turn_result_once() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cap = NonZeroU32::new(2).unwrap();
        let title = "42".to_owned();
        let HostedAuthority {
            mut account, peer, ..
        } = HostedAuthority::acquire_activation_renewal(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            cap,
            title.clone(),
            "fixture-audience".into(),
        )
        .await;
        let key = SigningKey::from_slice(&[1; 48]).unwrap();
        let minted = account
            .multiplayer_token(key.verifying_key())
            .await
            .unwrap();
        let original_public = minted.public_key_der().to_vec();
        let request = account.messaging_connection().await.unwrap();
        let messaging_id = request.player_messaging_id();
        let network_id = 9;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut messaging = MessagingSocket::connect(&request, network_id, Default::default())
            .await
            .unwrap();
        let original_turn = messaging.request_credentials(deadline).unwrap();
        let original_completed = matches!(
            messaging.drive().await,
            Ok(Event::Completed { request, result: Ok(()) }) if request == original_turn
        );
        let credentials = messaging.take_credentials().unwrap();
        let original_expiry = credentials.expires_at();
        let original_empty = credentials.servers().is_empty();
        drop(credentials);
        let original_moved_once = messaging.take_credentials().is_none();

        let headers = rta::websocket::upgrade_headers().unwrap();
        let mut request = account
            .rta_connection(rta::Generation::new(7).unwrap(), headers)
            .await
            .unwrap();
        let mut socket = RtaSocket::connect(&mut request, Default::default())
            .await
            .unwrap();
        let (subscription, _) = socket
            .subscribe(rta::Resource::session_directory(), deadline)
            .unwrap();
        assert!(matches!(
            socket.drive().await,
            Ok(rta::Event::Subscribed { subscription: got, .. }) if got == subscription
        ));
        let binding = socket
            .connection()
            .directory_binding(subscription, Uuid::from_u128(2))
            .unwrap();
        let reference =
            mpsd::Reference::new(Uuid::from_u128(7), "Fixture".into(), "Original".into()).unwrap();
        let mut properties = json!({"MaxMemberCount":cap.get(),"nonces":{},"SupportedConnections":[{
            "NetherNetId":network_id,"PmsgId":messaging_id,
        }]});
        let (mut session, created, acknowledged, activity, invited) = {
            let mut directory = account.mpsd();
            let mut attempt = directory
                .publish_attempt(
                    &reference,
                    mpsd::Publish {
                        binding,
                        member: Default::default(),
                        constants: None,
                        max_members: Some(cap),
                        properties: Some(properties.clone()),
                        join: mpsd::Restriction::Followed,
                        read: mpsd::Restriction::Followed,
                    },
                )
                .unwrap();
            let mut session = directory.publish_retained(&mut attempt).await.unwrap();
            let created = directory.sync(&mut session).await;
            properties["nonces"]["456"] = json!("original-peer-nonce");
            let acknowledged = directory
                .set_properties_bound(&mut session, binding, &properties)
                .await;
            let activity = directory.publish_activity(&session).await;
            let invited = directory.invite(&session, "456", &title).await;
            (session, created, acknowledged, activity, invited)
        };
        let renewed = account
            .multiplayer_token(key.verifying_key())
            .await
            .unwrap();
        let renewed_public = renewed.public_key_der().to_vec();
        let fresh_turn = messaging.request_credentials(deadline).unwrap();
        let fresh_completed = matches!(
            messaging.drive().await,
            Ok(Event::Completed { request, result: Ok(()) }) if request == fresh_turn
        );
        let credentials = messaging.take_credentials().unwrap();
        let refreshed_expiry = credentials.expires_at();
        let refreshed_empty = credentials.servers().is_empty();
        drop(credentials);
        let fresh_moved_once = messaging.take_credentials().is_none();
        let (refreshed, left, closed) = {
            let mut directory = account.mpsd();
            let refreshed = directory.sync(&mut session).await;
            let left = directory.leave_bound(&mut session, binding).await;
            (refreshed, left, session.is_closed())
        };
        socket.abort();
        messaging.close();
        let messaging_closed = messaging.drive().await.err();
        drop(messaging);
        let observed = peer.finish_activation_renewal().await;

        assert_eq!(
            original_public,
            key.verifying_key().to_public_key_der().unwrap().as_bytes()
        );
        assert_eq!(renewed_public, original_public);
        assert_eq!(observed.activation.minted_public_key, original_public);
        assert_eq!(observed.renewed_public_key, renewed_public);
        assert_ne!(original_turn, fresh_turn);
        assert_ne!(
            observed.original_turn_request,
            observed.refreshed_turn_request
        );
        assert!(original_completed && fresh_completed);
        assert!(original_moved_once && fresh_moved_once);
        assert!(original_empty && refreshed_empty);
        assert!(refreshed_expiry > original_expiry);
        assert_eq!(created.unwrap(), mpsd::Update::Unchanged);
        assert_eq!(acknowledged.unwrap(), mpsd::Update::Updated);
        activity.unwrap();
        invited.unwrap();
        assert_eq!(refreshed.unwrap(), mpsd::Update::Unchanged);
        assert_eq!(left.unwrap(), mpsd::Update::Closed);
        assert!(closed);
        assert_eq!(observed.activation.max_members, cap.get());
        assert_eq!(observed.activation.invited_xuid, "456");
        assert_eq!(
            messaging_closed,
            Some(crate::signaling::websocket::SocketError::Closed)
        );
        assert_eq!(
            observed.activation.rta,
            HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof)
        );
        assert!(matches!(
            observed.activation.messaging,
            HostedSocketTerminal::Close | HostedSocketTerminal::Eof
        ));
    })
    .await
    .unwrap();
}
