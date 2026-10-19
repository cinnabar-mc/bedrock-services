use super::*;
use crate::signaling::{Event, websocket::MessagingSocket};
use p384::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

/// Actual public SDK HTTP/TLS/socket constructors retain original proof, mint, route and cleanup owners.
#[tokio::test]
async fn hosted_activation_routes_real_connectors_and_original_create() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cap = NonZeroU32::new(2).unwrap();
        let title = "42".to_owned();
        let HostedAuthority { mut account, peer, .. } = HostedAuthority::acquire_activation(
            xbox::Config::default(), minecraft::Config::desktop("1.0.0",1,Uuid::from_u128(1)),
            cap,title.clone(),"fixture-audience".into(),
        ).await;
        let key = SigningKey::from_slice(&[1;48]).unwrap();
        let minted = account.multiplayer_token(key.verifying_key()).await.unwrap();
        let minted_public = minted.public_key_der().to_vec();
        let request = account.messaging_connection().await.unwrap();
        let messaging_id = request.player_messaging_id();
        let deadline = Instant::now()+Duration::from_secs(10);
        let mut messaging = MessagingSocket::connect(&request,9,Default::default()).await.unwrap();
        let turn = messaging.request_credentials(deadline).unwrap();
        assert!(matches!(messaging.drive().await,Ok(Event::Completed { request, result:Ok(()) }) if request==turn));
        let empty_ice = messaging.credentials().unwrap().servers().is_empty();
        let headers = rta::websocket::upgrade_headers().unwrap();
        let mut request = account.rta_connection(rta::Generation::new(7).unwrap(),headers).await.unwrap();
        let mut socket = RtaSocket::connect(&mut request,Default::default()).await.unwrap();
        let (subscription,_) = socket.subscribe(rta::Resource::session_directory(),deadline).unwrap();
        assert!(matches!(socket.drive().await,Ok(rta::Event::Subscribed { subscription:got,.. }) if got==subscription));
        let binding = socket.connection().directory_binding(subscription,Uuid::from_u128(2)).unwrap();
        let reference = mpsd::Reference::new(Uuid::from_u128(7),"Fixture".into(),"Original".into()).unwrap();
        let mut properties=json!({"MaxMemberCount":cap.get(),"nonces":{},"SupportedConnections":[{
            "NetherNetId":9,"PmsgId":messaging_id,
        }]});
        let (created, acknowledged, activity, invited, refreshed, left, bound) = {
            let mut directory=account.mpsd();
            let mut attempt=directory.publish_attempt(&reference,mpsd::Publish {
                binding,member:Default::default(),constants:None,max_members:Some(cap),properties:Some(properties.clone()),
                join:mpsd::Restriction::Followed,read:mpsd::Restriction::Followed,
            }).unwrap();
            let mut session=directory.publish_retained(&mut attempt).await.unwrap();
            let created=directory.sync(&mut session).await;
            properties["nonces"]["456"]=json!("original-peer-nonce");
            let acknowledged=directory.set_properties_bound(&mut session,binding,&properties).await;
            let activity=directory.publish_activity(&session).await;
            let invited=directory.invite(&session,"456",&title).await;
            let refreshed=directory.sync(&mut session).await;
            let left=directory.leave_bound(&mut session,binding).await;
            (created, acknowledged, activity, invited, refreshed, left, session.is_closed())
        };
        socket.abort();
        messaging.close();
        let messaging_closed=messaging.drive().await.err();
        drop(messaging);
        let observed=peer.finish_activation().await;
        assert_eq!(minted_public,key.verifying_key().to_public_key_der().unwrap().as_bytes());
        assert_eq!(observed.minted_public_key,minted_public);
        assert!(empty_ice && bound);
        assert_eq!(created.unwrap(),mpsd::Update::Unchanged);
        assert_eq!(acknowledged.unwrap(),mpsd::Update::Updated);
        activity.unwrap();invited.unwrap();
        assert_eq!(refreshed.unwrap(),mpsd::Update::Unchanged);
        assert_eq!(left.unwrap(),mpsd::Update::Closed);
        assert_eq!(observed.max_members,cap.get());
        assert_eq!(observed.created_properties["SupportedConnections"][0]["PmsgId"],json!(messaging_id));
        assert_eq!(observed.invited_xuid,"456");
        assert_eq!(messaging_closed,Some(crate::signaling::websocket::SocketError::Closed));
        assert_eq!(observed.rta,HostedSocketTerminal::Io(io::ErrorKind::UnexpectedEof));
        assert!(matches!(observed.messaging,HostedSocketTerminal::Close|HostedSocketTerminal::Eof));
    }).await.unwrap();
}

/// Canceling the actual consuming finish retains abort ownership of every original pending service task.
#[tokio::test]
async fn cancelled_activation_fixture_finish_retires_all_original_servers() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let HostedAuthority {
        account: _account,
        peer,
        ..
    } = HostedAuthority::acquire_activation(
        xbox::Config::default(),
        minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
        NonZeroU32::new(2).unwrap(),
        "42".into(),
        "fixture-audience".into(),
    )
    .await;
    let active = peer.activation.as_ref().unwrap();
    let servers = [
        peer.http.as_ref().unwrap().abort_handle(),
        active.rta.as_ref().unwrap().abort_handle(),
        active.messaging.as_ref().unwrap().abort_handle(),
    ];
    let mut finishing = Box::pin(peer.finish_activation());
    let pending = finishing
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending();
    drop(finishing);
    let retired = finished(&servers).await;
    for server in &servers {
        server.abort();
    }
    let cleaned = finished(&servers).await;
    assert!(
        cleaned,
        "original finite server tasks did not complete failure cleanup"
    );
    assert!(
        pending,
        "the actual unfinished HTTP/socket tasks unexpectedly completed"
    );
    assert!(
        retired,
        "canceling fixture finish detached an original server task"
    );
}

/// Waits only for actual Tokio task completion; the finite guard also lets the RED run clean its owners.
async fn finished(servers: &[tokio::task::AbortHandle]) -> bool {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !servers.iter().all(tokio::task::AbortHandle::is_finished) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}

/// A real mint-only caller joins every unused original listener without fabricating hosting requests.
#[tokio::test]
async fn aborted_activation_joins_original_servers_and_reports_only_the_minted_prefix() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let HostedAuthority {
            mut account, peer, ..
        } = HostedAuthority::acquire_activation(
            xbox::Config::default(),
            minecraft::Config::desktop("1.0.0", 1, Uuid::from_u128(1)),
            NonZeroU32::new(2).unwrap(),
            "42".into(),
            "fixture-audience".into(),
        )
        .await;
        let key = SigningKey::from_slice(&[1; 48]).unwrap();
        let minted = account
            .multiplayer_token(key.verifying_key())
            .await
            .unwrap();
        let public = minted.public_key_der().to_vec();
        let activation = peer.activation.as_ref().unwrap();
        let servers = [
            peer.http.as_ref().unwrap().abort_handle(),
            activation.rta.as_ref().unwrap().abort_handle(),
            activation.messaging.as_ref().unwrap().abort_handle(),
        ];
        let observed = peer.abort_activation().await;
        assert!(servers.iter().all(tokio::task::AbortHandle::is_finished));
        assert_eq!(observed.verified_http_requests, 9);
        assert_eq!(observed.minted_public_key, public);
        assert_eq!(
            public,
            key.verifying_key().to_public_key_der().unwrap().as_bytes()
        );
    })
    .await
    .unwrap();
}
