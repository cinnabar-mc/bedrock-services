use super::*;
use serde_json::{Value, json};
use std::task::Waker;

/// The actual edge retains a canceled partial write, pushed credentials and inbound legacy routing.
#[tokio::test]
async fn legacy_socket_preserves_cancelled_write_and_real_signal_prefix() {
    let (mut client, mut peer) = test_support::pair_legacy(9).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let original = Uuid::from_u128(1);
    let marker = Uuid::from_u128(2);
    client.socket.as_mut().unwrap().get_mut().limit_writes(0);
    let request = client
        .send_legacy_signal("remote", original, "original", false, deadline)
        .unwrap();
    {
        let driving = client.drive();
        tokio::pin!(driving);
        assert!(
            driving
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    client.socket.as_mut().unwrap().get_mut().resume_writes();
    let application = async {
        assert!(
            matches!(client.drive().await.unwrap(),Event::Completed { request:got,result:Ok(()) } if got==request)
        );
        let credentials = client.request_credentials(deadline).unwrap();
        assert!(
            matches!(client.drive().await.unwrap(),Event::Completed { request:got,result:Ok(()) } if got==credentials)
        );
        assert!(client.credentials().unwrap().servers().is_empty());
        let Event::LegacySignal(signal) = client.drive().await.unwrap() else {
            panic!("actual legacy signal");
        };
        assert_eq!(signal.sender(), "remote");
        assert_eq!(signal.signal(), "actual-incoming");
        let sent = client
            .send_legacy_signal("remote", marker, "through-marker", false, deadline)
            .unwrap();
        assert!(
            matches!(client.drive().await.unwrap(),Event::Completed { request:got,result:Ok(()) } if got==sent)
        );
        client.close();
        assert_eq!(client.drive().await.err(), Some(SocketError::Closed));
    };
    let service = async {
        let first: Value = serde_json::from_str(&peer.recv_text().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            first,
            json!({"Type":1,"To":"remote","Message":"original","MessageId":original})
        );
        peer.send_text(&json!({"Type":2,"From":"Server","Message":json!({"ExpirationInSeconds":300,"TurnAuthServers":[]}).to_string()}).to_string()).await.unwrap();
        peer.send_text(&json!({"Type":1,"From":"remote","Message":"actual-incoming"}).to_string())
            .await
            .unwrap();
        let next: Value = serde_json::from_str(&peer.recv_text().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            next,
            json!({"Type":1,"To":"remote","Message":"through-marker","MessageId":marker}),
            "the same reliable stream must contain neither a replay nor an invented peer receipt before its marker"
        );
        peer.close().await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(application, service);
    })
    .await
    .unwrap();
}
