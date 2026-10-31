use super::*;

const MARKER: &str = "original-turn-retirement-marker";

/// Finite actual service credentials; the synthetic endpoint is never contacted.
fn credentials(name: &str) -> Value {
    json!({"ExpirationInSeconds":60,"TurnAuthServers":[{
        "Username":name,"Password":"synthetic-retirement-password","Urls":["turn:fixture.invalid:3478"]
    }]})
}

/// Observes an actual written request while leaving the original borrowed drive cancelable.
async fn written(client: &mut MessagingSocket, server: &mut WebSocketStream<TcpStream>) -> Value {
    let drive = client.drive();
    tokio::pin!(drive);
    tokio::select! { biased;
        wire = read_json(server) => wire,
        _ = &mut drive => panic!("request completed before its actual response"),
    }
}

/// Exact retirement drops a batched cached result before its queued completion can be exposed.
#[tokio::test]
async fn retires_actual_batched_turn_cache_and_preserves_successor() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut client, mut server) = pair_with_initial(TEST_NETWORK_ID, None).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let original = client.request_credentials(deadline).unwrap();
        let request = written(&mut client, &mut server).await;
        server
            .send(Message::text(
                json!([
                    {"jsonrpc":"2.0","id":"unmatched-before-result","result":null},
                    {"jsonrpc":"2.0","id":request["id"],"result":credentials("batched")}
                ])
                .to_string(),
            ))
            .await
            .unwrap();
        let first_ignored = matches!(client.drive().await, Ok(Event::Ignored));
        let cached_before_completion =
            client.credentials().unwrap().servers()[0].username() == "batched";
        let retired = client.retire_credentials(original);
        let cleared = client.credentials().is_none();
        let repeated = client.retire_credentials(original);
        let successor = client.request_credentials(deadline).unwrap();
        let request = written(&mut client, &mut server).await;
        server
            .send(Message::text(
                json!({
                    "jsonrpc":"2.0","id":request["id"],"result":credentials("successor")
                })
                .to_string(),
            ))
            .await
            .unwrap();
        let successor_completed = matches!(client.drive().await,
            Ok(Event::Completed {request,result:Ok(())}) if request == successor);
        let stale = client.retire_credentials(original);
        let owner = client.take_credentials().unwrap();
        let moved_once = client.take_credentials().is_none();
        client.close();
        let (closed, peer_closed) = tokio::join!(client.drive(), server.close());
        assert!(matches!(closed, Err(SocketError::Closed)) && peer_closed.is_ok());
        assert!(first_ignored && cached_before_completion && retired && cleared);
        assert!(!repeated && !stale);
        assert!(successor_completed && moved_once);
        assert_eq!(owner.servers()[0].username(), "successor");
    })
    .await
    .unwrap();
}

/// Retiring local capacity cannot retract an accepted wire prefix or replay that request.
#[tokio::test]
async fn credential_retirement_retracts_unsent_but_preserves_partial_written_prefix_once() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut client, mut server) = pair_with_initial(TEST_NETWORK_ID, None).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let unsent = client.request_credentials(deadline).unwrap();
        let unsent_retired = client.retire_credentials(unsent);
        let original = client.request_credentials(deadline).unwrap();
        client.socket.as_mut().unwrap().get_mut().limit_writes(1);
        poll_fn(|cx| {
            assert!(client.poll_drive(cx).is_pending());
            if client.socket.as_ref().unwrap().get_ref().write_budget() == Some(0) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        let partial = client.write_active;
        let retired = client.retire_credentials(original);
        let partial_retained = client.write_active;
        client.socket.as_mut().unwrap().get_mut().resume_writes();
        let successor = client.request_credentials(deadline).unwrap();
        let application = async {
            let mut late_ignored = false;
            let mut completed_original = false;
            loop {
                match client.drive().await.unwrap() {
                    Event::Ignored => late_ignored = true,
                    Event::Completed {
                        request,
                        result: Ok(()),
                    } if request == original => completed_original = true,
                    Event::Completed {
                        request,
                        result: Ok(()),
                    } if request == successor => break,
                    _ => panic!("unexpected credential retirement event"),
                }
            }
            let marker = client
                .send_signal(
                    Uuid::from_u128(4),
                    Uuid::from_u128(5),
                    MARKER,
                    false,
                    deadline,
                )
                .unwrap();
            let marked = matches!(client.drive().await,
                Ok(Event::Completed {request,result:Ok(())}) if request == marker);
            let owner = client.take_credentials().unwrap();
            let moved_once = client.take_credentials().is_none();
            client.close();
            let closed = client.drive().await;
            (
                late_ignored,
                completed_original,
                marked,
                owner,
                moved_once,
                closed,
            )
        };
        let service = async {
            let first = read_json(&mut server).await;
            let second = read_json(&mut server).await;
            assert_eq!(RequestId(first["id"].as_u64().unwrap()), original);
            assert_eq!(RequestId(second["id"].as_u64().unwrap()), successor);
            server
                .send(Message::text(
                    json!([
                        {"jsonrpc":"2.0","id":first["id"],"result":credentials("retired")},
                        {"jsonrpc":"2.0","id":second["id"],"result":credentials("successor")}
                    ])
                    .to_string(),
                ))
                .await
                .unwrap();
            let marker = read_json(&mut server).await;
            assert_eq!(marker["method"], wire::SEND);
            let inner: Value =
                serde_json::from_str(marker["params"]["message"].as_str().unwrap()).unwrap();
            assert_eq!(inner["params"]["message"], MARKER);
            server
                .send(Message::text(
                    json!({"jsonrpc":"2.0","id":marker["id"],"result":null}).to_string(),
                ))
                .await
                .unwrap();
            server.close().await
        };
        let (application, service) = tokio::join!(application, service);
        let (late_ignored, completed_original, marked, owner, moved_once, closed) = application;
        assert!(service.is_ok() && matches!(closed, Err(SocketError::Closed)));
        assert!(unsent_retired && partial && retired && partial_retained);
        assert!(late_ignored && !completed_original && marked && moved_once);
        assert_eq!(owner.servers()[0].username(), "successor");
    })
    .await
    .unwrap();
}
