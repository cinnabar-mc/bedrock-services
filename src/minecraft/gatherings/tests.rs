use super::*;
use crate::{
    minecraft::{
        USER_AGENT,
        test_support::{authorization, services},
    },
    realms::NetworkProtocol,
    xbox::test_support::{fixture_bytes, read_request},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const EXPERIENCE: Uuid = Uuid::from_u128(17);

/// The catalog's read-only POST can recover without changing its body or credential.
#[tokio::test]
async fn catalog_search_retries_the_same_read_only_post() {
    crate::http::retry::with_virtual_retry_time(async {
        let mut step = 0;
        let (address, server) = fixture_bytes(
            move |path, headers, body| {
                step += 1;
                if step == 1 {
                    return (200, vec![], discovery(headers, None));
                }
                assert_eq!(path, "/gatherings-prefix/api/v2.0/discovery/blob/client");
                assert_eq!(body, b"{}\n");
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("authorization: mctoken original.")
                );
                if step == 2 {
                    (503, vec![], Vec::new())
                } else {
                    (200, vec![], br#"{"data":{"Items":[]}}"#.to_vec())
                }
            },
            3,
        )
        .await;
        let mut services = services(address);
        let result = services
            .gatherings()
            .await
            .unwrap()
            .search_items(&SearchFilter::default())
            .await;
        if result.is_err() {
            server.abort();
        }
        let served = server.await;
        assert!(result.unwrap().items.is_empty());
        served.unwrap();
    })
    .await
}

/// Supplies only public synthetic discovery, retaining the actual fixture host/path prefix.
fn discovery(headers: &str, gatherings: Option<Value>) -> Vec<u8> {
    let host = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .unwrap()
        .1
        .trim();
    json!({"result":{"serviceEnvironments":{
        "auth":{"prod":{"serviceUri":format!("http://{host}/auth"),"playFabTitleId":"AB12"}},
        "gatherings":gatherings.unwrap_or_else(|| json!({"prod":{"serviceUri":format!("http://{host}/gatherings-prefix")}}))
    }}}).to_string().into_bytes()
}

/// Drives actual discovery/search/count/join requests without an account substitute or metadata fetch.
#[tokio::test]
async fn gatherings_requests_keep_catalog_metadata_counts_and_explicit_join_transport() {
    let mut step = 0;
    let (address, server) = fixture_bytes(move |path, headers, bytes| {
        step += 1;
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains(&format!("user-agent: {USER_AGENT}")));
        if step == 1 {
            assert_eq!(path, "/api/v1.0/discovery/MinecraftPE/builds/1.26.50");
            assert!(!lower.contains("authorization:"));
            return (200, vec![], discovery(headers, None));
        }
        assert!(lower.contains("authorization: mctoken original."));
        assert!(lower.contains("accept: application/json"));
        for absent in ["signature:", "x-entitytoken:", "session-id:", "x-xbl-contract-version:"] {
            assert!(!lower.contains(absent));
        }
        let value = match step {
            2 => {
                assert_eq!(path, "/gatherings-prefix/api/v2.0/discovery/blob/client");
                assert!(lower.starts_with("post "));
                assert!(lower.contains("accept-language: en-us"));
                assert_eq!(bytes, b"{}\n");
                json!({"data":{"ContinuationToken":"next-page","Items":[
                    {"Id":"creator","ContentType":"3PP_V2.0","Title":{"en-US":"Creator","en_US":null},"Description":{"en-US":"Creator description","en_US":null},
                     "DisplayProperties":{"experienceId":EXPERIENCE,"news":"hello","availableGames":[{"title":"Game","imageTag":"mode"},null],"creatorName":false,"unused":{"opaque":true}}},
                    {"Id":"rank-zero","IsHidden":true,"ContentType":"3PP_V2.0","Title":{"NEUTRAL":"Zero"},
                     "Description":{"en_US":"Description"},"Images":[{"Id":"i","Tag":"Icon","Type":"Thumbnail","Url":"https://art.example/card"},null],
                     "DisplayProperties":{"url":"play.example","port":19132,"rank":0}},
                    {"Id":"invalid-properties","ContentType":"3PP_V2.0","DisplayProperties":[]},
                    {"Id":"future-type","ContentType":"FUTURE","DisplayProperties":{"rank":null}},
                    {"Id":"invalid-game","ContentType":"3PP_V2.0","DisplayProperties":{"availableGames":[[]]}},
                    null
                ]}})
            }
            3 => {
                assert_eq!(path, "/gatherings-prefix/api/v2.0/dataquery/playercounts");
                assert!(lower.starts_with("get "));
                assert!(bytes.is_empty());
                assert!(!lower.contains("content-type:"));
                json!({"result":[{"experienceId":EXPERIENCE,"playerCount":0},
                    {"experienceId":Uuid::from_u128(18)}, {"experienceId":Uuid::from_u128(19),"playerCount":-7},
                    null, [], {"experienceId":Uuid::nil(),"playerCount":9}, {"experienceId":"invalid","playerCount":1}]})
            }
            4..=7 => {
                assert_eq!(path, "/gatherings-prefix/api/v2.0/join/experience");
                assert!(lower.starts_with("post "));
                assert!(!lower.contains("accept-language:"));
                assert_eq!(serde_json::from_slice::<Value>(bytes).unwrap(), json!({"experienceId":EXPERIENCE}));
                json!({"result":{"networkProtocol":match step {4=>"NetherNet_JsonRpc",5=>"nethernet",6=>"Default",_=>"QUIC"},
                    "netherNetId":"1234567","ipV4Address":"203.0.113.7","port":19132,
                    "destinationInfo":{"experienceId":EXPERIENCE,"experienceName":"Selected",
                        "creatorId":"creator","serverId":"original-server","worldId":Uuid::from_u128(20),
                        "scenarioId":Uuid::from_u128(21),"mpsasScenarioId":"opaque","targetId":"target","worldName":"World"}}})
            }
            8 => {
                assert_eq!(path, "/gatherings-prefix/api/v2.0/discovery/blob/client");
                assert_eq!(serde_json::from_slice::<Value>(bytes).unwrap(), json!({"Count":2,"ContinuationToken":"next-page"}));
                return (401, vec![], br#"{"diagnostic":"SENSITIVE"}"#.to_vec());
            }
            _ => unreachable!(),
        };
        (200, vec![], value.to_string().into_bytes())
    }, 8).await;
    let mut services = services(address);
    let original = Arc::clone(services.authorization.as_ref().unwrap());
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut api = services.gatherings().await.unwrap();
        assert!(api.join_experience(Uuid::nil()).await.is_err());
        assert!(
            api.search_items(&SearchFilter {
                count: Some(51),
                ..Default::default()
            })
            .await
            .is_err()
        );
        let catalog = api.search_items(&SearchFilter::default()).await.unwrap();
        assert_eq!(catalog.continuation_token, "next-page");
        assert_eq!(
            catalog
                .items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            [
                "creator",
                "rank-zero",
                "invalid-properties",
                "future-type",
                "invalid-game",
                ""
            ]
        );
        assert_eq!(catalog.items[0].title["en-US"], "Creator");
        assert!(catalog.items[0].title["en_US"].is_empty());
        assert_eq!(catalog.items[0].description["en-US"], "Creator description");
        assert!(catalog.items[0].description["en_US"].is_empty());
        assert_eq!(catalog.items[0].properties().unwrap().rank, None);
        assert!(
            catalog.items[0]
                .display_properties
                .as_ref()
                .unwrap()
                .get()
                .contains("opaque")
        );
        assert!(
            catalog.items[0]
                .display_properties
                .as_ref()
                .unwrap()
                .get()
                .contains("\"creatorName\":false")
        );
        assert_eq!(
            catalog.items[0].properties().unwrap().available_games[0].image_tag,
            "mode"
        );
        let games = catalog.items[0].properties().unwrap().available_games;
        assert_eq!(games.len(), 2);
        assert_eq!(games[0].title, "Game");
        assert!(games[1].title.is_empty());
        assert_eq!(catalog.items[1].properties().unwrap().rank, Some(0));
        assert!(catalog.items[1].hidden);
        assert_eq!(catalog.items[1].images[0].url, "https://art.example/card");
        assert_eq!(catalog.items[1].images.len(), 2);
        assert!(catalog.items[1].images[1].url.is_empty());
        assert!(catalog.items[2].properties().is_err());
        assert_eq!(catalog.items[3].content_type, "FUTURE");
        assert!(catalog.items[4].properties().is_err());
        assert!(catalog.items[5].content_type.is_empty());
        let mut counts = api.player_counts().await.unwrap();
        assert_eq!(counts.len(), 3);
        assert_eq!(
            counts
                .iter()
                .map(|count| count.player_count)
                .collect::<Vec<_>>(),
            [Some(0), None, Some(-7)]
        );
        counts[0].player_count = Some(999);
        assert_eq!(api.player_counts().await.unwrap()[0].player_count, Some(0));
        let joined = api.join_experience(EXPERIENCE).await.unwrap();
        assert_eq!(joined.network_protocol, NetworkProtocol::NetherNetJsonRpc);
        assert_eq!(joined.destination_info.experience_id, EXPERIENCE);
        assert_eq!(joined.destination_info.server_id, "original-server");
        assert_eq!(joined.nethernet_id, "1234567");
        for _ in 0..3 {
            assert!(matches!(
                api.join_experience(EXPERIENCE).await,
                Err(crate::Error::UnsupportedNetworkProtocol)
            ));
        }
        let error = api
            .search_items(&SearchFilter {
                count: Some(2),
                continuation_token: catalog.continuation_token,
                ..Default::default()
            })
            .await
            .err()
            .unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    })
    .await;
    if result.is_err() {
        server.abort();
    }
    let served = server.await;
    result.unwrap();
    served.unwrap();
    assert!(services.authorization.is_none());
    services.authorization = Some(authorization("replacement"));
    assert!(!services.reject(&original));
}

/// Authorization failures short-circuit joins; a final rejection preserves the same typed status.
#[tokio::test]
async fn join_preserves_authorization_and_request_failures_without_an_extra_dispatch() {
    for authorization_failure in [true, false] {
        let mut step = 0;
        let (address, server) = fixture_bytes(
            move |path, headers, bytes| {
                step += 1;
                let headers_lower = headers.to_ascii_lowercase();
                if step == 1 {
                    assert_eq!(path, "/api/v1.0/discovery/MinecraftPE/builds/1.26.50");
                    return (200, vec![], discovery(headers, None));
                }
                assert_eq!(step, 2);
                if authorization_failure {
                    assert_eq!(path, "/api/v1.0/discovery/MinecraftPE/builds/1.26.60");
                    assert!(headers_lower.starts_with("get "));
                    assert!(!headers_lower.contains("authorization:"));
                    assert!(bytes.is_empty());
                } else {
                    assert_eq!(path, "/gatherings-prefix/api/v2.0/join/experience");
                    assert!(headers_lower.starts_with("post "));
                    assert!(headers_lower.contains("authorization: mctoken original."));
                    assert_eq!(
                        serde_json::from_slice::<Value>(bytes).unwrap(),
                        json!({"experienceId": EXPERIENCE})
                    );
                }
                (404, vec![("x-err", "1234")], b"SENSITIVE".to_vec())
            },
            2,
        )
        .await;
        let mut services = services(address);
        let original = Arc::clone(services.authorization.as_ref().unwrap());
        let mut api = services.gatherings().await.unwrap();
        if authorization_failure {
            api.minecraft.authorization = None;
            api.minecraft.environment = None;
            api.minecraft.config.game_version = "1.26.60".into();
        }
        let error = api.join_experience(EXPERIENCE).await.err().unwrap();
        assert!(matches!(
            error,
            Error::Status {
                status: StatusCode::NOT_FOUND,
                xerr: Some(1234)
            }
        ));
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
        server.await.unwrap();
        if authorization_failure {
            assert!(services.authorization.is_none());
        } else {
            assert!(Arc::ptr_eq(
                &original,
                services.authorization.as_ref().unwrap()
            ));
        }
    }
}

/// Completed count failures retain the cache and throttle; fresh wrappers use the same owner.
#[tokio::test]
async fn population_failure_keeps_original_cache_and_attempt_interval() {
    let mut step = 0;
    let (address, server) = fixture_bytes(move |path, headers, _| {
        step += 1;
        if step == 1 { return (200, vec![], discovery(headers,None)); }
        assert_eq!(path,"/gatherings-prefix/api/v2.0/dataquery/playercounts");
        if step == 3 { return (503,vec![],b"SENSITIVE".to_vec()); }
        (200,vec![],json!({"result":[{"experienceId":EXPERIENCE,"playerCount":if step==2 {3} else {4}}]}).to_string().into_bytes())
    },4).await;
    let mut services = services(address);
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        assert_eq!(
            services
                .gatherings()
                .await
                .unwrap()
                .player_counts()
                .await
                .unwrap()[0]
                .player_count,
            Some(3)
        );
        services.gatherings_state.requested = Some(Instant::now() - PLAYER_COUNTS_REFRESH_INTERVAL);
        {
            let mut api = services.gatherings().await.unwrap();
            assert!(api.player_counts().await.is_err());
            assert_eq!(api.cached_player_counts()[0].player_count, Some(3));
        }
        assert_eq!(
            services
                .gatherings()
                .await
                .unwrap()
                .player_counts()
                .await
                .unwrap()[0]
                .player_count,
            Some(3)
        );
        services.gatherings_state.requested = Some(Instant::now() - PLAYER_COUNTS_REFRESH_INTERVAL);
        assert_eq!(
            services
                .gatherings()
                .await
                .unwrap()
                .player_counts()
                .await
                .unwrap()[0]
                .player_count,
            Some(4)
        );
    })
    .await;
    if result.is_err() {
        server.abort();
    }
    let served = server.await;
    result.unwrap();
    served.unwrap();
}

/// Canceling an actual pending HTTP read cannot admit partial counts or throttle its successor.
#[tokio::test]
async fn canceled_population_http_request_preserves_cache_and_allows_immediate_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut services = services(address);
    services.environment = Some(super::super::Environment {
        service_uri: format!("http://{address}/auth"),
        play_fab_title_id: "AB12".into(),
        issuer: String::new(),
    });
    services.set_fixture_environments(
        json!({"gatherings":{"prod":{"serviceUri":format!("http://{address}")}}}),
    );
    services.gatherings_state.counts = vec![ExperiencePlayerCount {
        experience_id: EXPERIENCE,
        player_count: Some(5),
    }];
    let mut api = services.gatherings().await.unwrap();
    let mut pending = Box::pin(api.player_counts());
    let (mut stream, request) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            request=async {
                let (mut stream,_)=listener.accept().await.unwrap();
                let (bytes,_,_)=read_request(&mut stream).await;
                (stream,bytes)
            }=>request,
            _=&mut pending=>panic!("actual read must remain pending"),
        }
    })
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&request).starts_with("GET /api/v2.0/dataquery/playercounts "));
    drop(pending);
    assert!(api.minecraft.gatherings_state.requested.is_none());
    assert_eq!(api.cached_player_counts()[0].player_count, Some(5));
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let retry = api.player_counts();
    let peer = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        let body = json!({"result":[{"experienceId":EXPERIENCE,"playerCount":6}]}).to_string();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    };
    let (counts, ()) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(retry, peer) })
            .await
            .unwrap();
    assert_eq!(counts.unwrap()[0].player_count, Some(6));
}

/// Optional unsafe discovery fails before credentials and cannot poison the shared auth owner.
#[tokio::test]
async fn invalid_gatherings_discovery_leaves_minecraft_authorization_available() {
    for environment in [
        Value::Null,
        json!(false),
        json!({"prod":{"serviceUri":"http://unsafe.example"}}),
        json!({"prod":{"serviceUri":"https://user:SENSITIVE@unsafe.example"}}),
        json!({"prod":{"serviceUri":"https://unsafe.example/?SENSITIVE"}}),
    ] {
        let (address, server) = fixture_bytes(
            move |_, headers, _| {
                assert!(!headers.to_ascii_lowercase().contains("authorization:"));
                (200, vec![], discovery(headers, Some(environment.clone())))
            },
            1,
        )
        .await;
        let mut services = services(address);
        let original = Arc::clone(services.authorization.as_ref().unwrap());
        let error = services.gatherings().await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
        assert!(services.environment.is_some());
        assert!(Arc::ptr_eq(&original, &services.authorize().await.unwrap()));
        server.await.unwrap();
    }
}

/// Malformed typed envelopes/assignments cannot produce a catalog or endpoint.
#[tokio::test]
async fn gatherings_rejects_wrong_containers_null_results_and_invalid_join_fields() {
    let replies = [
        (false, br#"[]"#.as_slice()),
        (false, br#"{"data":[]}"#),
        (false, br#"{"data":null}"#),
        (false, br#"{"data":{"Items":[[]]}}"#),
        (false, br#"{"data":{"Items":[{"Images":[[]]}]}}"#),
        (false, br#"{"data":{"Items":[{"Images":[false]}]}}"#),
        (false, br#"{"data":{"Items":[{"Title":{"en-US":false}}]}}"#),
        (true, br#"{"result":[]}"#),
        (true, br#"{"result":null}"#),
        (
            true,
            br#"{"result":{"networkProtocol":"Default","port":19132}}"#,
        ),
        (
            true,
            br#"{"result":{"networkProtocol":"NETHERNET_JSONRPC","netherNetId":""}}"#,
        ),
        (
            true,
            br#"{"result":{"networkProtocol":"Default","ipV4Address":"host","port":65536}}"#,
        ),
        (
            true,
            br#"{"result":{"networkProtocol":"NETHERNET_JSONRPC","netherNetId":"1","destinationInfo":[]}}"#,
        ),
    ];
    for (join, body) in replies {
        let mut step = 0;
        let (address, server) = fixture_bytes(
            move |_, headers, _| {
                step += 1;
                if step == 1 {
                    (200, vec![], discovery(headers, None))
                } else {
                    (200, vec![], body.to_vec())
                }
            },
            2,
        )
        .await;
        let mut services = services(address);
        let mut api = services.gatherings().await.unwrap();
        let result = if join {
            api.join_experience(EXPERIENCE).await.map(|_| ())
        } else {
            api.search_items(&SearchFilter::default()).await.map(|_| ())
        };
        assert!(result.is_err());
        server.await.unwrap();
    }
}

/// Counts require a complete array envelope; malformed replies retain the original snapshot.
#[tokio::test]
async fn malformed_population_results_preserve_the_previous_snapshot() {
    for body in [
        br#"{}"#.as_slice(),
        br#"{"result":null}"#,
        br#"{"result":{}}"#,
        br#"{"result":[]} trailing"#,
    ] {
        let mut step = 0;
        let (address, server) = fixture_bytes(
            move |_, headers, _| {
                step += 1;
                if step == 1 {
                    (200, vec![], discovery(headers, None))
                } else {
                    (200, vec![], body.to_vec())
                }
            },
            2,
        )
        .await;
        let mut services = services(address);
        services.gatherings_state.counts = vec![ExperiencePlayerCount {
            experience_id: EXPERIENCE,
            player_count: Some(8),
        }];
        let mut api = services.gatherings().await.unwrap();
        assert!(api.player_counts().await.is_err());
        assert_eq!(api.cached_player_counts()[0].player_count, Some(8));
        assert_eq!(api.player_counts().await.unwrap()[0].player_count, Some(8));
        server.await.unwrap();
    }
}

/// The concrete service owner admits catalog metadata above acquisition's limit but not above its own.
#[tokio::test]
async fn gatherings_catalog_uses_the_bounded_service_response_budget() {
    let mut step = 0;
    let (address, server) = fixture_bytes(
        move |_, headers, _| {
            step += 1;
            if step == 1 {
                return (200, vec![], discovery(headers, None));
            }
            assert_eq!(step, 2);
            (
                200,
                vec![],
                json!({"data":{"Items":[{"Id":"large","DisplayProperties":{
            "unused":"x".repeat(crate::http::RESPONSE_LIMIT+1)}}]}})
                .to_string()
                .into_bytes(),
            )
        },
        2,
    )
    .await;
    let mut catalog_owner = services(address);
    let page = catalog_owner
        .gatherings()
        .await
        .unwrap()
        .search_items(&SearchFilter::default())
        .await
        .unwrap();
    assert!(
        page.items[0]
            .display_properties
            .as_ref()
            .unwrap()
            .get()
            .len()
            > crate::http::RESPONSE_LIMIT
    );
    server.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut services = services(address);
    services.environment = Some(super::super::Environment {
        service_uri: format!("http://{address}/auth"),
        play_fab_title_id: "AB12".into(),
        issuer: String::new(),
    });
    services.set_fixture_environments(
        json!({"gatherings":{"prod":{"serviceUri":format!("http://{address}")}}}),
    );
    let read = async {
        services
            .gatherings()
            .await
            .unwrap()
            .search_items(&SearchFilter::default())
            .await
    };
    let peer = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    crate::http::SERVICE_RESPONSE_LIMIT + 1
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    };
    let (result, ()) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(read, peer) })
            .await
            .unwrap();
    assert!(matches!(result, Err(Error::ResponseTooLarge)));
}
