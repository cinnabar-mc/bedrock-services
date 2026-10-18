use super::*;
use crate::{
    oauth::Credentials,
    realms::{Error as RealmsError, Join, NetworkProtocol, PingResult},
    xbox::tests::token,
};
use serde_json::{Value, json};
use std::{
    num::NonZeroU64,
    time::{Duration, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Reply {
    status: u16,
    body: String,
    retry_after: Option<&'static str>,
}

impl Reply {
    /// Encodes original fixture metadata without using a service response or real credential.
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            body: value.to_string(),
            retry_after: None,
        }
    }

    /// Supplies the plain-text compatibility/count body used by the Realms endpoint.
    fn text(body: &str) -> Self {
        Self {
            status: 200,
            body: body.to_owned(),
            retry_after: None,
        }
    }
}

/// Runs a finite real-HTTP script and closes every connection, without wall-clock sleeps.
async fn fixture(
    mut reply: impl FnMut(usize, &str, &str, &[u8], std::net::SocketAddr) -> Reply + Send + 'static,
    count: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for step in 1..=count {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut buffer = [0_u8; 2048];
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n != 0, "fixture request closed before headers");
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let headers = headers.to_ascii_lowercase();
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| value.parse::<usize>().unwrap());
            while bytes.len() < header_end + length {
                let mut buffer = [0_u8; 2048];
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n != 0, "fixture request closed before body");
                bytes.extend_from_slice(&buffer[..n]);
            }
            let target = headers
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let response = reply(
                step,
                target,
                &headers,
                &bytes[header_end..header_end + length],
                address,
            );
            let retry = response
                .retry_after
                .map_or_else(String::new, |value| format!("Retry-After: {value}\r\n"));
            let headers = format!(
                "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\nDate: Tue, 01 Jan 2030 00:00:00 GMT\r\n{retry}\r\n",
                response.status,
                response.body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            socket.write_all(response.body.as_bytes()).await.unwrap();
        }
    });
    (address, server)
}

/// Builds one test-only account with fixture HTTP; no real endpoints or secrets are used.
fn services(address: std::net::SocketAddr, version: &str, protocol: u32) -> Minecraft {
    let config = xbox::Config::default();
    let credentials = Credentials::from_tokens(
        config.client_id.clone(),
        "access".into(),
        "refresh".into(),
        UNIX_EPOCH + Duration::from_secs(4_102_444_800),
    )
    .unwrap();
    let xbox = xbox::Account::new(Http::fixture(address), config, credentials).unwrap();
    let mut minecraft = Minecraft::new(
        xbox,
        Config::desktop(version, protocol, uuid::Uuid::new_v4()),
    )
    .unwrap();
    minecraft.http = Http::fixture_agent(address, USER_AGENT);
    minecraft
}

/// Exercises shared XSTS, persistent version negotiation, explicit membership and all join variants.
#[tokio::test]
async fn realms_requests_reuse_account_policy_and_preserve_join_outcomes() {
    let version = "1.26.60.2";
    let protocol = 1014;
    let (address, server) = fixture(move |step, target, headers, body, address| {
        if step >= 6 && step != 24 {
            assert!(headers.contains("user-agent: libhttpclient/1.0.0.0"));
            assert!(headers.contains("x-clientplatform: android"));
            assert!(headers.contains(&format!("x-networkprotocolversion: {protocol}")));
            assert!(headers.contains(if step < 25 { "authorization: xbl3.0 x=synthetic;realms" } else { "authorization: xbl3.0 x=synthetic;realms2" }));
            let expected = match step { 6 => version, 7 | 27 => "1.26.60", _ => "1.26.59" };
            assert!(headers.contains(&format!("client-version: {expected}\r\n")));
        }
        match step {
            1 => {
                assert_eq!(target, format!("/api/v1.0/discovery/minecraftpe/builds/{version}"));
                Reply::json(200, json!({"result":{"serviceEnvironments":{
                    "auth":{"prod":{"serviceUri":format!("http://{address}/auth"),"playFabTitleId":"AB12"}},
                    "realms_frontend_bedrock_legacy":{"prod":{"serviceUri":format!("http://{address}/prefix/")}}
                }}}))
            }
            2 => { assert_eq!(target,"/device-token"); Reply::json(200,token("device",false)) }
            3 => { assert_eq!(target,"/nsal"); Reply::json(200,json!({"EndPoints":[{"Protocol":"http","Host":"127.0.0.1","HostType":"fqdn","RelyingParty":"http://xboxlive.com"}]})) }
            4 => { assert_eq!(target,"/sisu"); Reply::json(200,json!({"TitleToken":token("title",false),"UserToken":token("user",true),"AuthorizationToken":token("xbox",true)})) }
            5 | 24 => {
                assert_eq!(target,"/xsts");
                assert_eq!(serde_json::from_slice::<Value>(body).unwrap()["RelyingParty"],"https://pocket.realms.minecraft.net/");
                Reply::json(200,token(if step == 5 {"realms"} else {"realms2"},true))
            }
            6 | 26 | 28 => { assert_eq!(target,"/prefix/worlds"); Reply::json(400,json!({"reason":"unknown_client_version","secret":"SECRET"})) }
            7 | 8 => {
                assert_eq!(target,"/prefix/mco/client/compatible");
                Reply::text(if step == 7 {"OUTDATED"} else {" compatible \n"})
            }
            9 | 25 => { assert_eq!(target,"/prefix/worlds"); Reply::json(200,json!({"servers":[{"id":7,"name":"Fixture","players":null}]})) }
            10 => { assert_eq!(target,"/prefix/worlds/7"); Reply::json(200,json!({"id":7,"players":[{"Name":"Fixture","online":true}]})) }
            11 => { assert_eq!(target,"/prefix/worlds/v1/link/fixture-code"); assert!(headers.starts_with("get ")); Reply::json(200,json!({"id":7})) }
            12 => { assert_eq!(target,"/prefix/invites/v1/link/accept/fixture-code"); assert!(headers.starts_with("post ")); assert!(!headers.contains("content-type:")); Reply::json(200,json!({"id":7})) }
            13 => { assert_eq!(target,"/prefix/invites/count/pending"); Reply::text(" 4\n") }
            14..=22 => {
                assert_eq!(target,"/prefix/worlds/7/join");
                assert!(headers.starts_with("post "));
                let payload: Value = serde_json::from_slice(body).unwrap();
                let regions = if step == 17 { json!([{"latencyMs":17,"region":"fixture"}]) } else { json!([]) };
                assert_eq!(payload,json!({"joinIntention":"VANILLA","pingRegions":regions}));
                match step {
                    14 => Reply { status:277, body:"SECRET".into(), retry_after:Some("0") },
                    15 => Reply { status:503, body:"SECRET".into(), retry_after:Some("malformed") },
                    16 => Reply::json(503,json!({"diagnostic":"SECRET"})),
                    17 => Reply::json(200,json!({"address":"[2001:db8::1]:19132","pendingUpdate":true,"sessionRegionData":{"regionName":"fixture","serviceQuality":7}})),
                    18 => Reply::json(200,json!({"address":"42","networkProtocol":" nethernet "})),
                    19 => Reply::json(200,json!({"address":"43","networkProtocol":"NETHERNET_JSONRPC"})),
                    20 => Reply::json(200,json!({"address":"44","networkProtocol":"FUTURE"})),
                    21 => Reply::json(403,json!({"diagnostic":"SECRET"})),
                    22 => Reply::json(404,json!({"diagnostic":"SECRET"})),
                    _ => unreachable!(),
                }
            }
            23 => { assert_eq!(target,"/prefix/worlds"); Reply::json(401,json!({"secret":"SECRET"})) }
            27 => { assert_eq!(target,"/prefix/mco/client/compatible"); Reply::json(503,json!({"secret":"SECRET"})) }
            _ => panic!("unexpected Realms request {step}: {target}"),
        }
    },28).await;
    let mut minecraft = services(address, version, protocol);
    let id = NonZeroU64::new(7).unwrap();
    assert_eq!(
        minecraft.realms().await.unwrap().list().await.unwrap()[0].id,
        id
    );
    let mut realms = minecraft.realms().await.unwrap();
    assert!(realms.details(id).await.unwrap().players[0].online);
    assert_eq!(realms.preview_invite("fixture-code").await.unwrap().id, id);
    assert_eq!(realms.accept_invite("fixture-code").await.unwrap().id, id);
    assert_eq!(realms.pending_invites().await.unwrap(), 4);
    for expected in [Duration::ZERO, Duration::from_secs(5)] {
        assert!(
            matches!(realms.join(id,&[]).await.unwrap(), Join::Pending {retry_after} if retry_after == expected)
        );
    }
    let failure = realms.join(id, &[]).await.err().unwrap();
    assert!(!format!("{failure} {failure:?}").contains("SECRET"));
    let Join::Ready(address) = realms
        .join(
            id,
            &[PingResult {
                latency_ms: 17,
                region: "fixture".into(),
            }],
        )
        .await
        .unwrap()
    else {
        panic!("expected ready Realm")
    };
    assert_eq!(address.address, "[2001:db8::1]:19132");
    assert_eq!(address.network_protocol, NetworkProtocol::Default);
    assert!(address.pending_update);
    assert_eq!(address.session_region.unwrap().region_name, "fixture");
    for expected in [
        NetworkProtocol::NetherNet,
        NetworkProtocol::NetherNetJsonRpc,
        NetworkProtocol::Unknown("FUTURE".into()),
    ] {
        let Join::Ready(address) = realms.join(id, &[]).await.unwrap() else {
            panic!("expected ready Realm")
        };
        assert_eq!(address.network_protocol, expected);
    }
    assert!(matches!(
        realms.join(id, &[]).await,
        Err(RealmsError::NotMember)
    ));
    assert!(matches!(
        realms.join(id, &[]).await,
        Err(RealmsError::NotFound)
    ));
    assert!(realms.list().await.is_err());
    assert_eq!(realms.list().await.unwrap()[0].id, id);
    for _ in 0..2 {
        assert!(realms.list().await.is_err());
    }
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

/// Malformed optional Realms discovery cannot redirect credentials or break auth discovery.
#[tokio::test]
async fn invalid_realms_discovery_fails_before_xbox_acquisition() {
    let environments = [
        Value::Null,
        json!(true),
        json!({"staging":{"serviceUri":"https://example.invalid"}}),
        json!({"prod":{"serviceUri":"http://example.invalid"}}),
        json!({"prod":{"serviceUri":"https://user:SECRET@example.invalid"}}),
        json!({"prod":{"serviceUri":"https://example.invalid?credential=SECRET"}}),
        json!({"prod":{"serviceUri":"https://example.invalid#SECRET"}}),
    ];
    for environment in environments {
        let (address,server) = fixture(move |_,_,_,_,address| Reply::json(200,json!({"result":{"serviceEnvironments":{
            "auth":{"prod":{"serviceUri":format!("http://{address}/auth"),"playFabTitleId":"AB12"}},
            "realms_frontend_bedrock_legacy":environment,
        }}})),1).await;
        let mut minecraft = services(address, "1.26.60", 1014);
        minecraft.discover().await.unwrap();
        let failure = minecraft.realms().await.err().unwrap();
        assert!(!format!("{failure} {failure:?}").contains("SECRET"));
        assert!(minecraft.environment.is_some());
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
