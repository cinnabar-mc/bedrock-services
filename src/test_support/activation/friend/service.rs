//! Fixed catalogue/account requests on the original verified HTTP fixture owner.

use super::*;
use crate::xbox::{
    mpsd::test_support::{header, verify},
    test_support::{read_request, token, write_response},
};

pub(in super::super) struct Reply {
    pub(in super::super) status: u16,
    pub(in super::super) headers: Vec<(String, String)>,
    pub(in super::super) body: Value,
}

impl Reply {
    /// Owns only this finite response's framing fields until the original write completes.
    pub(in super::super) fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }
}

/// Reuses the bounded request decoder/TLS acceptor; only original member removal ends the script.
pub(in super::super) async fn serve(listener: TcpListener, state: Shared, version: String) {
    loop {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = rta::websocket::test_support::acceptor()
            .accept(tcp)
            .await
            .unwrap();
        let (bytes, end, length) = read_request(&mut stream).await;
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        let target = headers.split_whitespace().nth(1).unwrap();
        let reply = {
            let mut state = state.lock().unwrap();
            assert!(
                state.verified_http_requests < 32,
                "finite friend request prefix exceeded"
            );
            let reply = respond(
                target,
                headers,
                &bytes[end..end + length],
                &mut state,
                &version,
            );
            state.verified_http_requests += 1;
            reply
        };
        let body = if matches!(reply.status, 204 | 304) {
            Vec::new()
        } else {
            serde_json::to_vec(&reply.body).unwrap()
        };
        let mut response_headers: Vec<_> = reply
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        response_headers.push(("Date", super::super::super::script::DATE));
        write_response(&mut stream, reply.status, response_headers, &body).await;
        let finished = {
            let mut state = state.lock().unwrap();
            super::super::reconnect::flushed(target, headers, &reply, &mut state);
            let friend = state.friend.as_mut().unwrap();
            if target == format!("/handles/{HANDLE}/session") {
                let _ = friend.joined.take().unwrap().send(());
            }
            if headers.starts_with("GET ")
                && reply.status == 200
                && friend.nonce_available
                && reply.body["properties"]["custom"]["nonces"]
                    [super::super::super::script::HOST_XUID]
                    .as_str()
                    == Some(NONCE)
            {
                friend.nonce_published = true;
            }
            friend.leaves == 1
        };
        if finished {
            return;
        }
    }
}

/// Reuses original signing/token/mint responses while enforcing the friend-specific concrete reads.
fn respond(target: &str, headers: &str, body: &[u8], state: &mut State, version: &str) -> Reply {
    if state.verified_http_requests < 3 {
        return original(
            state.verified_http_requests + 1,
            target,
            headers,
            body,
            state,
            version,
        );
    }
    match target {
        path if path == format!("/api/v1.0/discovery/MinecraftPE/builds/{version}") => {
            let mut reply = original(4, target, headers, body, state, version);
            let environments = &mut reply.body["result"]["serviceEnvironments"];
            environments["realms_frontend_bedrock_legacy"] =
                json!({"prod":{"serviceUri":AUTH_ORIGIN}});
            environments["signaling"] =
                json!({"prod":{"serviceUri":SIGNALING_ORIGIN.replace("https://", "wss://")}});
            reply
        }
        "/nsal-current" => original(5, target, headers, body, state, version),
        "/xsts" => {
            let request: Value = serde_json::from_slice(body).unwrap();
            match request["RelyingParty"].as_str().unwrap() {
                "https://pocket.realms.minecraft.net/" => {
                    verify(target, headers, body, state.proof.as_ref().unwrap(), &[]);
                    let friend = state.friend.as_mut().unwrap();
                    assert!(!friend.realms_token && !friend.listed_realms);
                    friend.realms_token = true;
                    Reply::json(200, token("friend-realms", true))
                }
                "rp://hosted-playfab" => original(6, target, headers, body, state, version),
                "rp://rta" => original(11, target, headers, body, state, version),
                "rp://mpsd" => original(12, target, headers, body, state, version),
                _ => panic!("unexpected friend relying party"),
            }
        }
        "/worlds" => {
            let friend = state.friend.as_mut().unwrap();
            assert!(friend.realms_token && !friend.listed_realms && !friend.listed_friends);
            assert!(headers.starts_with("GET ") && body.is_empty());
            assert_eq!(
                header(headers, "authorization"),
                "XBL3.0 x=synthetic;friend-realms"
            );
            assert_eq!(header(headers, "client-version"), version);
            assert_eq!(
                header(headers, "x-networkprotocolversion"),
                friend.protocol.to_string()
            );
            friend.listed_realms = true;
            Reply::json(200, json!({"servers":[]}))
        }
        "/handles/query?include=relatedInfo,customProperties" => {
            let friend = state.friend.as_ref().unwrap();
            assert!(friend.listed_realms && !friend.listed_friends);
            assert!(headers.starts_with("POST "));
            super::super::script::verify_directory(target, headers, body, state);
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!({
                    "type":"activity","scid":minecraft::SERVICE_CONFIG_ID,
                    "owners":{"people":{"moniker":"people","monikerXuid":super::super::super::script::HOST_XUID}}
                })
            );
            let reference = directory::reference();
            let activity = json!({"id":HANDLE,"type":"activity","ownerXuid":HOST_XUID,
                "sessionRef":reference,"relatedInfo":{"closed":false},
                "customProperties":directory::properties(state)});
            state.reference = Some(reference);
            state.friend.as_mut().unwrap().listed_friends = true;
            Reply::json(200, json!({"results":[activity]}))
        }
        "/Client/LoginWithXbox" => original(7, target, headers, body, state, version),
        "/api/v1.0/session/start" => original(8, target, headers, body, state, version),
        "/api/v1.0/multiplayer/session/start" => {
            assert!(state.friend.as_ref().unwrap().nonce_published);
            assert!(
                state.minted_public_key.is_empty(),
                "friend mint must occur once"
            );
            original(9, target, headers, body, state, version)
        }
        "/api/v1.0/configuration" => {
            assert_eq!(
                state.friend.as_ref().unwrap().dialect,
                HostedFriendDialect::Messaging
            );
            original(10, target, headers, body, state, version)
        }
        _ => directory::respond(target, headers, body, state),
    }
}

/// Keeps all common acquisition/signature/mint behavior in its existing finite scenario owner.
fn original(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    state: &mut State,
    version: &str,
) -> Reply {
    let (status, headers, body) =
        super::super::script::respond(step, target, headers, body, state, version);
    Reply {
        status,
        headers: headers
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect(),
        body,
    }
}
