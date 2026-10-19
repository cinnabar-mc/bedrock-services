//! Fixed signed acquisition/create/activity/invite exchanges for the public activation owner.

use super::*;
use crate::xbox::{
    XBOX_RELYING_PARTY,
    mpsd::test_support::{DIRECTORY_CONTRACT, SIGNED_HEADERS, header, verify},
    test_support::{read_request, token, write_response},
};
use aws_lc_rs::{rand::SystemRandom, signature::RSA_PKCS1_SHA256};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p384::pkcs8::DecodePublicKey;

/// Emits the same actual service credential metadata consumed by the protected Messaging upgrade.
pub(super) fn service_header() -> String {
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"pmid":MESSAGING_ID})).unwrap());
    format!("MCToken fixture.{claims}.synthetic")
}

/// Serves exactly the retained original HTTP task through verified fixture TLS.
pub(super) async fn serve(listener: TcpListener, state: Shared, version: String) {
    for step in 1..=EXCHANGES {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = rta::websocket::test_support::acceptor()
            .accept(tcp)
            .await
            .unwrap();
        let (bytes, end, length) = read_request(&mut stream).await;
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        let target = headers.split_whitespace().nth(1).unwrap();
        let (status, extra, response) = {
            let mut state = state.lock().unwrap();
            let response = respond(
                step,
                target,
                headers,
                &bytes[end..end + length],
                &mut state,
                &version,
            );
            state.verified_http_requests = step;
            response
        };
        let body = if status == 304 {
            Vec::new()
        } else {
            serde_json::to_vec(&response).unwrap()
        };
        let mut extra = extra;
        extra.push(("Date", super::super::script::DATE));
        write_response(&mut stream, status, extra, &body).await;
    }
}

/// Checks the actual method/body/issuance in each fixed phase before producing its ordinary response.
fn respond(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    state: &mut State,
    version: &str,
) -> (u16, Vec<(&'static str, &'static str)>, Value) {
    let result = match step {
        1 => {
            assert_eq!(target, "/device-token");
            let value: Value = serde_json::from_slice(body).unwrap();
            let proof = value["Properties"]["ProofKey"].clone();
            verify(target, headers, body, &proof, &[]);
            state.proof = Some(proof);
            token("device", false)
        }
        2 => {
            assert_eq!(target, "/nsal");
            assert!(headers.starts_with("GET "));
            assert!(header(headers, "authorization").is_empty());
            json!({"EndPoints":[{"Protocol":"http", "Host":"127.0.0.1", "HostType":"fqdn", "RelyingParty":XBOX_RELYING_PARTY, "SignaturePolicyIndex":0}], "SignaturePolicies":[{"Version":1}]})
        }
        3 => {
            assert_eq!(target, "/sisu");
            verify(target, headers, body, state.proof.as_ref().unwrap(), &[]);
            let value: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(value["ProofKey"], *state.proof.as_ref().unwrap());
            assert_eq!(value["AccessToken"], "t=synthetic-access");
            json!({"TitleToken":token("title", false), "UserToken":token("user",false), "AuthorizationToken":token("xbox",true)})
        }
        4 => {
            assert_eq!(
                target,
                format!("/api/v1.0/discovery/MinecraftPE/builds/{version}")
            );
            assert!(headers.starts_with("GET ") && body.is_empty());
            assert!(header(headers, "authorization").is_empty());
            json!({"result":{"serviceEnvironments":{
                "auth":{"prod":{"serviceUri":AUTH_ORIGIN,"playFabTitleId":TITLE,"issuer":super::super::HOSTED_WORLD_ISSUER}},
                "signaling-afd":{"prod":{"serviceUri":SIGNALING_ORIGIN}},
            }}})
        }
        5 => {
            assert_eq!(target, "/nsal-current");
            assert_eq!(header(headers, "authorization"), "XBL3.0 x=synthetic;xbox");
            verify(target, headers, body, state.proof.as_ref().unwrap(), &[]);
            let playfab = crate::playfab::login_url(TITLE).unwrap();
            let directory =
                url::Url::parse(crate::xbox::mpsd::test_support::DIRECTORY_ENDPOINT).unwrap();
            let rta = rta::websocket::test_support::endpoint();
            json!({"EndPoints":[
                {"Protocol":"https","Host":playfab.host_str().unwrap(),"HostType":"fqdn","Path":playfab.path(),"RelyingParty":"rp://hosted-playfab","SignaturePolicyIndex":0},
                {"Protocol":"https","Host":rta.host_str().unwrap(),"HostType":"fqdn","RelyingParty":"rp://rta","SignaturePolicyIndex":1},
                {"Protocol":"https","Host":directory.host_str().unwrap(),"HostType":"fqdn","RelyingParty":"rp://mpsd","SignaturePolicyIndex":2}],
                "SignaturePolicies":[{"Version":1},{"Version":1,"ExtraHeaders":state.headers},{"Version":1,"ExtraHeaders":SIGNED_HEADERS}]})
        }
        6 | 11 | 12 => {
            assert_eq!(target, "/xsts");
            verify(target, headers, body, state.proof.as_ref().unwrap(), &[]);
            let party = match step {
                6 => "rp://hosted-playfab",
                11 => "rp://rta",
                _ => "rp://mpsd",
            };
            let value: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(value["RelyingParty"], party);
            token(
                match step {
                    6 => "playfab",
                    11 => "rta",
                    _ => "directory",
                },
                true,
            )
        }
        7 => {
            assert_eq!(target, "/Client/LoginWithXbox");
            assert!(headers.starts_with("POST "));
            assert!(header(headers, "authorization").is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!({"TitleId":TITLE,"CreateAccount":true,"XboxToken":"XBL3.0 x=synthetic;playfab"})
            );
            json!({"data":{"SessionTicket":"hosted-ticket","PlayFabId":"hosted-player", "EntityToken":{"EntityToken":"hosted-entity", "TokenExpiration":"2099-01-01T00:00:00Z", "Entity":{"Id":"hosted-title-player", "Type":"title_player_account"}}}})
        }
        8 => {
            assert_eq!(target, "/api/v1.0/session/start");
            let session = Uuid::parse_str(header(headers, "session-id")).unwrap();
            assert!(!session.is_nil());
            state.session_id = Some(session);
            let value: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(value["user"]["token"], "hosted-ticket");
            assert_eq!(value["user"]["tokenType"], "PlayFab");
            json!({"result":{"authorizationHeader":service_header(), "validUntil":"2099-01-01T00:00:00Z"}})
        }
        9 => {
            assert_eq!(target, "/api/v1.0/multiplayer/session/start");
            service_request(headers, state);
            let value: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 1);
            let public = value["publicKey"].as_str().unwrap();
            let der = STANDARD.decode(public).unwrap();
            p384::ecdsa::VerifyingKey::from_public_key_der(&der).unwrap();
            state.minted_public_key = der;
            let issued = httpdate::parse_http_date(super::super::script::DATE).unwrap();
            let issued = time::OffsetDateTime::from(issued);
            let expires = issued + time::Duration::seconds(300);
            let claims = json!({"iss":super::super::HOSTED_WORLD_ISSUER,"aud":state.audience,"sub":"hosted-fixture-host","xid":super::super::script::HOST_XUID,"xname":"Host","iat":issued.unix_timestamp(),"exp":expires.unix_timestamp(),"cpk":public});
            let header = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({"alg":"RS256","kid":HOSTED_ACTIVATION_KEY_ID})).unwrap(),
            );
            let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let input = format!("{header}.{claims}");
            let mut signature = vec![0; state.issuer.public_modulus_len()];
            state
                .issuer
                .sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    input.as_bytes(),
                    &mut signature,
                )
                .unwrap();
            let expires = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                expires.year(),
                u8::from(expires.month()),
                expires.day(),
                expires.hour(),
                expires.minute(),
                expires.second()
            );
            json!({"result":{"signedToken":format!("{input}.{}",URL_SAFE_NO_PAD.encode(signature)), "validUntil":expires}})
        }
        10 => {
            assert_eq!(target, "/api/v1.0/configuration");
            assert!(headers.starts_with("GET ") && body.is_empty());
            assert_eq!(header(headers, "authorization"), service_header());
            assert!(header(headers, "session-id").is_empty());
            json!({"result":{"signalingUri":SIGNALING_ORIGIN.replace("https://","wss://"),"pingFrequency":"00:01:00"}})
        }
        13..=19 => return directory(step, target, headers, body, state),
        _ => panic!("unexpected public-activation HTTP exchange"),
    };
    (200, Vec::new(), result)
}

/// Matches actual credential and Session-Id across the original owner's service requests.
fn service_request(headers: &str, state: &State) {
    assert_eq!(header(headers, "authorization"), service_header());
    assert_eq!(
        Uuid::parse_str(header(headers, "session-id")).unwrap(),
        state.session_id.unwrap()
    );
}

/// Verifies original creation metadata and reuses its actual document/binding for activity and retirement.
fn directory(
    step: usize,
    target: &str,
    headers: &str,
    body: &[u8],
    state: &mut State,
) -> (u16, Vec<(&'static str, &'static str)>, Value) {
    verify(
        target,
        headers,
        body,
        state.proof.as_ref().unwrap(),
        SIGNED_HEADERS,
    );
    assert_eq!(
        header(headers, "authorization"),
        "XBL3.0 x=synthetic;directory"
    );
    assert_eq!(
        header(headers, "x-xbl-contract-version"),
        DIRECTORY_CONTRACT
    );
    if step == 13 {
        let url = url::Url::parse(&format!("https://fixture.invalid{target}")).unwrap();
        let parts = url
            .path_segments()
            .unwrap()
            .map(|part| {
                percent_encoding::percent_decode_str(part)
                    .decode_utf8()
                    .unwrap()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(parts.len(), 6);
        assert_eq!(
            (&*parts[0], &*parts[2], &*parts[4]),
            ("serviceconfigs", "sessionTemplates", "sessions")
        );
        state.reference = Some(
            mpsd::Reference::new(
                Uuid::parse_str(&parts[1]).unwrap(),
                parts[3].clone(),
                parts[5].clone(),
            )
            .unwrap(),
        );
    }
    let reference = state.reference.as_ref().unwrap();
    if step == 16 || step == 17 {
        assert_eq!(target, "/handles");
        assert!(headers.starts_with("POST "));
        let value: Value = serde_json::from_slice(body).unwrap();
        if step == 16 {
            assert_eq!(
                value,
                json!({"type":"activity","version":1,"sessionRef":reference})
            );
            return (201, Vec::new(), Value::Null);
        }
        assert_eq!(
            value,
            json!({"type":"invite","version":1,"sessionRef":reference,"invitedXuid":"456","inviteAttributes":{"titleId":state.title_id}})
        );
        state.invited_xuid = "456".into();
        return (
            201,
            Vec::new(),
            json!({"id":Uuid::from_u128(0x7110),"senderXuid":super::super::script::HOST_XUID,"invitedXuid":state.invited_xuid,"sessionRef":reference}),
        );
    }
    let mut expected =
        url::Url::parse(crate::xbox::mpsd::test_support::DIRECTORY_ENDPOINT).unwrap();
    expected.path_segments_mut().unwrap().extend([
        "serviceconfigs",
        &reference.service_config_id().to_string(),
        "sessionTemplates",
        reference.template_name(),
        "sessions",
        reference.name(),
    ]);
    assert_eq!(target, expected.path());
    match step {
        13 => {
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-none-match"), "*");
            assert!(header(headers, "if-match").is_empty());
            let actual: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                actual["constants"]["system"]["maxMembersCount"],
                state.max_members.get()
            );
            assert_eq!(
                actual["properties"]["system"],
                json!({"joinRestriction":"followed","readRestriction":"followed","closed":false})
            );
            let custom = &actual["properties"]["custom"];
            assert_eq!(custom["MaxMemberCount"], state.max_members.get());
            assert_eq!(custom["SupportedConnections"].as_array().unwrap().len(), 1);
            assert!(
                custom["SupportedConnections"][0]["NetherNetId"]
                    .as_u64()
                    .is_some_and(|id| id != 0)
            );
            assert_eq!(
                custom["SupportedConnections"][0]["PmsgId"],
                json!(MESSAGING_ID)
            );
            assert_eq!(
                actual["members"]["me"]["constants"]["system"]["xuid"],
                super::super::script::HOST_XUID
            );
            assert_eq!(
                actual["members"]["me"]["properties"]["system"]["connection"],
                json!(super::super::script::CONNECTION)
            );
            state.created_properties = custom.clone();
            state.created_capacity = actual["constants"]["system"]["maxMembersCount"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok());
            state.snapshot = actual;
            state.snapshot["sessionRef"] = json!(reference);
            state.snapshot["branch"] = json!(Uuid::from_u128(0x7102));
            state.snapshot["changeNumber"] = json!(1);
            state.snapshot["members"]["1"] = json!({"constants":{"system":{"xuid":"456"}},"properties":{"system":{"active":true}}});
            (
                201,
                vec![("ETag", "\"host-created\"")],
                state.snapshot.clone(),
            )
        }
        14 | 18 => {
            assert!(headers.starts_with("GET ") && body.is_empty());
            assert_eq!(
                header(headers, "if-none-match"),
                if step == 14 {
                    "\"host-created\""
                } else {
                    "\"host-acknowledged\""
                }
            );
            (304, Vec::new(), Value::Null)
        }
        15 => {
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-match"), "\"host-created\"");
            let actual: Value = serde_json::from_slice(body).unwrap();
            let custom = &actual["properties"]["custom"];
            let mut without = custom.clone();
            without["nonces"] = state.created_properties["nonces"].clone();
            assert_eq!(without, state.created_properties);
            assert!(
                custom["nonces"]["456"]
                    .as_str()
                    .is_some_and(|nonce| !nonce.is_empty())
            );
            state.snapshot["properties"]["custom"] = custom.clone();
            state.snapshot["changeNumber"] = json!(2);
            (
                200,
                vec![("ETag", "\"host-acknowledged\"")],
                state.snapshot.clone(),
            )
        }
        19 => {
            assert!(headers.starts_with("PUT "));
            assert_eq!(header(headers, "if-match"), "\"host-acknowledged\"");
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                json!({"members":{"me":null}})
            );
            (204, Vec::new(), Value::Null)
        }
        _ => panic!("unexpected activation directory exchange"),
    }
}
