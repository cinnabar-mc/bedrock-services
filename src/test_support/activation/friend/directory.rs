//! Exact decoded activity, conditional handle join, nonce snapshot and original member removal.

use super::*;
use crate::xbox::mpsd::test_support::header;
use service::Reply;

/// Supplies the fixed retail title namespace used by the actual activity and joined resource.
pub(super) fn reference() -> mpsd::Reference {
    mpsd::Reference::new(minecraft::SERVICE_CONFIG_ID, TEMPLATE.into(), NAME.into()).unwrap()
}

/// Produces a complete title document; only the same service's own admission changes its nonce map.
pub(super) fn properties(state: &State) -> Value {
    let friend = state.friend.as_ref().unwrap();
    let connection = match friend.dialect {
        HostedFriendDialect::Messaging => {
            json!({"ConnectionType":7,"NetherNetId":HOST_NETWORK,"PmsgId":HOST_MESSAGING})
        }
        HostedFriendDialect::Legacy => {
            json!({"ConnectionType":3,"RakNetGUID":HOST_NETWORK.to_string()})
        }
    };
    let mut properties = json!({"ownerId":HOST_XUID,"hostName":"Controlled host",
        "worldName":"Controlled friend world","MemberCount":1 + u32::from(friend.joins != 0),"MaxMemberCount":state.max_members.get(),
        "RealmId":0,"ExperienceId":Uuid::nil(),"ExperienceWorldId":Uuid::nil(),
        "FriendId":"","BroadcastSetting":3,"TransportLayer":2,
        "protocol":friend.protocol,"SupportedConnections":[connection],"nonces":{}});
    if friend.nonce_available {
        properties["nonces"][super::super::super::script::HOST_XUID] = json!(NONCE);
    }
    properties
}

/// Uses only the original directory's endpoint and the fixed selected reference.
fn location() -> String {
    let mut url = url::Url::parse(crate::xbox::mpsd::test_support::DIRECTORY_ENDPOINT).unwrap();
    let reference = reference();
    url.path_segments_mut().unwrap().extend([
        "serviceconfigs",
        &reference.service_config_id().to_string(),
        "sessionTemplates",
        TEMPLATE,
        "sessions",
        NAME,
    ]);
    url.path().to_owned()
}

/// Validates actual signed writes and retains the exact original binding from the joined member.
pub(super) fn respond(target: &str, headers: &str, body: &[u8], state: &mut State) -> Reply {
    super::super::script::verify_directory(target, headers, body, state);
    assert!(state.friend.as_ref().unwrap().listed_friends);
    if target == format!("/handles/{HANDLE}/session") {
        assert!(headers.starts_with("PUT "));
        assert_eq!(header(headers, "if-match"), "*");
        assert!(header(headers, "if-none-match").is_empty());
        assert_eq!(state.friend.as_ref().unwrap().joins, 0);
        let value: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 1);
        assert_eq!(value["members"].as_object().unwrap().len(), 1);
        let member = &value["members"]["me"];
        assert_eq!(
            member["constants"]["system"]["xuid"],
            super::super::super::script::HOST_XUID
        );
        let binding = &member["properties"]["system"];
        assert_eq!(binding["active"], true);
        assert_eq!(
            binding["connection"],
            json!(super::super::super::script::CONNECTION)
        );
        assert!(
            !Uuid::parse_str(binding["subscription"]["id"].as_str().unwrap())
                .unwrap()
                .is_nil()
        );
        state.friend.as_mut().unwrap().joins += 1;
        state.snapshot = json!({"sessionRef":reference(),"branch":BRANCH,"changeNumber":1,
            "constants":{"system":{"maxMembersCount":state.max_members.get()}},
            "properties":{"system":{"closed":false},"custom":properties(state)},
            "members":{"me":member,"1":{"constants":{"system":{"xuid":HOST_XUID}},
                "properties":{"system":{"active":true}}}}});
        let mut response = Reply::json(200, state.snapshot.clone());
        response.headers = vec![
            ("ETag".into(), "\"friend-joined\"".into()),
            ("Content-Location".into(), location()),
        ];
        return response;
    }
    assert_eq!(target, location());
    assert_eq!(state.friend.as_ref().unwrap().joins, 1);
    assert_eq!(state.friend.as_ref().unwrap().leaves, 0);
    let admitted = state.friend.as_ref().unwrap().nonce_available;
    if headers.starts_with("GET ") {
        assert!(body.is_empty());
        let previous = header(headers, "if-none-match");
        if !admitted || previous == "\"friend-admitted\"" {
            assert_eq!(
                previous,
                if admitted {
                    "\"friend-admitted\""
                } else {
                    "\"friend-joined\""
                }
            );
            return Reply::json(304, Value::Null);
        }
        assert_eq!(previous, "\"friend-joined\"");
        state.snapshot["properties"]["custom"] = properties(state);
        state.snapshot["changeNumber"] = json!(2);
        let mut response = Reply::json(200, state.snapshot.clone());
        response
            .headers
            .push(("ETag".into(), "\"friend-admitted\"".into()));
        return response;
    }
    assert!(headers.starts_with("PUT "));
    assert_eq!(
        header(headers, "if-match"),
        if admitted {
            "\"friend-admitted\""
        } else {
            "\"friend-joined\""
        }
    );
    assert_eq!(
        serde_json::from_slice::<Value>(body).unwrap(),
        json!({"members":{"me":null}})
    );
    state.friend.as_mut().unwrap().leaves += 1;
    Reply::json(204, Value::Null)
}
