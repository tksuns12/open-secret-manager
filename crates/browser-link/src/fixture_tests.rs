//! The frozen messages of a browser fill. `fixtures/messages.json` holds
//! each message as this code wrote it when the format was frozen; the
//! extension's own tests read the same file, so that the two
//! implementations stay on one format. The file is never made again: to
//! add one for a new version, run with `OSM_WRITE_NEW_FIXTURES=1` while it
//! does not exist.

use serde_json::{json, Value};

use crate::{
    frame::{encode, Prefix},
    Caller, Cancel, Failure, FillReply, FillRequest, Forwarded, Refusal, Request, Response,
    Waiting, CHROMIUM_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME, VERSION,
};

const REFUSALS: [Refusal; 12] = [
    Refusal::InvalidMessage,
    Refusal::UnsupportedMessage,
    Refusal::UnsupportedVersion,
    Refusal::ExtensionNotAllowed,
    Refusal::OriginRejected,
    Refusal::FrameRejected,
    Refusal::DesktopSessionUnavailable,
    Refusal::Busy,
    Refusal::Replayed,
    Refusal::Denied,
    Refusal::Cancelled,
    Refusal::Expired,
];

fn text(message: &impl serde::Serialize) -> String {
    String::from_utf8(encode(message).unwrap().to_vec()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn request() -> FillRequest {
    FillRequest {
        version: VERSION,
        request_id: "7f6c0a1e-0b9c-4f5d-9a57-2f1f8f3f9d11".into(),
        tab_id: 12,
        frame_id: 0,
        document_id: "0d3b6a52-6b1c-4c0e-8a6e-0a7d6c1b2e3f".into(),
        origin: "https://example.com".into(),
    }
}

fn reply() -> FillReply {
    let request = request();
    FillReply {
        request_id: request.request_id,
        tab_id: request.tab_id,
        frame_id: request.frame_id,
        document_id: request.document_id,
        origin: request.origin,
        username: "owner@example.test".into(),
        password: "p@ss \"quoted\" \\ and 🔑".into(),
    }
}

fn messages() -> Value {
    let request = request();
    let cancel = Cancel {
        version: VERSION,
        request_id: request.request_id.clone(),
    };
    let errors: serde_json::Map<String, Value> = REFUSALS
        .iter()
        .map(|code| {
            let name = serde_json::to_value(code)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            (
                name,
                text(&Response::refusal(&request.request_id, *code)).into(),
            )
        })
        .collect();
    let fill = text(&Request::FillRequest(request.clone()));
    json!({
        "about": "The messages of a browser fill as the Rust code wrote them when the format was frozen. Each is the JSON text a frame carries. A frame is four length bytes and that text: in the machine's byte order between browser and host, shown here for a little-endian machine, and big-endian between the host and the desktop session.",
        "version": VERSION,
        "host_name": HOST_NAME,
        "chromium_extension_id": CHROMIUM_EXTENSION_ID,
        "firefox_extension_id": FIREFOX_EXTENSION_ID,
        "from_extension": {
            "fill_request": fill,
            "cancel": text(&Request::Cancel(cancel)),
        },
        "to_extension": {
            "waiting": text(&Response::Waiting(Waiting { request_id: request.request_id.clone() })),
            "fill_reply": text(&Response::FillReply(reply())),
            "error_naming_no_request": text(&Response::Error(Failure::unnamed(Refusal::InvalidMessage))),
            "errors": errors,
        },
        "host_to_session": {
            "from_chromium": text(&Forwarded {
                caller: Caller::Chromium(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")),
                request: request.clone(),
            }),
            "from_firefox": text(&Forwarded {
                caller: Caller::Firefox(FIREFOX_EXTENSION_ID.into()),
                request: request.clone(),
            }),
        },
        "frames_of_the_fill_request": {
            "browser_on_a_little_endian_machine": hex(&[&(fill.len() as u32).to_le_bytes()[..], fill.as_bytes()].concat()),
            "socket": hex(&Prefix::Socket.frame(fill.as_bytes()).unwrap()),
        },
    })
}

/// Says where two values differ, so that a failure names the message.
fn differences(path: &str, frozen: &Value, made: &Value, found: &mut Vec<String>) {
    match (frozen, made) {
        (Value::Object(frozen), Value::Object(made)) => {
            for name in frozen.keys().chain(made.keys()) {
                match (frozen.get(name), made.get(name)) {
                    (Some(left), Some(right)) => {
                        differences(&format!("{path}.{name}"), left, right, found)
                    }
                    _ => found.push(format!("{path}.{name} is in one and not the other")),
                }
            }
        }
        _ if frozen != made => found.push(path.to_owned()),
        _ => {}
    }
}

#[test]
fn the_messages_of_a_fill_are_the_frozen_ones() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/messages.json");
    let made = messages();
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences("messages", &frozen, &made, &mut found);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "these no longer match the frozen values: {found:#?}"
    );

    // And back: the frozen texts read as what they were.
    let frozen_text =
        |section: &str, name: &str| frozen[section][name].as_str().unwrap().as_bytes().to_vec();
    assert_eq!(
        Request::read(&frozen_text("from_extension", "fill_request")).unwrap(),
        Request::FillRequest(request())
    );
    assert!(matches!(
        Request::read(&frozen_text("from_extension", "cancel")).unwrap(),
        Request::Cancel(cancel) if cancel.request_id == request().request_id
    ));
    let read = |name: &str| -> Response {
        serde_json::from_slice(&frozen_text("to_extension", name)).unwrap()
    };
    assert!(read("waiting").answers(&request()) && !read("waiting").is_final());
    assert_eq!(read("fill_reply"), Response::FillReply(reply()));
    assert!(read("fill_reply").answers(&request()));
    assert_eq!(
        read("error_naming_no_request"),
        Response::Error(Failure::unnamed(Refusal::InvalidMessage))
    );
    let errors = frozen["to_extension"]["errors"].as_object().unwrap();
    assert_eq!(errors.len(), REFUSALS.len());
    for code in REFUSALS {
        let name = serde_json::to_value(code).unwrap();
        let stored = errors[name.as_str().unwrap()].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Response>(stored).unwrap(),
            Response::refusal(&request().request_id, code)
        );
    }
    for (name, browser) in [("from_chromium", "Chromium"), ("from_firefox", "Firefox")] {
        let forwarded: Forwarded =
            serde_json::from_slice(&frozen_text("host_to_session", name)).unwrap();
        assert!(forwarded.caller.is_allowed());
        assert_eq!(forwarded.caller.browser(), browser);
        assert_eq!(forwarded.request, request());
    }

    // The frames: the same text behind four length bytes.
    let frames = &frozen["frames_of_the_fill_request"];
    #[cfg(target_endian = "little")]
    assert_eq!(
        hex(&Prefix::Browser
            .frame(&frozen_text("from_extension", "fill_request"))
            .unwrap()),
        frames["browser_on_a_little_endian_machine"]
    );
    assert_eq!(
        hex(&Prefix::Socket
            .frame(&frozen_text("from_extension", "fill_request"))
            .unwrap()),
        frames["socket"]
    );
    assert!(frames["socket"].as_str().unwrap().starts_with("000000c0"));

    // A message of a later version is refused by name, not misread.
    let later = String::from_utf8(frozen_text("from_extension", "fill_request"))
        .unwrap()
        .replace("\"version\":1", "\"version\":2");
    assert_eq!(
        Request::read(later.as_bytes()),
        Err(Failure::new(
            &request().request_id,
            Refusal::UnsupportedVersion
        ))
    );
}
