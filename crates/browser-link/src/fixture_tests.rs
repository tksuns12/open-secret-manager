//! The frozen messages of a browser fill. `fixtures/messages.json` holds
//! each message as this code wrote it when the format was frozen; the
//! extension's own tests read the same file, so that the two
//! implementations stay on one format. The file is never made again: to
//! add one for a new version, run with `OSM_WRITE_NEW_FIXTURES=1` while it
//! does not exist.

use serde_json::{json, Value};

use crate::{
    frame::{encode, Prefix},
    Caller, Cancel, CardField, CardFrame, CardReply, CardRequest, CardValues, Ceremony, Failure,
    FillReply, FillRequest, Forwarded, ForwardedCard, ForwardedPasskey, PasskeyReply,
    PasskeyRequest, Refusal, Request, Response, Waiting, CARD_VERSION, CHROMIUM_EXTENSION_ID,
    FIREFOX_EXTENSION_ID, HOST_NAME, PASSKEY_VERSION, VERSION,
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
        #[cfg(any(debug_assertions, feature = "allow-unpacked-chromium"))]
        assert!(forwarded.caller.is_allowed());
        #[cfg(not(any(debug_assertions, feature = "allow-unpacked-chromium")))]
        assert_eq!(forwarded.caller.is_allowed(), browser == "Firefox");
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

fn card_request() -> CardRequest {
    CardRequest {
        version: CARD_VERSION,
        request_id: "c0a1e7f6-0b9c-4f5d-9a57-2f1f8f3f9d11".into(),
        tab_id: 12,
        top_origin: "https://shop.example".into(),
        frames: vec![
            CardFrame {
                frame_id: 0,
                document_id: "0d3b6a52-6b1c-4c0e-8a6e-0a7d6c1b2e3f".into(),
                origin: "https://shop.example".into(),
                fields: vec![
                    CardField::Cardholder,
                    CardField::ExpiryMonth,
                    CardField::ExpiryYear,
                ],
            },
            CardFrame {
                frame_id: 3,
                document_id: "a7d6c1b2-6b1c-4c0e-8a6e-0d3b6a522e3f".into(),
                origin: "https://pay.example.net".into(),
                fields: vec![
                    CardField::Number,
                    CardField::Expiry,
                    CardField::SecurityCode,
                ],
            },
        ],
    }
}

fn card_reply() -> CardReply {
    let request = card_request();
    CardReply {
        request_id: request.request_id,
        tab_id: request.tab_id,
        top_origin: request.top_origin,
        frames: request.frames,
        card: CardValues {
            cardholder: "Owner Ünïcödé".into(),
            number: "4111111111111111".into(),
            expiry_month: "03".into(),
            expiry_year: "2030".into(),
            security_code: "123".into(),
        },
    }
}

fn card_messages() -> Value {
    let request = card_request();
    json!({
        "about": "The messages of a card's fill, which came with version 2 of the protocol (Phase 17), as the Rust code wrote them when they were frozen. A login's fill and a withdrawal stay at version 1 (messages.json); the refusals and `waiting` are the same messages for either.",
        "version": CARD_VERSION,
        "card_fields": [
            CardField::Number,
            CardField::Cardholder,
            CardField::Expiry,
            CardField::ExpiryMonth,
            CardField::ExpiryYear,
            CardField::SecurityCode,
        ],
        "from_extension": {
            "card_request": text(&Request::CardRequest(request.clone())),
        },
        "to_extension": {
            "card_reply": text(&Response::CardReply(card_reply())),
        },
        "host_to_session": {
            "from_chromium": text(&ForwardedCard {
                caller: Caller::Chromium(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")),
                card: request.clone(),
            }),
            "from_firefox": text(&ForwardedCard {
                caller: Caller::Firefox(FIREFOX_EXTENSION_ID.into()),
                card: request,
            }),
        },
    })
}

#[test]
fn the_messages_of_a_card_fill_are_the_frozen_ones() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/messages-2.json");
    let made = card_messages();
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences("messages-2", &frozen, &made, &mut found);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "these no longer match the frozen values: {found:#?}"
    );

    let frozen_text =
        |section: &str, name: &str| frozen[section][name].as_str().unwrap().as_bytes().to_vec();
    assert_eq!(
        Request::read(&frozen_text("from_extension", "card_request")).unwrap(),
        Request::CardRequest(card_request())
    );
    let reply: Response =
        serde_json::from_slice(&frozen_text("to_extension", "card_reply")).unwrap();
    assert_eq!(reply, Response::CardReply(card_reply()));
    assert!(reply.answers_card(&card_request()) && !reply.answers(&request()));
    for (name, browser) in [("from_chromium", "Chromium"), ("from_firefox", "Firefox")] {
        let forwarded: ForwardedCard =
            serde_json::from_slice(&frozen_text("host_to_session", name)).unwrap();
        #[cfg(any(debug_assertions, feature = "allow-unpacked-chromium"))]
        assert!(forwarded.caller.is_allowed());
        #[cfg(not(any(debug_assertions, feature = "allow-unpacked-chromium")))]
        assert_eq!(forwarded.caller.is_allowed(), browser == "Firefox");
        assert_eq!(forwarded.caller.browser(), browser);
        assert_eq!(forwarded.card, card_request());
        // Not taken for a login's.
        assert!(
            serde_json::from_slice::<Forwarded>(&frozen_text("host_to_session", name)).is_err()
        );
    }
    // A card's request at a login's version is refused by its version.
    let earlier = String::from_utf8(frozen_text("from_extension", "card_request"))
        .unwrap()
        .replace("\"version\":2", "\"version\":1");
    assert_eq!(
        Request::read(earlier.as_bytes()),
        Err(Failure::new(
            &card_request().request_id,
            Refusal::UnsupportedVersion
        ))
    );
}

fn passkey_request(options: &str) -> PasskeyRequest {
    PasskeyRequest {
        version: PASSKEY_VERSION,
        request_id: "5b0e7a6c-2f8d-4d1a-9c3e-6a4b2d8f1e07".into(),
        tab_id: 14,
        origin: "https://login.example.com".into(),
        options: options.into(),
    }
}

/// A site's request to make a passkey, as WebAuthn's JSON writes it.
const CREATION: &str = r#"{"rp":{"id":"example.com","name":"Example"},"user":{"id":"AQIDBA","name":"owner@example.com","displayName":"Owner"},"challenge":"Y2hhbGxlbmdlIG9mIGEgc2l0ZQ","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required","userVerification":"preferred"}}"#;

/// A site's request to sign in.
const SIGN_IN: &str = r#"{"challenge":"Y2hhbGxlbmdlIG9mIGEgc2l0ZQ","rpId":"example.com","allowCredentials":[],"userVerification":"preferred"}"#;

/// The passkey refusals, which came with the passkeys.
const PASSKEY_REFUSALS: [Refusal; 4] = [
    Refusal::NoPasskey,
    Refusal::PasskeyRefused,
    Refusal::PasskeyExists,
    Refusal::UseBrowser,
];

fn passkey_reply() -> PasskeyReply {
    let request = passkey_request(SIGN_IN);
    PasskeyReply {
        request_id: request.request_id,
        tab_id: request.tab_id,
        origin: request.origin,
        credential: r#"{"id":"oKGio6SlpqeoqaqrrK2urw","rawId":"oKGio6SlpqeoqaqrrK2urw","type":"public-key"}"#.into(),
    }
}

fn passkey_messages() -> Value {
    let errors: serde_json::Map<String, Value> = PASSKEY_REFUSALS
        .iter()
        .map(|code| {
            let name = serde_json::to_value(code)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            let message = text(&Response::refusal(
                &passkey_request(SIGN_IN).request_id,
                *code,
            ));
            (name, Value::String(message))
        })
        .collect();
    json!({
        "about": "The messages of a passkey's request, which came with version 2 of the protocol (Phase 18, stop 6), as the Rust code wrote them when they were frozen. A site's options and the credential that answers them are WebAuthn's JSON, carried as text; `waiting`, a withdrawal, and the refusals of messages.json are the same messages for a passkey's request.",
        "version": PASSKEY_VERSION,
        "from_extension": {
            "passkey_create": text(&Request::PasskeyCreate(passkey_request(CREATION))),
            "passkey_get": text(&Request::PasskeyGet(passkey_request(SIGN_IN))),
        },
        "to_extension": {
            "passkey_reply": text(&Response::PasskeyReply(passkey_reply())),
            "errors": errors,
        },
        "host_to_session": {
            "create_from_chromium": text(&ForwardedPasskey {
                caller: Caller::Chromium(format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")),
                ceremony: Ceremony::Create,
                passkey: passkey_request(CREATION),
            }),
            "get_from_firefox": text(&ForwardedPasskey {
                caller: Caller::Firefox(FIREFOX_EXTENSION_ID.into()),
                ceremony: Ceremony::Get,
                passkey: passkey_request(SIGN_IN),
            }),
        },
    })
}

#[test]
fn the_messages_of_a_passkey_are_the_frozen_ones() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/messages-2-passkeys.json");
    let made = passkey_messages();
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences("messages-2-passkeys", &frozen, &made, &mut found);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "these no longer match the frozen values: {found:#?}"
    );

    let frozen_text =
        |section: &str, name: &str| frozen[section][name].as_str().unwrap().as_bytes().to_vec();
    assert_eq!(
        Request::read(&frozen_text("from_extension", "passkey_create")).unwrap(),
        Request::PasskeyCreate(passkey_request(CREATION))
    );
    assert_eq!(
        Request::read(&frozen_text("from_extension", "passkey_get")).unwrap(),
        Request::PasskeyGet(passkey_request(SIGN_IN))
    );
    let reply: Response =
        serde_json::from_slice(&frozen_text("to_extension", "passkey_reply")).unwrap();
    assert_eq!(reply, Response::PasskeyReply(passkey_reply()));
    assert!(reply.answers_passkey(&passkey_request(SIGN_IN)) && !reply.answers(&request()));
    let errors = frozen["to_extension"]["errors"].as_object().unwrap();
    assert_eq!(errors.len(), PASSKEY_REFUSALS.len());
    for code in PASSKEY_REFUSALS {
        let name = serde_json::to_value(code).unwrap();
        let stored = errors[name.as_str().unwrap()].as_str().unwrap();
        let read: Response = serde_json::from_str(stored).unwrap();
        assert!(read.answers_passkey(&passkey_request(SIGN_IN)) && read.is_final());
    }
    for (name, ceremony, browser) in [
        ("create_from_chromium", Ceremony::Create, "Chromium"),
        ("get_from_firefox", Ceremony::Get, "Firefox"),
    ] {
        let forwarded: ForwardedPasskey =
            serde_json::from_slice(&frozen_text("host_to_session", name)).unwrap();
        #[cfg(any(debug_assertions, feature = "allow-unpacked-chromium"))]
        assert!(forwarded.caller.is_allowed());
        #[cfg(not(any(debug_assertions, feature = "allow-unpacked-chromium")))]
        assert_eq!(forwarded.caller.is_allowed(), browser == "Firefox");
        assert_eq!(forwarded.caller.browser(), browser);
        assert_eq!(forwarded.ceremony, ceremony);
        // Not taken for a login's or a card's.
        assert!(
            serde_json::from_slice::<Forwarded>(&frozen_text("host_to_session", name)).is_err()
        );
        assert!(
            serde_json::from_slice::<ForwardedCard>(&frozen_text("host_to_session", name)).is_err()
        );
    }
    // At a login's version, refused by its version; too large, or for an
    // origin that is not https, refused.
    let text_of = |name: &str| String::from_utf8(frozen_text("from_extension", name)).unwrap();
    let id = passkey_request(SIGN_IN).request_id;
    assert_eq!(
        Request::read(
            text_of("passkey_get")
                .replace("\"version\":2", "\"version\":1")
                .as_bytes()
        ),
        Err(Failure::new(&id, Refusal::UnsupportedVersion))
    );
    let mut large = passkey_request(&"x".repeat(crate::MAX_PASSKEY_OPTIONS + 1));
    assert_eq!(large.check(), Err(Refusal::InvalidMessage));
    large.options = SIGN_IN.into();
    large.origin = "http://login.example.com".into();
    assert_eq!(large.check(), Err(Refusal::OriginRejected));
}
