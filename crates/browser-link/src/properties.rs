//! What arrives from the other side of a fill is read without a crash, and
//! is either refused or exactly what the protocol allows. The cases are new
//! on every run; a failing one is kept in `proptest-regressions/`.

use proptest::prelude::*;
use serde_json::{json, Value};

use crate::{
    frame::{Prefix, MAX_FRAME},
    Caller, FillRequest, Request, Response,
};

/// An ID as the extension makes them: 1 to 64 letters, digits, or hyphens.
fn is_id(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<f64>().prop_map(Value::from),
        ".{0,12}".prop_map(Value::from),
        Just(Value::from("https://example.com")),
        Just(Value::from(1)),
        Just(Value::from(0)),
    ];
    leaf.prop_recursive(2, 12, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..3).prop_map(Value::from),
            prop::collection::vec(("[a-zA-Z]{1,10}", inner), 0..3)
                .prop_map(|fields| Value::Object(fields.into_iter().collect())),
        ]
    })
}

/// Something shaped like a message from the extension, with any value in
/// any field.
fn request_like() -> impl Strategy<Value = Value> {
    let kind = prop_oneof![
        Just(Value::from("fill_request")),
        Just(Value::from("cancel")),
        Just(Value::from("unlock")),
        any_json(),
    ];
    let field = prop_oneof![
        Just("version".to_owned()),
        Just("requestId".to_owned()),
        Just("tabId".to_owned()),
        Just("frameId".to_owned()),
        Just("documentId".to_owned()),
        Just("origin".to_owned()),
        Just("username".to_owned()),
        "[a-zA-Z]{1,8}",
    ];
    let value = prop_oneof![
        any_json(),
        "[a-zA-Z0-9-]{0,70}".prop_map(Value::from),
        prop_oneof![
            Just("https://example.com"),
            Just("https://Example.com"),
            Just("https://example.com:443"),
            Just("https://example.com/"),
            Just("http://example.com"),
            Just("https://a@example.com"),
        ]
        .prop_map(Value::from),
        (-2_i64..3).prop_map(Value::from),
    ];
    (kind, prop::collection::vec((field, value), 0..8)).prop_map(|(kind, fields)| {
        let mut message = json!({ "type": kind, "version": 1, "requestId": "r-1", "tabId": 1,
            "frameId": 0, "documentId": "d-1", "origin": "https://example.com" });
        for (name, value) in fields {
            message[name.as_str()] = value;
        }
        message
    })
}

proptest! {
    /// Whatever the extension sends is refused, naming the request only by
    /// an ID of the allowed form, or is a request whose every check passed.
    #[test]
    fn a_message_from_the_extension_is_refused_or_wholly_valid(
        body in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..200),
            request_like().prop_map(|message| serde_json::to_vec(&message).unwrap()),
        ],
    ) {
        match Request::read(&body) {
            Ok(Request::FillRequest(request)) => {
                let origin = request.check();
                prop_assert!(origin.is_ok());
                prop_assert_eq!(origin.unwrap().to_string(), request.origin.clone());
                prop_assert!(is_id(&request.request_id) && is_id(&request.document_id));
                prop_assert_eq!(request.frame_id, 0);
            }
            Ok(Request::Cancel(cancel)) => prop_assert!(is_id(&cancel.request_id)),
            Ok(Request::CardRequest(card)) => {
                let origin = card.check();
                prop_assert!(origin.is_ok());
                prop_assert_eq!(origin.unwrap().to_string(), card.top_origin.clone());
                prop_assert!(!card.frames.is_empty() && card.frames.len() <= 8);
            }
            Err(failure) => {
                if let Some(id) = &failure.request_id {
                    prop_assert!(is_id(id));
                }
            }
        }
    }

    /// A card's request is refused, or every document it names is an HTTPS
    /// origin, each frame once with fields each once, and the page itself,
    /// if named, of the page's origin.
    #[test]
    fn a_card_request_is_refused_or_wholly_valid(
        frames in prop::collection::vec(
            (
                0_i64..4,
                prop_oneof![
                    Just("https://example.com"),
                    Just("https://pay.example.net"),
                    Just("http://example.com"),
                    Just("https://example.com/"),
                    Just("null"),
                ],
                prop::collection::vec(
                    prop_oneof![Just("number"), Just("security_code"), Just("expiry"), Just("pin")],
                    0..4,
                ),
            ),
            0..10,
        ),
    ) {
        let frames: Vec<Value> = frames
            .into_iter()
            .map(|(frame, origin, fields)| json!({ "frameId": frame, "documentId": "d-1", "origin": origin, "fields": fields }))
            .collect();
        let message = json!({ "type": "card_request", "version": 2, "requestId": "r-1", "tabId": 1,
            "topOrigin": "https://example.com", "frames": frames });
        match Request::read(&serde_json::to_vec(&message).unwrap()) {
            Ok(Request::CardRequest(card)) => {
                prop_assert!(card.check().is_ok());
                let mut ids: Vec<i64> = card.frames.iter().map(|frame| frame.frame_id).collect();
                ids.sort_unstable();
                ids.dedup();
                prop_assert_eq!(ids.len(), card.frames.len());
                for frame in &card.frames {
                    prop_assert!(frame.origin == "https://example.com" || frame.origin == "https://pay.example.net");
                    prop_assert!(frame.frame_id != 0 || frame.origin == "https://example.com");
                    prop_assert!(!frame.fields.is_empty());
                }
            }
            Ok(other) => prop_assert!(false, "{other:?}"),
            Err(failure) => prop_assert_eq!(failure.request_id.as_deref(), Some("r-1")),
        }
    }

    /// A reply is handed on only if it answers the request exactly.
    #[test]
    fn a_response_answers_a_request_only_if_it_names_all_of_it(
        response in request_like().prop_map(|mut message| {
            message["type"] = json!("fill_reply");
            message.as_object_mut().unwrap().remove("version");
            message["username"] = json!("u");
            message["password"] = json!("p");
            message
        }),
    ) {
        let request = FillRequest {
            version: 1,
            request_id: "r-1".into(),
            tab_id: 1,
            frame_id: 0,
            document_id: "d-1".into(),
            origin: "https://example.com".into(),
        };
        if let Ok(read) = serde_json::from_value::<Response>(response.clone()) {
            if read.answers(&request) {
                prop_assert_eq!(&response["requestId"], "r-1");
                prop_assert_eq!(&response["tabId"], 1);
                prop_assert_eq!(&response["frameId"], 0);
                prop_assert_eq!(&response["documentId"], "d-1");
                prop_assert_eq!(&response["origin"], "https://example.com");
            }
        }
    }

    /// Frames read from any byte stream are never larger than a frame may
    /// be, and reading stops at the first one that is not a frame.
    #[test]
    fn frames_read_from_any_stream_are_within_the_bound(
        prefix in prop_oneof![Just(Prefix::Browser), Just(Prefix::Socket)],
        stream in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..300),
            (any::<u32>(), prop::collection::vec(any::<u8>(), 0..64)).prop_map(|(length, rest)| {
                [length.to_be_bytes().to_vec(), length.to_le_bytes().to_vec(), rest].concat()
            }),
        ],
    ) {
        let mut reader = stream.as_slice();
        while let Ok(Some(body)) = prefix.read(&mut reader) {
            prop_assert!(!body.is_empty() && body.len() <= MAX_FRAME);
        }
    }

    /// Only the allowed extension of each browser is let through, whatever
    /// the command line says.
    #[test]
    fn only_the_allowed_extension_is_let_through(arguments in prop::collection::vec(
        prop_oneof![
            Just(format!("chrome-extension://{}/", crate::CHROMIUM_EXTENSION_ID)),
            Just(crate::FIREFOX_EXTENSION_ID.to_owned()),
            "chrome-extension://[a-p]{0,34}/?",
            ".{0,40}",
        ],
        0..4,
    )) {
        if let Some(caller) = Caller::from_args(&arguments).filter(Caller::is_allowed) {
            match caller {
                Caller::Chromium(origin) => prop_assert_eq!(
                    origin,
                    format!("chrome-extension://{}/", crate::CHROMIUM_EXTENSION_ID)
                ),
                Caller::Firefox(extension) => {
                    prop_assert_eq!(extension, crate::FIREFOX_EXTENSION_ID);
                    prop_assert!(arguments.len() >= 2);
                }
            }
        }
    }
}
