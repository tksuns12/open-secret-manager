//! What a browser extension sends the native host, and the frames it comes
//! in. A message is refused, naming its request only by an ID of the
//! allowed form, or is one whose every check passed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_browser_link::frame::Prefix;
use osm_browser_link::Request;

fn is_id(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fuzz_target!(|data: &[u8]| {
    match Request::read(data) {
        Ok(Request::FillRequest(request)) => {
            let origin = request.check().expect("a request read is a valid one");
            assert_eq!(origin.to_string(), request.origin);
            assert!(is_id(&request.request_id) && is_id(&request.document_id));
            assert_eq!(request.frame_id, 0);
        }
        Ok(Request::Cancel(cancel)) => assert!(is_id(&cancel.request_id)),
        Err(failure) => {
            if let Some(id) = &failure.request_id {
                assert!(is_id(id));
            }
        }
    }
    for prefix in [Prefix::Browser, Prefix::Socket] {
        let _ = prefix.read(&mut &data[..]);
    }
});
