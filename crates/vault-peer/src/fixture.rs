//! What the frozen-format tests of this crate share. Each area's test, in a
//! `fixtures` module beside the code it freezes, builds its messages from
//! inputs anyone can write down and compares them with a file under
//! `fixtures/`. A file is never made again: to add one for a new format,
//! run its test with `OSM_WRITE_NEW_FIXTURES=1` while it does not exist.

use std::path::PathBuf;

use serde_json::Value;

pub(crate) fn folder() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// `N` bytes counting up from `first`.
pub(crate) fn counting<const N: usize>(first: u8) -> [u8; N] {
    std::array::from_fn(|index| first.wrapping_add(index as u8))
}

/// A message as it is sent: its postcard body, and that body in a frame.
pub(crate) fn sent(message: &impl serde::Serialize) -> Value {
    let frame = crate::wire::encode_frame(message).unwrap();
    serde_json::json!({ "body": hex(&frame[4..]), "frame": hex(&frame) })
}

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

/// Checks what this build made against the frozen file `name`, and returns
/// the frozen values for the test to read back.
pub(crate) fn frozen(name: &str, made: &Value) -> Value {
    let path = folder().join(name);
    if !path.exists() && std::env::var_os("OSM_WRITE_NEW_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(made).unwrap() + "\n").unwrap();
    }
    let frozen: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut found = Vec::new();
    differences(name, &frozen, made, &mut found);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "these no longer match the frozen values: {found:#?}"
    );
    frozen
}
