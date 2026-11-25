//! What another device sends: a message body is refused, or is the one
//! form of a message, sent as exactly those bytes; and a stream of frames
//! is cut into the same bodies however its bytes arrive.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osm_vault_peer::wire::{decode_body, encode_frame, FrameDecoder};
use osm_vault_peer::{
    EnrollmentGrant, JoinChallenge, JoinCommit, JoinRequest, JoinReveal, SyncMessage,
};
use serde::{de::DeserializeOwned, Serialize};

fn one_form<T: Serialize + DeserializeOwned>(body: &[u8]) {
    if let Ok(message) = decode_body::<T>(body) {
        assert_eq!(&encode_frame(&message).unwrap()[4..], body);
    }
}

fn bodies(chunks: impl Iterator<Item = Vec<u8>>) -> Result<Vec<Vec<u8>>, ()> {
    let mut decoder = FrameDecoder::default();
    let mut found = Vec::new();
    for chunk in chunks {
        decoder.push(&chunk).map_err(|_| ())?;
        while let Some(body) = decoder.next_body().map_err(|_| ())? {
            found.push(body);
        }
    }
    Ok(found)
}

fuzz_target!(|data: &[u8]| {
    one_form::<SyncMessage>(data);
    one_form::<JoinRequest>(data);
    one_form::<JoinCommit>(data);
    one_form::<JoinChallenge>(data);
    one_form::<JoinReveal>(data);
    one_form::<EnrollmentGrant>(data);
    // At once, and a byte at a time.
    let whole = bodies(std::iter::once(data.to_vec()));
    let bytewise = bodies(data.iter().map(|byte| vec![*byte]));
    assert_eq!(whole, bytewise);
});
