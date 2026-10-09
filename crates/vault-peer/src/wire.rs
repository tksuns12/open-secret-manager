//! Length-prefixed frames: a 4-byte big-endian length, then a postcard body.
//!
//! Lengths are checked before any body is buffered, so a peer cannot make
//! the receiver allocate more than [`MAX_FRAME_BYTES`] for one frame.

use serde::{de::DeserializeOwned, Serialize};

use crate::{Error, Result};

/// Fits one maximum-size revision (16 MiB of ciphertext) plus overhead.
pub const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;
const LENGTH_PREFIX: usize = 4;

pub fn encode_frame(message: &impl Serialize) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(message).map_err(|_| Error::MalformedFrame)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes a body that has already been split from its length prefix.
///
/// Only the one form of a message is read. postcard alone would also take
/// a number written in more bytes than it needs, so a message is read only
/// if it is written back as exactly the bytes that came.
pub fn decode_body<T: Serialize + DeserializeOwned>(body: &[u8]) -> Result<T> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge);
    }
    let (message, rest) = postcard::take_from_bytes(body).map_err(|_| Error::MalformedFrame)?;
    if !rest.is_empty() || postcard::to_allocvec(&message).ok().as_deref() != Some(body) {
        return Err(Error::MalformedFrame);
    }
    Ok(message)
}

/// Reassembles frames from a byte stream.
#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// Appends received bytes. Fails as soon as a declared length exceeds
    /// the limit, before the body is buffered.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(bytes);
        if let Some(length) = self.declared_length() {
            if length > MAX_FRAME_BYTES {
                self.buffer.clear();
                return Err(Error::FrameTooLarge);
            }
        }
        Ok(())
    }

    /// Returns the next complete frame body, if one has fully arrived.
    pub fn next_body(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(length) = self.declared_length() else {
            return Ok(None);
        };
        if length > MAX_FRAME_BYTES {
            return Err(Error::FrameTooLarge);
        }
        if self.buffer.len() < LENGTH_PREFIX + length {
            return Ok(None);
        }
        let body = self.buffer[LENGTH_PREFIX..LENGTH_PREFIX + length].to_vec();
        self.buffer.drain(..LENGTH_PREFIX + length);
        Ok(Some(body))
    }

    fn declared_length(&self) -> Option<usize> {
        let prefix: [u8; LENGTH_PREFIX] = self.buffer.get(..LENGTH_PREFIX)?.try_into().ok()?;
        Some(u32::from_be_bytes(prefix) as usize)
    }
}
