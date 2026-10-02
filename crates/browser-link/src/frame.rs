//! Length-prefixed frames, bounded on both hops.
//!
//! Between the browser and the host the prefix is the browser's: 32 bits in
//! the machine's byte order. Between the host and the desktop session it is
//! 32 bits, big-endian. Either way a frame is JSON of at most [`MAX_FRAME`]
//! bytes, far below what a browser allows, so that neither side ever
//! buffers more than that for the other.

use std::io::{self, Read, Write};

use serde::Serialize;
use zeroize::Zeroizing;

/// The largest frame either hop carries.
pub const MAX_FRAME: usize = 64 * 1024;

/// A frame's bytes, wiped when dropped: a reply carries a password.
pub type Body = Zeroizing<Vec<u8>>;

/// Which way the four length bytes are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// The browser's native messaging: the machine's byte order.
    Browser,
    /// The socket between the host and the desktop session: big-endian.
    Socket,
}

impl Prefix {
    /// The length a prefix announces, refused if no frame may have it.
    pub fn length(self, prefix: [u8; 4]) -> io::Result<usize> {
        let length = match self {
            Self::Browser => u32::from_ne_bytes(prefix),
            Self::Socket => u32::from_be_bytes(prefix),
        } as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }
        Ok(length)
    }

    /// A frame holding `body`, prefix included.
    pub fn frame(self, body: &[u8]) -> io::Result<Body> {
        if body.is_empty() || body.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }
        let length = body.len() as u32;
        let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
        frame.extend_from_slice(&match self {
            Self::Browser => length.to_ne_bytes(),
            Self::Socket => length.to_be_bytes(),
        });
        frame.extend_from_slice(body);
        Ok(frame)
    }

    /// Reads one frame. `None` when the other side closed between frames;
    /// closing inside one is an error.
    pub fn read(self, reader: &mut impl Read) -> io::Result<Option<Body>> {
        let mut prefix = [0_u8; 4];
        let mut filled = 0;
        while filled < prefix.len() {
            match reader.read(&mut prefix[filled..]) {
                Ok(0) if filled == 0 => return Ok(None),
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        let mut body = Zeroizing::new(vec![0_u8; self.length(prefix)?]);
        reader.read_exact(&mut body)?;
        Ok(Some(body))
    }

    /// Writes `message` as one frame.
    pub fn write(self, writer: &mut impl Write, message: &impl Serialize) -> io::Result<()> {
        writer.write_all(&self.frame(&encode(message)?)?)?;
        writer.flush()
    }
}

/// A message as the JSON a frame carries.
pub fn encode(message: &impl Serialize) -> io::Result<Body> {
    serde_json::to_vec(message)
        .map(Zeroizing::new)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(prefix: Prefix, mut bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        while let Some(body) = prefix.read(&mut bytes)? {
            frames.push(body.to_vec());
        }
        Ok(frames)
    }

    #[test]
    fn frames_round_trip_in_each_byte_order() {
        for prefix in [Prefix::Browser, Prefix::Socket] {
            let mut bytes = Vec::new();
            prefix.write(&mut bytes, &"first").unwrap();
            prefix.write(&mut bytes, &["second"]).unwrap();
            assert_eq!(
                read_all(prefix, &bytes).unwrap(),
                [br#""first""#.to_vec(), br#"["second"]"#.to_vec()]
            );
        }
        let framed = Prefix::Socket.frame(b"{}").unwrap();
        assert_eq!(framed.as_slice(), [0, 0, 0, 2, b'{', b'}']);
        let framed = Prefix::Browser.frame(b"{}").unwrap();
        assert_eq!(&framed[..4], 2_u32.to_ne_bytes());
    }

    #[test]
    fn a_frame_of_no_length_or_too_much_is_refused() {
        for prefix in [Prefix::Browser, Prefix::Socket] {
            assert!(prefix.length([0; 4]).is_err());
            assert!(prefix.length([0xff; 4]).is_err());
            assert!(prefix.frame(b"").is_err());
            assert!(prefix.frame(&vec![b' '; MAX_FRAME + 1]).is_err());
            let largest = prefix.frame(&vec![b' '; MAX_FRAME]).unwrap();
            assert_eq!(
                prefix.read(&mut largest.as_slice()).unwrap().unwrap().len(),
                MAX_FRAME
            );
        }
        let over = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert!(Prefix::Socket.length(over).is_err());
        // The body is never read, or allocated, for a refused length.
        let mut bytes = over.to_vec();
        bytes.extend_from_slice(&[b' '; 16]);
        assert_eq!(
            Prefix::Socket
                .read(&mut bytes.as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn closing_between_frames_ends_and_closing_inside_one_fails() {
        assert!(read_all(Prefix::Socket, &[]).unwrap().is_empty());
        // Inside the prefix.
        assert_eq!(
            read_all(Prefix::Socket, &[0, 0]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        // Inside the body.
        assert_eq!(
            read_all(Prefix::Socket, &[0, 0, 0, 9, b'{'])
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        // After one whole frame.
        let mut bytes = Prefix::Socket.frame(b"{}").unwrap().to_vec();
        bytes.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            read_all(Prefix::Socket, &bytes).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
