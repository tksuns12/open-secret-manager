//! How the host and the desktop session prove to each other, over a Windows
//! named pipe, that each knows the link's secret: before the host sends a
//! request, and before the session accepts one.
//!
//! A pipe's name is listed by `dir \\.\pipe\` for every account on the
//! machine, so it is no secret, and once the app has quit another account
//! can make a pipe of the same name. The secret is a second value, kept in
//! the file in the owner's folder with the name, that never crosses the
//! pipe: each side sends a fresh random number and proves, with an HMAC of
//! both numbers and the pipe's name, that it holds the secret. The host
//! sends nothing but its number until the session has proved it.
//!
//! The two proofs carry different labels, so that one cannot be played back
//! as the other.

use std::{fmt::Write as _, io};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// How many random bytes the secret has.
pub const SECRET_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const PROOF_BYTES: usize = 32;

/// The value only the owner's folder holds.
pub type Secret = Zeroizing<[u8; SECRET_BYTES]>;

/// A new random secret.
pub fn new_secret() -> io::Result<Secret> {
    let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
    random(&mut *secret)?;
    Ok(secret)
}

fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(|error| io::Error::other(error.to_string()))
}

/// The secret as 64 lowercase hex digits.
pub fn secret_to_hex(secret: &Secret) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(SECRET_BYTES * 2));
    for byte in secret.iter() {
        write!(text, "{byte:02x}").expect("writing to a string");
    }
    text
}

/// The secret that `text` spells, if it is exactly 64 lowercase hex digits.
pub fn secret_from_hex(text: &str) -> Option<Secret> {
    if text.len() != SECRET_BYTES * 2 {
        return None;
    }
    let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
    for (byte, pair) in secret.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digit = |digit: u8| match digit {
            b'0'..=b'9' => Some(digit - b'0'),
            b'a'..=b'f' => Some(digit - b'a' + 10),
            _ => None,
        };
        *byte = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(secret)
}

fn proof(
    label: &[u8],
    secret: &Secret,
    name: &str,
    host_nonce: &[u8],
    session_nonce: &[u8],
) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(&secret[..]).expect("a key of any length");
    mac.update(label);
    // The name's length first, so that no name can run into the numbers.
    mac.update(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
    mac.update(name.as_bytes());
    mac.update(host_nonce);
    mac.update(session_nonce);
    mac
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the other end of the pipe does not hold the link's secret",
    )
}

const SESSION: &[u8] = b"osm-browser-link session";
const HOST: &[u8] = b"osm-browser-link host";

/// The host's half. Succeeds only once the session on the pipe has proved
/// it holds `secret`; nothing but a random number has been sent before.
pub async fn as_host(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    name: &str,
    secret: &Secret,
) -> io::Result<()> {
    let mut host_nonce = [0_u8; NONCE_BYTES];
    random(&mut host_nonce)?;
    stream.write_all(&host_nonce).await?;
    stream.flush().await?;

    let mut session_nonce = [0_u8; NONCE_BYTES];
    stream.read_exact(&mut session_nonce).await?;
    let mut theirs = [0_u8; PROOF_BYTES];
    stream.read_exact(&mut theirs).await?;
    proof(SESSION, secret, name, &host_nonce, &session_nonce)
        .verify_slice(&theirs)
        .map_err(|_| refused())?;

    let ours = proof(HOST, secret, name, &host_nonce, &session_nonce).finalize();
    stream.write_all(&ours.into_bytes()).await?;
    stream.flush().await
}

/// The session's half. Succeeds only once the host has proved it holds
/// `secret`; the host is sent only the session's proof.
pub async fn as_session(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    name: &str,
    secret: &Secret,
) -> io::Result<()> {
    let mut host_nonce = [0_u8; NONCE_BYTES];
    stream.read_exact(&mut host_nonce).await?;
    let mut session_nonce = [0_u8; NONCE_BYTES];
    random(&mut session_nonce)?;
    let ours = proof(SESSION, secret, name, &host_nonce, &session_nonce).finalize();
    stream.write_all(&session_nonce).await?;
    stream.write_all(&ours.into_bytes()).await?;
    stream.flush().await?;

    let mut theirs = [0_u8; PROOF_BYTES];
    stream.read_exact(&mut theirs).await?;
    proof(HOST, secret, name, &host_nonce, &session_nonce)
        .verify_slice(&theirs)
        .map_err(|_| refused())
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    const NAME: &str = r"\\.\pipe\OpenSecretManager-00112233445566778899aabbccddeeff";

    async fn meet(host: &Secret, session: &Secret, session_name: &str) -> (bool, bool) {
        let (mut a, mut b) = duplex(1024);
        // Each end closes its side when it is done, as a pipe's would.
        let (host_result, session_result) = tokio::join!(
            async {
                let result = as_host(&mut a, NAME, host).await;
                drop(a);
                result
            },
            async {
                let result = as_session(&mut b, session_name, session).await;
                drop(b);
                result
            }
        );
        (host_result.is_ok(), session_result.is_ok())
    }

    #[tokio::test]
    async fn two_ends_with_the_same_secret_trust_each_other() {
        let secret = new_secret().unwrap();
        assert_eq!(meet(&secret, &secret, NAME).await, (true, true));
    }

    #[tokio::test]
    async fn a_pipe_made_without_the_secret_is_not_trusted_and_gets_no_request() {
        let (host, session) = (new_secret().unwrap(), new_secret().unwrap());
        let (host_ok, session_ok) = meet(&host, &session, NAME).await;
        assert!(!host_ok && !session_ok);

        // What a squatter that does not know the secret sees: the host's
        // number, and nothing after it, whatever it answers.
        let (mut host_end, mut squatter) = duplex(1024);
        let squatter_task = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut number = [0_u8; NONCE_BYTES];
            squatter.read_exact(&mut number).await.unwrap();
            seen.extend_from_slice(&number);
            squatter
                .write_all(&[7_u8; NONCE_BYTES + PROOF_BYTES])
                .await
                .unwrap();
            squatter.shutdown().await.unwrap();
            let mut rest = Vec::new();
            squatter.read_to_end(&mut rest).await.unwrap();
            (seen.len(), rest)
        });
        let secret = new_secret().unwrap();
        assert!(as_host(&mut host_end, NAME, &secret).await.is_err());
        drop(host_end);
        let (seen, rest) = squatter_task.await.unwrap();
        assert_eq!(seen, NONCE_BYTES);
        assert!(rest.is_empty(), "the host sent {} bytes more", rest.len());
    }

    /// A host that speaks the protocol by hand, sending `host_proof` made by
    /// `make` from the session's own proof and the numbers, to see whether
    /// the session accepts it.
    async fn session_meets_a_host_sending(
        secret: &Secret,
        make: impl FnOnce(&Secret, &[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32],
    ) -> io::Result<()> {
        let (mut host, mut session) = duplex(1024);
        let host_nonce = [3_u8; NONCE_BYTES];
        let session_side = async {
            let result = as_session(&mut session, NAME, secret).await;
            // Kept open until the session has judged, so that it is the
            // proof that is refused and not the end of the stream.
            result
        };
        let host_side = async {
            host.write_all(&host_nonce).await.unwrap();
            let mut session_nonce = [0_u8; NONCE_BYTES];
            host.read_exact(&mut session_nonce).await.unwrap();
            let mut session_proof = [0_u8; PROOF_BYTES];
            host.read_exact(&mut session_proof).await.unwrap();
            let sent = make(secret, &host_nonce, &session_nonce, &session_proof);
            host.write_all(&sent).await.unwrap();
        };
        let (result, ()) = tokio::join!(session_side, host_side);
        drop(host);
        result
    }

    #[tokio::test]
    async fn the_session_takes_only_the_hosts_own_proof() {
        let secret = new_secret().unwrap();
        let right = |secret: &Secret, host: &[u8; 32], session: &[u8; 32], _: &[u8; 32]| {
            proof(HOST, secret, NAME, host, session)
                .finalize()
                .into_bytes()
                .into()
        };
        assert!(session_meets_a_host_sending(&secret, right).await.is_ok());
        // Nothing, a guess, the session's own proof played back, and a proof
        // made under the other label.
        let zero = |_: &Secret, _: &[u8; 32], _: &[u8; 32], _: &[u8; 32]| [0_u8; 32];
        let echoed = |_: &Secret, _: &[u8; 32], _: &[u8; 32], theirs: &[u8; 32]| *theirs;
        let relabelled = |secret: &Secret, host: &[u8; 32], session: &[u8; 32], _: &[u8; 32]| {
            proof(SESSION, secret, NAME, host, session)
                .finalize()
                .into_bytes()
                .into()
        };
        assert!(session_meets_a_host_sending(&secret, zero).await.is_err());
        assert!(session_meets_a_host_sending(&secret, echoed).await.is_err());
        assert!(session_meets_a_host_sending(&secret, relabelled)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_proof_is_for_one_pipe_name() {
        let secret = new_secret().unwrap();
        assert_eq!(
            meet(&secret, &secret, r"\\.\pipe\OpenSecretManager-other").await,
            (false, false)
        );
    }

    #[tokio::test]
    async fn the_hosts_proof_cannot_be_played_back_as_the_sessions() {
        let secret = new_secret().unwrap();
        let (host_nonce, session_nonce) = ([1_u8; NONCE_BYTES], [2_u8; NONCE_BYTES]);
        let as_host_proof = proof(HOST, &secret, NAME, &host_nonce, &session_nonce).finalize();
        assert!(proof(SESSION, &secret, NAME, &host_nonce, &session_nonce)
            .verify_slice(&as_host_proof.into_bytes())
            .is_err());
    }

    #[test]
    fn a_secret_is_spelled_in_exactly_64_lowercase_hex_digits() {
        let secret = new_secret().unwrap();
        let text = secret_to_hex(&secret);
        assert_eq!(text.len(), 64);
        assert_eq!(*secret_from_hex(&text).unwrap(), *secret);
        for wrong in [
            String::new(),
            text[..63].to_owned(),
            format!("{}0", *text),
            text.to_uppercase(),
            format!("{}g", &text[..63]),
        ] {
            assert!(secret_from_hex(&wrong).is_none(), "{wrong:?}");
        }
    }
}
