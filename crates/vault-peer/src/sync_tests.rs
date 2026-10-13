//! Sync sessions over a byte stream: two sides that each have much to send
//! the other, a slow path, a peer that says nothing, and a peer of the
//! previous version. The clock is tokio's, paused, so a wait the session
//! would give up on passes at once.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tempfile::tempdir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
    time::{Instant, Sleep},
};

use crate::{
    fixture::unhex,
    tests::{inviter, login, pair},
    transport::{read_frame, run_session},
    Error, SyncMessage,
};

/// Version 1 waited to send while the peer's frames went unread: when each
/// side had more batches for the other than the queue and the buffers
/// held, both waited for room until the session timed out, every time
/// (seen with 1,200 revisions each way here before the change).
#[tokio::test(start_paused = true)]
async fn two_devices_that_each_lack_many_of_the_others_revisions_finish() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let mut b = pair(dir.path(), &mut a);
    for n in 0..1_200 {
        a.vault.put(login(&format!("A {n}"), "a password")).unwrap();
        b.vault.put(login(&format!("B {n}"), "b password")).unwrap();
    }
    let (to_a, to_b) = tokio::io::duplex(64 * 1024);
    let (a_vault, b_vault) = (Mutex::new(&mut a.vault), Mutex::new(&mut b.vault));
    let (from_a, from_b) = tokio::join!(
        run_session(to_b, &a_vault, None),
        run_session(to_a, &b_vault, None)
    );
    let ((from_a, _), (from_b, _)) = (from_a.unwrap(), from_b.unwrap());
    assert_eq!((from_a.sent, from_b.sent), (1_200, 1_200));
    assert_eq!((from_a.applied, from_b.applied), (1_200, 1_200));
    drop((a_vault, b_vault));
    assert_eq!(a.vault.list().unwrap().len(), 2_400);
    assert_eq!(
        a.vault.revision_ids().unwrap().len(),
        b.vault.revision_ids().unwrap().len()
    );
}

/// A stream that writes 16 KiB a second.
struct Slow<S> {
    inner: S,
    room: usize,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Slow<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Slow<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(wait) = self.wait.as_mut() {
            if wait.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.wait = None;
            self.room = 16 * 1024;
        }
        if self.room == 0 {
            self.wait = Some(Box::pin(tokio::time::sleep(Duration::from_secs(1))));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let room = self.room;
        let polled = Pin::new(&mut self.inner).poll_write(cx, &buf[..buf.len().min(room)]);
        if let Poll::Ready(Ok(written)) = polled {
            self.room -= written;
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Version 1 gave up on a frame that took more than a minute to arrive,
/// however steadily it came. A batch of 2 MiB at 16 KiB a second takes two
/// minutes, during which the receiver, with nothing to send, says nothing.
#[tokio::test(start_paused = true)]
async fn a_large_batch_on_a_slow_path_arrives() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let mut b = pair(dir.path(), &mut a);
    let mut large = login("Large", "p");
    large.notes = "x".repeat(2 * 1024 * 1024);
    a.vault.put(large.clone()).unwrap();
    let (to_a, to_b) = tokio::io::duplex(64 * 1024);
    let slow = Slow {
        inner: to_b,
        room: 16 * 1024,
        wait: None,
    };
    let (a_vault, b_vault) = (Mutex::new(&mut a.vault), Mutex::new(&mut b.vault));
    let started = Instant::now();
    let (from_a, from_b) = tokio::join!(
        run_session(slow, &a_vault, None),
        run_session(to_a, &b_vault, None)
    );
    assert!(started.elapsed() > Duration::from_secs(120));
    assert_eq!(from_a.unwrap().0.sent, 1);
    assert_eq!(from_b.unwrap().0.applied, 1);
    drop((a_vault, b_vault));
    assert_eq!(
        b.vault.get(&large.id).unwrap().item.notes.len(),
        2 * 1024 * 1024
    );
}

/// A peer that sends nothing and reads nothing ends the session after a
/// minute.
#[tokio::test(start_paused = true)]
async fn a_peer_that_says_nothing_is_given_up_on() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let (here, _silent) = tokio::io::duplex(64 * 1024);
    let vault = Mutex::new(&mut a.vault);
    let started = Instant::now();
    assert!(matches!(
        run_session(here, &vault, None).await,
        Err(Error::Timeout)
    ));
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(60) && waited < Duration::from_secs(70),
        "{waited:?}"
    );
}

/// A device of version 1 sends its `Hello` and its inventory at once. This
/// side refuses the session by its version and still sends its own `Hello`,
/// which the other reads and refuses by its version in turn.
#[tokio::test(start_paused = true)]
async fn a_peer_of_version_1_is_refused_by_its_version_and_reads_ours() {
    let dir = tempdir().unwrap();
    let mut a = inviter(dir.path());
    let vault_id = a.vault.vault_id();
    let (here, mut there) = tokio::io::duplex(64 * 1024);
    let first: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/sync.json")).unwrap();
    // The frozen frames are for another vault; this one's ID goes in their
    // place, so the version is all that differs.
    let hello = unhex(first["hello"]["frame"].as_str().unwrap());
    let mut hello = hello;
    hello[6..38].copy_from_slice(&vault_id);
    let inventory = unhex(first["inventory"]["frame"].as_str().unwrap());
    let peer = async move {
        there.write_all(&hello).await.unwrap();
        there.write_all(&inventory).await.unwrap();
        let ours: SyncMessage = read_frame(&mut there).await.unwrap();
        // The rest of what comes until the connection closes.
        let mut rest = Vec::new();
        let _ = there.read_to_end(&mut rest).await;
        ours
    };
    let vault = Mutex::new(&mut a.vault);
    let (result, ours) = tokio::join!(run_session(here, &vault, None), peer);
    assert!(
        matches!(result, Err(Error::UnsupportedVersion)),
        "{result:?}"
    );
    assert!(matches!(ours, SyncMessage::Hello { version: 2, .. }));
}
