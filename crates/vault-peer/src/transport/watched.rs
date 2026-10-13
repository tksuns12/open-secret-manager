//! A stream that notes when bytes last moved through it, either way, so a
//! sync session can tell a slow path, whose bytes keep moving, from one that
//! has stopped.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

/// When bytes last moved, shared by a stream's two halves.
#[derive(Clone)]
pub(crate) struct Moved(Arc<Mutex<Instant>>);

impl Moved {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    /// Notes that something moved now.
    pub(crate) fn mark(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
    }

    fn last(&self) -> Instant {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns once nothing has moved either way for `silence`.
    pub(crate) async fn stalled(&self, silence: Duration) {
        loop {
            let deadline = self.last() + silence;
            if deadline <= Instant::now() {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

pub(crate) struct Watched<S> {
    inner: S,
    moved: Moved,
}

impl<S> Watched<S> {
    pub(crate) fn new(inner: S, moved: Moved) -> Self {
        Self { inner, moved }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.moved.mark();
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            self.moved.mark();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
