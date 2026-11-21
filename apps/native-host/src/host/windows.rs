//! The host's side of the session's named pipe.
//!
//! The pipe's name is in a file in the account's data folder (see
//! `osm_browser_link::endpoint`). A pipe cannot be cancelled from another
//! thread the way a socket is shut down, so the host runs its connections on
//! a small runtime: each request's connection is a task, which a withdrawal
//! tells to stop.

use std::{
    collections::HashMap,
    io::{self, Write},
    sync::{Arc, Mutex},
};

use osm_browser_link::{endpoint, frame::Prefix, Failure, Refusal, Response};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    runtime::{Builder, Runtime},
    sync::oneshot,
    time::{sleep, timeout, Duration},
};
use zeroize::Zeroizing;

use super::{lock, send, Host, MAX_OPEN, SEND_LIMIT, SILENCE_LIMIT};

/// What Windows says when a pipe exists and no instance is free.
const ERROR_PIPE_BUSY: i32 = 231;

/// The requests waiting for the desktop session, each with what withdraws
/// it: dropping or sending on it ends the task that carries the request.
pub(super) type Open = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

/// The runtime the connections run on.
pub(super) struct Link(Runtime);

impl Link {
    pub(super) fn new() -> Self {
        // Two workers: one may be held up writing to a browser that has
        // stopped reading, which must not stop the others.
        Self(
            Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a runtime for the host's connections"),
        )
    }
}

/// Connects to the session's pipe, waiting for an instance to be free.
async fn connect(name: &str) -> io::Result<NamedPipeClient> {
    loop {
        match ClientOptions::new().open(name) {
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                sleep(Duration::from_millis(20)).await;
            }
            other => return other,
        }
    }
}

impl<W: Write + Send + 'static> Host<W> {
    /// Passes a checked request, `body`, to the desktop session and leaves a
    /// task handing back what the session answers to it, as `answers` tells.
    pub(super) fn forward(
        &self,
        request_id: &str,
        body: &[u8],
        answers: impl Fn(&Response) -> bool + Send + 'static,
    ) -> Result<(), Refusal> {
        let mut open = lock(&self.open);
        if open.contains_key(request_id) {
            return Err(Refusal::Replayed);
        }
        if open.len() >= MAX_OPEN {
            return Err(Refusal::Busy);
        }
        let unavailable = |_| Refusal::DesktopSessionUnavailable;
        let file = self
            .socket
            .as_ref()
            .ok_or(Refusal::DesktopSessionUnavailable)?;
        let name = endpoint::read_pipe_name(file).map_err(unavailable)?;
        let framed = Prefix::Socket.frame(body).map_err(unavailable)?;
        let runtime = &self.link.0;
        let session = runtime
            .block_on(timeout(SEND_LIMIT, async {
                let mut session = connect(&name).await?;
                session.write_all(&framed).await?;
                io::Result::Ok(session)
            }))
            .map_err(|_| Refusal::DesktopSessionUnavailable)?
            .map_err(unavailable)?;
        let (withdraw, withdrawn) = oneshot::channel();
        open.insert(request_id.to_owned(), withdraw);
        drop(open);

        let (request_id, out, open) = (request_id.to_owned(), self.out.clone(), self.open.clone());
        runtime.spawn(relay(request_id, answers, session, withdrawn, out, open));
        Ok(())
    }

    /// Withdraws a request. Closing its connection is what tells the
    /// desktop session.
    pub(super) fn cancel(&self, request_id: &str) {
        if let Some(withdraw) = lock(&self.open).remove(request_id) {
            let _ = withdraw.send(());
        }
    }
}

/// The next frame from the session.
async fn read_frame(session: &mut NamedPipeClient) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0_u8; 4];
    session.read_exact(&mut prefix).await?;
    let mut body = Zeroizing::new(vec![0_u8; Prefix::Socket.length(prefix)?]);
    session.read_exact(&mut body).await?;
    Ok(body)
}

/// Hands the desktop session's answers to one request back to the
/// extension, until the answer that ends it.
async fn relay<W: Write>(
    request_id: String,
    answers: impl Fn(&Response) -> bool,
    mut session: NamedPipeClient,
    mut withdrawn: oneshot::Receiver<()>,
    out: Arc<Mutex<W>>,
    open: Open,
) {
    loop {
        // Only what answers exactly this request is handed on. Anything
        // else, a closed connection, and a long silence all mean there is
        // no session to trust with it. A withdrawal ends the wait at once.
        let body = tokio::select! {
            biased;
            _ = &mut withdrawn => None,
            read = timeout(SILENCE_LIMIT, read_frame(&mut session)) => read.ok().and_then(Result::ok),
        };
        let answer = body.and_then(|body| {
            serde_json::from_slice::<Response>(&body)
                .ok()
                .filter(|response| answers(response))
        });
        // Held while answering, so that nothing but `cancelled` follows a
        // withdrawal.
        let mut open = lock(&open);
        if !open.contains_key(&request_id) {
            send(&*out, &Response::refusal(&request_id, Refusal::Cancelled));
            return;
        }
        let answer = answer.unwrap_or_else(|| {
            Response::Error(Failure::new(
                &request_id,
                Refusal::DesktopSessionUnavailable,
            ))
        });
        send(&*out, &answer);
        if answer.is_final() {
            open.remove(&request_id);
            return;
        }
    }
}
