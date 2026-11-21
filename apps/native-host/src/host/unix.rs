//! The host's side of the session's Unix socket.

use std::{
    collections::HashMap,
    io::Write,
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    thread,
};

use osm_browser_link::{endpoint, frame::Prefix, Failure, Refusal, Response};

use super::{lock, send, Host, MAX_OPEN, SEND_LIMIT, SILENCE_LIMIT};

/// The requests waiting for the desktop session, each with the connection
/// that carries it.
pub(super) type Open = Arc<Mutex<HashMap<String, UnixStream>>>;

/// What a Unix socket needs besides its path: nothing.
pub(super) struct Link;

impl Link {
    pub(super) fn new() -> Self {
        Self
    }
}

impl<W: Write + Send + 'static> Host<W> {
    /// Passes a checked request, `body`, to the desktop session and leaves a
    /// thread handing back what the session answers to it, as `answers`
    /// tells.
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
        let path = self
            .socket
            .as_ref()
            .ok_or(Refusal::DesktopSessionUnavailable)?;
        let mut session = endpoint::connect(path).map_err(unavailable)?;
        session
            .set_read_timeout(Some(SILENCE_LIMIT))
            .map_err(unavailable)?;
        session
            .set_write_timeout(Some(SEND_LIMIT))
            .map_err(unavailable)?;
        let framed = Prefix::Socket.frame(body).map_err(unavailable)?;
        session.write_all(&framed).map_err(unavailable)?;
        open.insert(
            request_id.to_owned(),
            session.try_clone().map_err(unavailable)?,
        );
        drop(open);

        let (request_id, out, open) = (request_id.to_owned(), self.out.clone(), self.open.clone());
        thread::spawn(move || relay(&request_id, &answers, session, &out, &open));
        Ok(())
    }

    /// Withdraws a request. Closing its connection is what tells the
    /// desktop session.
    pub(super) fn cancel(&self, request_id: &str) {
        if let Some(session) = lock(&self.open).remove(request_id) {
            let _ = session.shutdown(Shutdown::Both);
        }
    }
}

/// Hands the desktop session's answers to one request back to the
/// extension, until the answer that ends it.
fn relay(
    request_id: &str,
    answers: &impl Fn(&Response) -> bool,
    mut session: UnixStream,
    out: &Mutex<impl Write>,
    open: &Open,
) {
    loop {
        // Only what answers exactly this request is handed on. Anything
        // else, a closed connection, and a long silence all mean there is
        // no session to trust with it.
        let answer = match Prefix::Socket.read(&mut session) {
            Ok(Some(body)) => serde_json::from_slice::<Response>(&body)
                .ok()
                .filter(|response| answers(response)),
            _ => None,
        };
        // Held while answering, so that nothing but `cancelled` follows a
        // withdrawal.
        let mut open = lock(open);
        if !open.contains_key(request_id) {
            send(out, &Response::refusal(request_id, Refusal::Cancelled));
            return;
        }
        let answer = answer.unwrap_or_else(|| {
            Response::Error(Failure::new(request_id, Refusal::DesktopSessionUnavailable))
        });
        send(out, &answer);
        if answer.is_final() {
            open.remove(request_id);
            return;
        }
    }
}
