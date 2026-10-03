use std::{
    collections::HashMap,
    io::Write,
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use osm_browser_link::{
    endpoint, frame::Prefix, Caller, Failure, FillRequest, Forwarded, Refusal, Request, Response,
};

/// How many requests may wait for the desktop session at once. The session
/// takes one at a time and refuses the rest itself; this only bounds what
/// the host holds open.
const MAX_OPEN: usize = 4;

/// How long the desktop session may stay silent. It says it is waiting for
/// the owner far more often than this, so a longer silence means it hung.
const SILENCE_LIMIT: Duration = Duration::from_secs(60);

/// How long the desktop session may take to accept the request.
const SEND_LIMIT: Duration = Duration::from_secs(5);

/// The requests waiting for the desktop session, each with the connection
/// that carries it.
type Open = Arc<Mutex<HashMap<String, UnixStream>>>;

pub struct Host<W> {
    /// The extension that started this process, if it is the allowed one.
    caller: Option<Caller>,
    /// Where the desktop session listens, if this account has such a place.
    socket: Option<PathBuf>,
    out: Arc<Mutex<W>>,
    open: Open,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A thread that panicked while holding it left nothing half-written
    // that matters more than answering.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn send(out: &Mutex<impl Write>, response: &Response) {
    // If the browser is gone there is nobody to tell; reading standard
    // input ends the process.
    let _ = Prefix::Browser.write(&mut *lock(out), response);
}

impl<W: Write + Send + 'static> Host<W> {
    pub fn new(caller: Option<Caller>, out: W) -> Self {
        Self::at(caller, endpoint::socket_path(), out)
    }

    fn at(caller: Option<Caller>, socket: Option<PathBuf>, out: W) -> Self {
        Self {
            caller,
            socket,
            out: Arc::new(Mutex::new(out)),
            open: Open::default(),
        }
    }

    /// Takes one message from the extension.
    pub fn handle(&mut self, body: &[u8]) {
        match Request::read(body) {
            Ok(Request::FillRequest(request)) => {
                if let Err(code) = self.forward(&request) {
                    send(&self.out, &Response::refusal(&request.request_id, code));
                }
            }
            Ok(Request::Cancel(cancel)) => self.cancel(&cancel.request_id),
            Err(failure) => send(&self.out, &Response::Error(failure)),
        }
    }

    /// Passes a checked request to the desktop session and leaves a thread
    /// handing back what the session answers.
    fn forward(&self, request: &FillRequest) -> Result<(), Refusal> {
        let caller = self.caller.clone().ok_or(Refusal::ExtensionNotAllowed)?;
        let mut open = lock(&self.open);
        if open.contains_key(&request.request_id) {
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
        let forwarded = Forwarded {
            caller,
            request: request.clone(),
        };
        Prefix::Socket
            .write(&mut session, &forwarded)
            .map_err(unavailable)?;
        open.insert(
            request.request_id.clone(),
            session.try_clone().map_err(unavailable)?,
        );
        drop(open);

        let (request, out, open) = (request.clone(), self.out.clone(), self.open.clone());
        thread::spawn(move || relay(&request, session, &out, &open));
        Ok(())
    }

    /// Withdraws a request. Closing its connection is what tells the
    /// desktop session.
    fn cancel(&self, request_id: &str) {
        if let Some(session) = lock(&self.open).remove(request_id) {
            let _ = session.shutdown(Shutdown::Both);
        }
    }
}

/// Hands the desktop session's answers to one request back to the
/// extension, until the answer that ends it.
fn relay(request: &FillRequest, mut session: UnixStream, out: &Mutex<impl Write>, open: &Open) {
    loop {
        // Only what answers exactly this request is handed on. Anything
        // else, a closed connection, and a long silence all mean there is
        // no session to trust with it.
        let answer = match Prefix::Socket.read(&mut session) {
            Ok(Some(body)) => serde_json::from_slice::<Response>(&body)
                .ok()
                .filter(|response| response.answers(request)),
            _ => None,
        };
        // Held while answering, so that nothing but `cancelled` follows a
        // withdrawal.
        let mut open = lock(open);
        if !open.contains_key(&request.request_id) {
            send(
                out,
                &Response::refusal(&request.request_id, Refusal::Cancelled),
            );
            return;
        }
        let answer = answer.unwrap_or_else(|| {
            Response::Error(Failure::new(
                &request.request_id,
                Refusal::DesktopSessionUnavailable,
            ))
        });
        send(out, &answer);
        if answer.is_final() {
            open.remove(&request.request_id);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use osm_browser_link::CHROMIUM_EXTENSION_ID;
    use proptest::prelude::*;

    use super::*;

    /// Standard output, kept.
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);

    impl Write for Written {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            lock(&self.0).write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Written {
        fn responses(&self) -> Vec<Response> {
            let bytes = lock(&self.0).clone();
            let mut bytes = bytes.as_slice();
            let mut responses = Vec::new();
            while let Some(body) = Prefix::Browser.read(&mut bytes).unwrap() {
                responses.push(serde_json::from_slice(&body).unwrap());
            }
            responses
        }
    }

    fn allowed() -> Option<Caller> {
        Some(Caller::Chromium(format!(
            "chrome-extension://{CHROMIUM_EXTENSION_ID}/"
        )))
    }

    fn fill(request_id: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"fill_request","version":1,"requestId":"{request_id}","tabId":1,"frameId":0,"documentId":"d","origin":"{origin}"}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_request_that_cannot_be_passed_on_is_refused() {
        let written = Written::default();
        // No data folder, so nowhere a desktop session could listen.
        let mut host = Host::at(allowed(), None, written.clone());
        host.handle(b"not json");
        host.handle(br#"{"type":"unlock","version":1,"requestId":"a"}"#);
        host.handle(&fill("b", "http://example.test"));
        host.handle(&fill("c", "https://example.test"));
        // Withdrawing a request that is not waiting says nothing.
        host.handle(br#"{"type":"cancel","version":1,"requestId":"c"}"#);

        // Nothing listens at a path either.
        let mut host = Host::at(
            allowed(),
            Some("/nonexistent/browser.sock".into()),
            written.clone(),
        );
        host.handle(&fill("d", "https://example.test"));

        // Started by anything but the allowed extension, nothing is passed
        // on whether or not a session is there.
        let mut host = Host::at(
            None,
            Some("/nonexistent/browser.sock".into()),
            written.clone(),
        );
        host.handle(&fill("e", "https://example.test"));

        assert_eq!(
            written.responses(),
            [
                Response::Error(Failure::unnamed(Refusal::InvalidMessage)),
                Response::refusal("a", Refusal::UnsupportedMessage),
                Response::refusal("b", Refusal::OriginRejected),
                Response::refusal("c", Refusal::DesktopSessionUnavailable),
                Response::refusal("d", Refusal::DesktopSessionUnavailable),
                Response::refusal("e", Refusal::ExtensionNotAllowed),
            ]
        );
    }

    proptest! {
        /// Whatever the extension sends, the host answers each message at
        /// most once, and with nowhere to pass a request on, only with a
        /// refusal: never with anything a page could be filled with.
        #[test]
        fn the_host_answers_any_message_with_at_most_one_refusal(
            caller in prop_oneof![
                Just(allowed()),
                Just(None),
                Just(Some(Caller::Firefox("another@example.test".into()))),
            ],
            bodies in prop::collection::vec(
                prop_oneof![
                    prop::collection::vec(any::<u8>(), 0..120),
                    ("[a-zA-Z0-9-]{0,70}", ".{0,30}")
                        .prop_map(|(id, origin): (String, String)| fill(&id, &origin)),
                    "[a-zA-Z0-9-]{0,70}".prop_map(|id: String| {
                        format!(r#"{{"type":"cancel","version":1,"requestId":"{id}"}}"#).into_bytes()
                    }),
                ],
                1..6,
            ),
        ) {
            let written = Written::default();
            let mut host = Host::at(caller, None, written.clone());
            for body in &bodies {
                host.handle(body);
            }
            let responses = written.responses();
            prop_assert!(responses.len() <= bodies.len());
            for response in responses {
                prop_assert!(matches!(response, Response::Error(_)), "{response:?}");
            }
        }
    }
}
