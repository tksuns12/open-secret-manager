use std::{
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use osm_browser_link::{
    endpoint,
    frame::{self, Prefix},
    Caller, Ceremony, Forwarded, ForwardedCard, ForwardedPasskey, PasskeyRequest, Refusal, Request,
    Response,
};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix::{Link, Open};
#[cfg(windows)]
use windows::{Link, Open};

/// How many requests may wait for the desktop session at once. The session
/// takes one at a time and refuses the rest itself; this only bounds what
/// the host holds open.
const MAX_OPEN: usize = 4;

/// How long the desktop session may stay silent. It says it is waiting for
/// the owner far more often than this, so a longer silence means it hung.
const SILENCE_LIMIT: Duration = Duration::from_secs(60);

/// How long the desktop session may take to accept the request.
const SEND_LIMIT: Duration = Duration::from_secs(5);

pub struct Host<W> {
    /// The extension that started this process, if it is the allowed one.
    caller: Option<Caller>,
    /// Where the desktop session listens, if this account has such a place:
    /// its socket, or on Windows the file that names its pipe.
    socket: Option<PathBuf>,
    out: Arc<Mutex<W>>,
    /// The requests waiting for the desktop session.
    open: Open,
    /// What the platform needs to reach the session. Nothing, on Unix.
    #[cfg_attr(unix, allow(dead_code))]
    link: Link,
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
            link: Link::new(),
        }
    }

    /// Takes one message from the extension.
    pub fn handle(&mut self, body: &[u8]) {
        match Request::read(body) {
            Ok(Request::FillRequest(request)) => {
                let request_id = request.request_id.clone();
                let forwarded = self.caller.clone().map(|caller| {
                    frame::encode(&Forwarded {
                        caller,
                        request: request.clone(),
                    })
                });
                self.pass_on(&request_id, forwarded, move |response| {
                    response.answers(&request)
                });
            }
            Ok(Request::CardRequest(card)) => {
                let request_id = card.request_id.clone();
                let forwarded = self.caller.clone().map(|caller| {
                    frame::encode(&ForwardedCard {
                        caller,
                        card: card.clone(),
                    })
                });
                self.pass_on(&request_id, forwarded, move |response| {
                    response.answers_card(&card)
                });
            }
            Ok(Request::PasskeyCreate(passkey)) => self.pass_on_passkey(Ceremony::Create, passkey),
            Ok(Request::PasskeyGet(passkey)) => self.pass_on_passkey(Ceremony::Get, passkey),
            Ok(Request::Cancel(cancel)) => self.cancel(&cancel.request_id),
            Err(failure) => send(&self.out, &Response::Error(failure)),
        }
    }

    /// Passes on a passkey's request, as a card's.
    fn pass_on_passkey(&self, ceremony: Ceremony, passkey: PasskeyRequest) {
        let request_id = passkey.request_id.clone();
        let forwarded = self.caller.clone().map(|caller| {
            frame::encode(&ForwardedPasskey {
                caller,
                ceremony,
                passkey: passkey.clone(),
            })
        });
        self.pass_on(&request_id, forwarded, move |response| {
            response.answers_passkey(&passkey)
        });
    }

    /// Passes on the encoded `forwarded` request, or tells the extension
    /// why not. `None`: the host was started by something other than the
    /// allowed extension.
    fn pass_on(
        &self,
        request_id: &str,
        forwarded: Option<std::io::Result<frame::Body>>,
        answers: impl Fn(&Response) -> bool + Send + 'static,
    ) {
        let outcome = match forwarded {
            None => Err(Refusal::ExtensionNotAllowed),
            Some(Err(_)) => Err(Refusal::InvalidMessage),
            Some(Ok(body)) => self.forward(request_id, &body, answers),
        };
        if let Err(code) = outcome {
            send(&self.out, &Response::refusal(request_id, code));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use osm_browser_link::{Failure, CHROMIUM_EXTENSION_ID};
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

    fn card(request_id: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"card_request","version":2,"requestId":"{request_id}","tabId":1,"topOrigin":"{origin}","frames":[{{"frameId":0,"documentId":"d","origin":"{origin}","fields":["number"]}}]}}"#
        )
        .into_bytes()
    }

    fn passkey(kind: &str, request_id: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{kind}","version":2,"requestId":"{request_id}","tabId":1,"origin":"{origin}","options":"{{}}"}}"#
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
        host.handle(&card("f", "https://example.test"));

        // A card's request is passed on as a login's is, and refused alike.
        let mut host = Host::at(
            allowed(),
            Some("/nonexistent/browser.sock".into()),
            written.clone(),
        );
        host.handle(&card("g", "https://example.test"));
        host.handle(&card("h", "http://example.test"));
        host.handle(
            &card("i", "https://example.test")
                .into_iter()
                .map(|byte| if byte == b'2' { b'1' } else { byte })
                .collect::<Vec<_>>(),
        );
        // And so is a passkey's.
        host.handle(&passkey("passkey_get", "j", "https://example.test"));
        host.handle(&passkey("passkey_create", "k", "http://example.test"));
        let mut host = Host::at(
            None,
            Some("/nonexistent/browser.sock".into()),
            written.clone(),
        );
        host.handle(&passkey("passkey_create", "l", "https://example.test"));

        assert_eq!(
            written.responses(),
            [
                Response::Error(Failure::unnamed(Refusal::InvalidMessage)),
                Response::refusal("a", Refusal::UnsupportedMessage),
                Response::refusal("b", Refusal::OriginRejected),
                Response::refusal("c", Refusal::DesktopSessionUnavailable),
                Response::refusal("d", Refusal::DesktopSessionUnavailable),
                Response::refusal("e", Refusal::ExtensionNotAllowed),
                Response::refusal("f", Refusal::ExtensionNotAllowed),
                Response::refusal("g", Refusal::DesktopSessionUnavailable),
                Response::refusal("h", Refusal::OriginRejected),
                Response::refusal("i", Refusal::UnsupportedVersion),
                Response::refusal("j", Refusal::DesktopSessionUnavailable),
                Response::refusal("k", Refusal::OriginRejected),
                Response::refusal("l", Refusal::ExtensionNotAllowed),
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
