#![forbid(unsafe_code)]

//! The native messaging host: what a browser starts when the extension asks
//! for a login to be filled.
//!
//! It holds no vault and no key. It reads the extension's requests from
//! standard input, checks each one, and passes a fill request to the
//! desktop session over the session's socket; the session's answers go back
//! to the extension on standard output once they are checked against the
//! request. Without a desktop session there is nothing to pass a request
//! to, and the answer is `desktop_session_unavailable`.
//!
//! The session is reached over a Unix socket, or on Windows a named pipe.

use std::{io, process::ExitCode};

use osm_browser_link::{frame::Prefix, Caller};

mod host;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // The browser names the extension that asked for the host. Only the one
    // allowed extension gets further than a refusal.
    let caller = Caller::from_args(&arguments).filter(Caller::is_allowed);
    let mut host = host::Host::new(caller, io::stdout());
    let mut input = io::stdin().lock();
    loop {
        match Prefix::Browser.read(&mut input) {
            Ok(Some(body)) => host.handle(&body),
            // The browser closed the port. Requests still waiting end with
            // this process: the desktop session sees their connections close.
            Ok(None) => return ExitCode::SUCCESS,
            // After a frame of a refused length, or half a frame, there is
            // no telling where the next one starts.
            Err(_) => return ExitCode::FAILURE,
        }
    }
}
