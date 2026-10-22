//! Development CLI that stands in for the desktop app's end of a browser
//! fill.
//!
//! It exists so that the native messaging host and the browser extension
//! can be exercised without the app's window; it is not the product
//! interface. The vault password is read from `OSM_PASSWORD`. Output lines
//! start with a keyword so scripts and tests can follow along:
//!
//! ```text
//! osm-fill create <vault>                                     CREATED
//! osm-fill add <vault> <title> <username> <password> <address>   ADDED <item>
//! osm-fill add-card <vault> <title> <cardholder> <number> <month> <year> <code>   ADDED <item>
//! osm-fill serve <vault> <socket|-> [first|deny|ask] [locked] [within=<seconds>]
//! ```
//!
//! `serve` listens on the socket (`-` is the one the app would use) until
//! `quit` or the end of stdin, and prints `LISTENING <socket>`. It plays
//! the owner: `first` fills each request with the first login offered and
//! denies a request that has none, `deny` denies every request, and `ask`,
//! the default, waits for a command. `locked` starts with the vault locked,
//! and `within` sets how long a request may wait.
//!
//! Each time a request arrives, and each time the vault locks or unlocks
//! under one, it prints `REQUEST <request> <origin> <browser>
//! <logins|locked>` and then `LOGIN <item> <title>` for every login
//! offered. A card's request prints `REQUEST <request> <origin> <browser>
//! <cards|locked> card <documents>`, then `FRAME <frame> <origin>
//! <field>,...` for each document it names and `CARD <item> <title>` for
//! every card offered;
//! `first` fills it with the first card. A page's request for a passkey
//! prints `REQUEST <request> <origin> <browser> <offered|locked> passkey
//! <create|get> <site> <verification>`, then for a sign-in `PASSKEY <item>
//! <credential> <user>` for each passkey the site takes, and for a new one
//! `LOGIN <item> <title>` for each login of the site it may go on; `first`
//! saves a new one as a new login and signs in with the first passkey, as
//! a verified owner. While the vault is unlocked, a sign-in it holds no
//! passkey for is answered `no_passkey` at once, as the app does. A request
//! that ends without this process deciding it prints `ENDED <request>`.
//! Commands on stdin, one per line:
//!
//! ```text
//! approve <item>        FILLED <request> <item>, or REFUSED <reason>
//! approve-card <item>   FILLED <request> <item>, or REFUSED <reason>
//! save-passkey [<item>] [unverified]   PASSKEY-SENT <request>, or REFUSED <reason>
//! sign-in <item> <credential> [unverified]   PASSKEY-SENT <request>, or REFUSED <reason>
//! use-browser           BROWSER <request>, or REFUSED not-pending
//! deny                  DENIED <request>, or REFUSED not-pending
//! lock                  LOCKED
//! unlock                UNLOCKED
//! quit
//! ```

use std::process::ExitCode;

#[cfg(unix)]
mod cli;

#[cfg(unix)]
fn main() -> ExitCode {
    cli::main()
}

/// The session is reached over a Unix socket, which this platform lacks.
#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("ERROR osm-fill needs Unix sockets");
    ExitCode::FAILURE
}
