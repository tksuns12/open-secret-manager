//! A relay for a vault's devices, run by the owner on a machine their
//! devices can all reach: a rented server, or a computer at home with a port
//! forwarded to it. It passes bytes between devices that cannot reach each
//! other directly and can read none of them (see the relay module of
//! `osm-vault-peer`, and docs/reaching-devices.md).
//!
//! ```text
//! osm-relay <folder> <listen-addr> <public-addr>
//! ```
//!
//! `folder` keeps the relay's TLS identity (`relay.sqlite3`) and its token
//! (`token`), made on the first run; `listen-addr` is where it listens, such
//! as `[::]:47830`; `public-addr` is where devices reach it, as `host:port`.
//! It prints `RELAY-CODE <code>`, the code to enter on one device in the
//! desktop app, which the vault carries to the others, and then runs until
//! stopped. Removing `token` and starting it again makes a new token and a
//! new code, which the devices then need; the old code stops working.

use std::{io::Write, path::Path, process::ExitCode, sync::Arc};

use osm_vault_peer::{serve_relay, NoKeystore, PeerStore, RelayCode};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [folder, listen, public] = args.as_slice() else {
        eprintln!("usage: osm-relay <folder> <listen-addr> <public-addr>");
        return ExitCode::from(2);
    };
    match run(Path::new(folder), listen, public).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("osm-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(folder: &Path, listen: &str, public: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(folder)?;
    // Its TLS key is kept in the file, as on a device without a keystore:
    // the relay holds nothing of a vault, and the key only names it.
    let identity = PeerStore::open(folder.join("relay.sqlite3"), Arc::new(NoKeystore))?
        .transport_identity()?;
    let token = token(&folder.join("token"))?;
    let code = RelayCode::new(public, identity.pin(), *token)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("RELAY-CODE {}", code.encode()?.as_str());
    std::io::stdout().flush()?;
    serve_relay(listener, identity, *token).await?;
    Ok(())
}

/// The relay's token, made the first time and kept readable by its owner
/// only.
fn token(path: &Path) -> std::io::Result<Zeroizing<[u8; 32]>> {
    let mut token = Zeroizing::new([0u8; 32]);
    if let Ok(text) = std::fs::read_to_string(path) {
        let text = Zeroizing::new(text);
        let hex = text.trim();
        if hex.len() == 64 {
            for (index, byte) in token.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                    .map_err(|_| std::io::Error::other("the token file is not a token"))?;
            }
            return Ok(token);
        }
        return Err(std::io::Error::other("the token file is not a token"));
    }
    getrandom::fill(token.as_mut()).map_err(|_| std::io::Error::other("no randomness"))?;
    let hex: Zeroizing<String> =
        Zeroizing::new(token.iter().map(|byte| format!("{byte:02x}")).collect());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(hex.as_bytes())?;
    Ok(token)
}
