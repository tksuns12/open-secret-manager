//! A relay for a vault's devices, run by the owner on a machine their
//! devices can all reach: a rented server, or a computer at home with a port
//! forwarded to it. It passes bytes between devices that cannot reach each
//! other directly and can read none of them (see the relay module of
//! `osm-vault-peer`, and docs/reaching-devices.md).
//!
//! ```text
//! osm-relay [--print-code] <folder> <listen-addr> <public-addr>
//! ```
//!
//! `folder` keeps the relay's TLS identity (`relay.sqlite3`) and its token
//! (`token`), made on the first run; `listen-addr` is where it listens, such
//! as `[::]:47830`; `public-addr` is where devices reach it, as `host:port`.
//! It prints `RELAY-CODE <code>` on the first run (when `token` is created)
//! or when `--print-code` is explicitly passed, so daemon restarts do not
//! repeatedly write the bearer token into logs. Removing `token` and starting
//! it again makes a new token and a new code, which the devices then need;
//! the old code stops working.

use std::{
    io::{ErrorKind, Write},
    path::Path,
    process::ExitCode,
    sync::Arc,
};

use osm_vault_peer::{serve_relay, NoKeystore, PeerStore, RelayCode};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (print_code, positional) = match args.first().map(String::as_str) {
        Some("--print-code") => (true, &args[1..]),
        _ => (false, args.as_slice()),
    };
    let [folder, listen, public] = positional else {
        eprintln!("usage: osm-relay [--print-code] <folder> <listen-addr> <public-addr>");
        return ExitCode::from(2);
    };
    match run(Path::new(folder), listen, public, print_code).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("osm-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(
    folder: &Path,
    listen: &str,
    public: &str,
    print_code: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_private_dir(folder)?;
    // Its TLS key is kept in the file, as on a device without a keystore:
    // the relay holds nothing of a vault, and the key only names it.
    let identity = PeerStore::open(folder.join("relay.sqlite3"), Arc::new(NoKeystore))?
        .transport_identity()?;
    let (token, created) = token(&folder.join("token"))?;
    let code = RelayCode::new(public, identity.pin(), *token)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    if created || print_code {
        println!("RELAY-CODE {}", code.encode()?.as_str());
        std::io::stdout().flush()?;
    } else {
        eprintln!("osm-relay: listening on {listen}");
    }
    serve_relay(listener, identity, *token).await?;
    Ok(())
}

fn ensure_private_dir(folder: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(folder)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The relay's token, made the first time and kept readable by its owner
/// only. Returns `(token, created)`.
fn token(path: &Path) -> std::io::Result<(Zeroizing<[u8; 32]>, bool)> {
    let mut token = Zeroizing::new([0u8; 32]);
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = Zeroizing::new(text);
            let hex = text.trim();
            if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "the token file is not a token",
                ));
            }
            for (index, byte) in token.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| {
                    std::io::Error::new(ErrorKind::InvalidData, "the token file is not a token")
                })?;
            }
            return Ok((token, false));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) if error.kind() == ErrorKind::InvalidData => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "the token file is not a token",
            ));
        }
        Err(error) => return Err(error),
    }
    getrandom::fill(token.as_mut()).map_err(|_| std::io::Error::other("no randomness"))?;
    let hex: Zeroizing<String> =
        Zeroizing::new(token.iter().map(|byte| format!("{byte:02x}")).collect());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(hex.as_bytes())?;
    Ok((token, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ascii_64_byte_token_file_errors_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        // 32 two-byte UTF-8 characters = 64 bytes, not valid hex.
        std::fs::write(&path, "é".repeat(32)).unwrap();
        let err = token(&path).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // Invalid UTF-8 bytes also return InvalidData without trying to overwrite.
        std::fs::write(&path, [0xff_u8; 64]).unwrap();
        let err = token(&path).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn token_reports_created_on_first_run_and_existing_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let (first, created_first) = token(&path).unwrap();
        assert!(created_first);
        let (second, created_second) = token(&path).unwrap();
        assert!(!created_second);
        assert_eq!(*first, *second);
    }
}
