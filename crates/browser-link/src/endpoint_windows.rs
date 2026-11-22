//! Where the desktop session listens, and how the host finds it, on Windows.
//!
//! The session listens on a named pipe. Pipe names are listed for every
//! account on the machine (`dir \\.\pipe\`), so a name is no secret, and
//! once the app has quit another account can make a pipe of the same name.
//! What keeps the link private is a second value, a secret, which the app
//! makes each time it starts and writes, with the pipe's name, to a file in
//! the account's own data folder, which only this account (and
//! administrators) can read. The secret never crosses the pipe: each side
//! proves it holds it (see [`crate::handshake`]), and the host sends nothing
//! to a pipe that cannot. A file left behind by an app that quit or crashed
//! names a pipe nobody trustworthy listens on, and is replaced at the next
//! start. Any program running as the owner can read the file and use the
//! pipe, which is why the owner still confirms every fill in the app.

use std::{
    fmt::Write,
    io,
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::handshake::{self, Secret};

/// The app's folder inside the account's data folder.
pub const APP_FOLDER: &str = "OpenSecretManager";

/// The file, inside the app's folder, that holds the current pipe's name
/// and secret.
pub const PIPE_FILE: &str = "browser.pipe";

/// What every pipe name starts with.
const PIPE_PREFIX: &str = r"\\.\pipe\OpenSecretManager-";

/// How many random bytes a pipe name carries.
const NAME_BYTES: usize = 16;

/// The file naming the pipe of the desktop session in an app folder.
pub fn pipe_file_in(app_folder: &Path) -> PathBuf {
    app_folder.join(PIPE_FILE)
}

/// The file naming the pipe of the desktop session in an app folder, under
/// the name the Unix socket's place has, so that callers need not tell the
/// two apart.
pub use self::pipe_file_in as socket_in;

/// The file naming the pipe of this account's desktop session, under the
/// name the Unix socket's place has. `None` if
/// the account has no data folder.
pub fn socket_path() -> Option<PathBuf> {
    pipe_file_path()
}

/// As [`socket_path`].
pub fn pipe_file_path() -> Option<PathBuf> {
    Some(pipe_file_in(&dirs::data_dir()?.join(APP_FOLDER)))
}

/// A pipe name nobody else has: `\\.\pipe\OpenSecretManager-` and 32 hex
/// digits from the system's random generator.
pub fn new_pipe_name() -> io::Result<String> {
    let mut random = [0_u8; NAME_BYTES];
    getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
    let mut name = String::from(PIPE_PREFIX);
    for byte in random {
        write!(name, "{byte:02x}").expect("writing to a string");
    }
    Ok(name)
}

/// Whether `name` is exactly a name [`new_pipe_name`] makes. The host
/// connects to nothing else, whatever the file says.
pub fn is_pipe_name(name: &str) -> bool {
    name.strip_prefix(PIPE_PREFIX).is_some_and(|digits| {
        digits.len() == NAME_BYTES * 2
            && digits
                .bytes()
                .all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(&digit))
    })
}

/// What the host needs to talk to the session: the pipe, and the secret
/// that proves the session is the app's.
pub struct Link {
    pub name: String,
    pub secret: Secret,
}

impl Link {
    /// A name and a secret nobody else has.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            name: new_pipe_name()?,
            secret: handshake::new_secret()?,
        })
    }

    /// Writes the link to `file`, whole or not at all: the host never reads
    /// half of it.
    pub fn write(&self, file: &Path) -> io::Result<()> {
        let text = Zeroizing::new(format!(
            "{}\n{}\n",
            self.name,
            &**handshake::secret_to_hex(&self.secret)
        ));
        // A name of its own, so that two copies starting together do not
        // write one file.
        let temp = file.with_extension(format!("pipe.{}.tmp", std::process::id()));
        std::fs::write(&temp, text.as_bytes())?;
        // Something that has the file open without letting it be replaced,
        // a virus scanner for one, lets go in a moment.
        let mut renamed = std::fs::rename(&temp, file);
        for _ in 0..20 {
            if renamed.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            renamed = std::fs::rename(&temp, file);
        }
        renamed.inspect_err(|_| {
            let _ = std::fs::remove_file(&temp);
        })
    }
}

/// The link the file at `file` holds: a pipe's name of this app, then its
/// secret, one to a line, and nothing else.
pub fn read_link(file: &Path) -> io::Result<Link> {
    let text = Zeroizing::new(std::fs::read_to_string(file)?);
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the file does not hold a link of this app",
        )
    };
    let mut lines = text.lines();
    let name = lines
        .next()
        .filter(|name| is_pipe_name(name))
        .ok_or_else(invalid)?;
    let secret = lines
        .next()
        .and_then(handshake::secret_from_hex)
        .ok_or_else(invalid)?;
    if lines.next().is_some() {
        return Err(invalid());
    }
    Ok(Link {
        name: name.to_owned(),
        secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_name_is_a_name_of_this_app_and_never_the_same_twice() {
        let first = new_pipe_name().unwrap();
        let second = new_pipe_name().unwrap();
        assert!(is_pipe_name(&first));
        assert_ne!(first, second);
        assert_eq!(first.len(), PIPE_PREFIX.len() + 32);
    }

    #[test]
    fn only_a_link_of_this_app_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let file = pipe_file_in(dir.path());
        assert_eq!(file.file_name().unwrap(), PIPE_FILE);
        assert_eq!(
            read_link(&file).err().unwrap().kind(),
            io::ErrorKind::NotFound
        );

        let link = Link::new().unwrap();
        let secret = &**handshake::secret_to_hex(&link.secret);
        let name = &link.name;
        for wrong in [
            String::new(),
            // The name alone, as an earlier version wrote it.
            name.clone(),
            format!("{name}\n"),
            format!("{}\n{secret}\n", r"\\.\pipe\other"),
            format!(
                "{}{}\n{secret}\n",
                r"\\remote\pipe\OpenSecretManager-",
                "0".repeat(32)
            ),
            format!("{name}0\n{secret}\n"),
            format!("{}\n{secret}\n", name.to_uppercase()),
            format!("{name}\n{}\n", &secret[1..]),
            format!("{name}\n{secret}\nmore\n"),
        ] {
            std::fs::write(&file, &wrong).unwrap();
            assert_eq!(
                read_link(&file).err().unwrap().kind(),
                io::ErrorKind::InvalidData,
                "{wrong:?}"
            );
        }
        link.write(&file).unwrap();
        let read = read_link(&file).unwrap();
        assert_eq!(read.name, link.name);
        assert_eq!(*read.secret, *link.secret);
        // A file written by Windows' own tools may have CRLF line ends.
        std::fs::write(&file, format!("{name}\r\n{secret}\r\n")).unwrap();
        assert_eq!(read_link(&file).unwrap().name, link.name);
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| entry
            .unwrap()
            .path()
            .extension()
            .is_none_or(|ext| ext != "tmp")));
    }

    #[test]
    fn the_session_file_is_in_the_apps_data_folder() {
        let path = pipe_file_path().unwrap();
        assert!(path.ends_with(Path::new(APP_FOLDER).join(PIPE_FILE)));
        assert!(path.is_absolute());
    }
}
