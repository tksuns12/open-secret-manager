//! Where the desktop session listens, and how the host finds it, on Windows.
//!
//! The session listens on a named pipe. Pipe names are shared by every
//! account on the machine, so the name is what keeps the pipe private: each
//! time the app starts it makes a new name nobody can guess, and writes it
//! to a file in the account's own data folder, which only this account (and
//! administrators) can read. The host reads the name from there. An account
//! that cannot read the file cannot create the pipe before the app does, or
//! pick the pipe out as the one to talk to. Any program running as the owner
//! can read the file and use the pipe, which is why the owner still confirms
//! every fill in the app.

use std::{
    fmt::Write,
    io,
    path::{Path, PathBuf},
};

/// The app's folder inside the account's data folder.
pub const APP_FOLDER: &str = "OpenSecretManager";

/// The file, inside the app's folder, that holds the current pipe's name.
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
    getrandom::fill(&mut random).map_err(io::Error::other)?;
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

/// The pipe the session in `file` listens on, if the file names one.
pub fn read_pipe_name(file: &Path) -> io::Result<String> {
    let name = std::fs::read_to_string(file)?;
    let name = name.trim_end();
    if is_pipe_name(name) {
        Ok(name.to_owned())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the file does not name a pipe of this app",
        ))
    }
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
    fn only_a_name_of_this_app_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let file = pipe_file_in(dir.path());
        assert_eq!(file.file_name().unwrap(), PIPE_FILE);
        assert_eq!(
            read_pipe_name(&file).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        let name = new_pipe_name().unwrap();
        for wrong in [
            String::new(),
            r"\\.\pipe\other".to_owned(),
            format!(r"\\remote\pipe\OpenSecretManager-{}", "0".repeat(32)),
            format!("{name}0"),
            name[..name.len() - 1].to_owned(),
            name.to_uppercase(),
            format!("{}g", &name[..name.len() - 1]),
        ] {
            std::fs::write(&file, &wrong).unwrap();
            assert_eq!(
                read_pipe_name(&file).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{wrong:?}"
            );
        }
        std::fs::write(&file, format!("{name}\r\n")).unwrap();
        assert_eq!(read_pipe_name(&file).unwrap(), name);
    }

    #[test]
    fn the_session_file_is_in_the_apps_data_folder() {
        let path = pipe_file_path().unwrap();
        assert!(path.ends_with(Path::new(APP_FOLDER).join(PIPE_FILE)));
        assert!(path.is_absolute());
    }
}
