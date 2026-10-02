//! Where the desktop session listens, and how the host reaches it.
//!
//! The socket is a file in the app's data folder. What makes it a private
//! channel is the operating system account: the host connects only to a
//! socket that this account owns, and the desktop session answers only a
//! connection from this account. Any program running as the owner can use
//! it, which is why the owner still confirms every fill in the app.

use std::{
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};

/// The app's folder inside the account's data folder.
pub const APP_FOLDER: &str = "OpenSecretManager";

/// The socket's file name inside the app's folder.
pub const SOCKET_NAME: &str = "browser.sock";

/// The socket of the desktop session in an app folder.
pub fn socket_in(app_folder: &Path) -> PathBuf {
    app_folder.join(SOCKET_NAME)
}

/// The socket of this account's desktop session. `None` if the account has
/// no data folder.
pub fn socket_path() -> Option<PathBuf> {
    Some(socket_in(&dirs::data_dir()?.join(APP_FOLDER)))
}

/// The account this process runs as.
pub fn own_user() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Connects to the desktop session listening at `path`. Fails if nothing
/// listens there or if what is there is not a socket of this account.
pub fn connect(path: &Path) -> io::Result<UnixStream> {
    let found = std::fs::symlink_metadata(path)?;
    if !found.file_type().is_socket() || found.uid() != own_user() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a socket of this account",
        ));
    }
    UnixStream::connect(path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    /// A folder with a path short enough for a socket.
    fn folder() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("osm")
            .tempdir_in("/tmp")
            .unwrap()
    }

    #[test]
    fn the_host_connects_only_to_a_socket() {
        let dir = folder();
        let path = socket_in(dir.path());
        assert_eq!(path.file_name().unwrap(), SOCKET_NAME);

        // Nothing there.
        assert_eq!(connect(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
        // A file, and a link to a socket, are not the session's socket.
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            connect(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(&path).unwrap();
        let elsewhere = dir.path().join("other.sock");
        let listener = UnixListener::bind(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert_eq!(
            connect(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(&path).unwrap();
        drop(listener);

        // A socket nobody listens on any more.
        let listener = UnixListener::bind(&path).unwrap();
        drop(listener);
        assert_eq!(
            connect(&path).unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        std::fs::remove_file(&path).unwrap();

        let listener = UnixListener::bind(&path).unwrap();
        connect(&path).unwrap();
        listener.accept().unwrap();
        // The socket this process made belongs to the account it runs as.
        assert_eq!(std::fs::metadata(&path).unwrap().uid(), own_user());
    }

    #[test]
    fn the_session_socket_is_in_the_apps_data_folder() {
        let path = socket_path().unwrap();
        assert!(path.ends_with(Path::new(APP_FOLDER).join(SOCKET_NAME)));
        assert!(path.is_absolute());
    }
}
