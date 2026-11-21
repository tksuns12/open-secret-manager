//! The session's Unix socket: a file in the account's data folder, which
//! only connections from this account may use.

use std::{
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use osm_browser_link::endpoint;
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinSet,
};

use super::{converse, MAX_CONNECTIONS};
use crate::Desk;

/// Removes the socket's file when the session stops listening.
struct Unlink(PathBuf);

impl Drop for Unlink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The session's socket, bound and not yet served.
pub struct Bound {
    listener: std::os::unix::net::UnixListener,
    unlink: Unlink,
}

impl Bound {
    pub fn path(&self) -> &Path {
        &self.unlink.0
    }
}

/// Binds the session's socket at `path`. A socket left there by a session
/// that is gone is replaced; one that still answers is another running
/// session, and anything else in that place is left alone.
pub fn bind(path: &Path) -> io::Result<Bound> {
    if let Some(folder) = path.parent() {
        std::fs::create_dir_all(folder)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another session is listening",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "something other than a socket is in the socket's place",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    let unlink = Unlink(path.to_owned());
    // Who may connect is decided per connection, by its account. This only
    // keeps the file from looking like an invitation.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok(Bound { listener, unlink })
}

/// Serves the session's socket until dropped: each connection brings one
/// request to the desk and is told how it ended. Dropping it closes every
/// connection and removes the socket.
pub async fn serve(bound: Bound, desk: Arc<Desk>) -> io::Result<()> {
    let Bound { listener, unlink } = bound;
    let _unlink = unlink;
    let listener = UnixListener::from_std(listener)?;
    let mut conversations = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    // Out of file descriptors, most likely: let some close.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // Past the limit a connection is closed unanswered.
                if conversations.len() < MAX_CONNECTIONS {
                    let desk = desk.clone();
                    conversations.spawn(async move {
                        if is_own_account(&stream) {
                            converse(stream, &desk).await;
                        }
                    });
                }
            }
            Some(_) = conversations.join_next() => {}
        }
    }
}

/// Whether the connection comes from the account this session runs as.
fn is_own_account(stream: &UnixStream) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|peer| peer.uid() == endpoint::own_user())
}
