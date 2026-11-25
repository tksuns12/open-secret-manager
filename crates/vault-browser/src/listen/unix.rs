//! The session's Unix socket: a file in the account's data folder, which
//! only connections from this account may use.

use std::{
    fs::DirBuilder,
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
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
/// session, and anything else in that place is left alone. The socket is
/// bound to a short random sibling, tightened to `0o600`, and atomically
/// renamed into place so no world-accessible window exists.
pub fn bind(path: &Path) -> io::Result<Bound> {
    let own = endpoint::own_user();
    let folder = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path has no parent directory",
        )
    })?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)?;
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))?;
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => {
            if found.uid() != own {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "existing socket is owned by another account",
                ));
            }
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
    let mut suffix = [0_u8; 4];
    getrandom::fill(&mut suffix).map_err(|error| io::Error::other(error.to_string()))?;
    let tmp_name = format!(
        ".b-{:02x}{:02x}{:02x}{:02x}.sock",
        suffix[0], suffix[1], suffix[2], suffix[3]
    );
    let tmp = folder.join(tmp_name);
    let listener = std::os::unix::net::UnixListener::bind(&tmp)?;
    if let Err(error) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .and_then(|()| std::fs::rename(&tmp, path))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    let unlink = Unlink(path.to_owned());
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
