//! The session's named pipe. Its name is made fresh each time the session
//! starts and written to a file in the account's data folder, which is what
//! keeps other accounts from finding it (see `osm_browser_link::endpoint`).

use std::{
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use osm_browser_link::endpoint;
use tokio::{net::windows::named_pipe::ServerOptions, task::JoinSet, time::sleep};

use super::{converse, MAX_CONNECTIONS};
use crate::Desk;

/// What Windows says when a pipe exists and no instance is free.
const ERROR_PIPE_BUSY: i32 = 231;

/// The session's pipe, named and not yet served.
pub struct Bound {
    name: String,
    file: PathBuf,
}

impl Bound {
    /// The file that names the pipe.
    pub fn path(&self) -> &Path {
        &self.file
    }

    /// The pipe's name, the one the file will hold.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Removes the file naming the pipe when the session stops listening, if it
/// still names this session's pipe.
struct Unlink {
    file: PathBuf,
    name: String,
}

impl Drop for Unlink {
    fn drop(&mut self) {
        if endpoint::read_pipe_name(&self.file).is_ok_and(|named| named == self.name) {
            let _ = std::fs::remove_file(&self.file);
        }
    }
}

/// Chooses the session's pipe, named by the file at `file`. The pipe itself
/// is made when the session is served. A file left by a session that is gone
/// is replaced; one that names a pipe that still answers is another running
/// session.
pub fn bind(file: &Path) -> io::Result<Bound> {
    if let Some(folder) = file.parent() {
        std::fs::create_dir_all(folder)?;
    }
    if let Ok(name) = endpoint::read_pipe_name(file) {
        match OpenOptions::new().read(true).write(true).open(&name) {
            Ok(_) => return Err(in_use()),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => return Err(in_use()),
            Err(_) => {}
        }
    }
    Ok(Bound {
        name: endpoint::new_pipe_name()?,
        file: file.to_owned(),
    })
}

fn in_use() -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, "another session is listening")
}

fn instance(name: &str) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    ServerOptions::new()
        .reject_remote_clients(true)
        .create(name)
}

/// Serves the session's pipe until dropped: each connection brings one
/// request to the desk and is told how it ended. Dropping it closes every
/// connection and removes the file that names the pipe.
pub async fn serve(bound: Bound, desk: Arc<Desk>) -> io::Result<()> {
    let Bound { name, file } = bound;
    // The first instance is made by this session or not at all: nobody can
    // have made the pipe first under a name only this session knows, and if
    // they did, this fails.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&name)?;
    // Only now can the host find it.
    std::fs::write(&file, &name)?;
    let _unlink = Unlink { file, name };
    let name = &_unlink.name;
    let mut conversations = JoinSet::new();
    loop {
        tokio::select! {
            connected = server.connect() => {
                // A pipe with no instance waiting refuses the next host, so
                // the next one is made before this one is served.
                let next = loop {
                    match instance(name) {
                        Ok(next) => break next,
                        // Out of handles, most likely: let some close.
                        Err(_) => sleep(Duration::from_millis(100)).await,
                    }
                };
                let stream = std::mem::replace(&mut server, next);
                // Past the limit a connection is closed unanswered.
                if connected.is_ok() && conversations.len() < MAX_CONNECTIONS {
                    let desk = desk.clone();
                    conversations.spawn(async move { converse(stream, &desk).await });
                }
            }
            Some(_) = conversations.join_next() => {}
        }
    }
}
