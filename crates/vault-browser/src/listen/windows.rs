//! The session's named pipe. Its name and a secret are made fresh each time
//! the session starts and written to a file in the account's data folder.
//! The name can be seen by any account, so a connection is served only once
//! the host has proved it holds the secret too (see
//! `osm_browser_link::handshake` and `osm_browser_link::endpoint`).

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use osm_browser_link::{
    endpoint::{self, Link},
    handshake,
};
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeServer},
    runtime::Builder,
    task::JoinSet,
    time::{sleep, timeout},
};

use super::{converse, MAX_CONNECTIONS};
use crate::Desk;

/// How long a connection has to prove it holds the secret before it is
/// closed unanswered.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(2);

/// Win32 `ERROR_PIPE_BUSY`: all pipe instances are busy; wait briefly and retry.
const ERROR_PIPE_BUSY: i32 = 231;

/// Maximum consecutive errors when creating a replacement pipe instance before
/// `serve` gives up rather than spinning forever.
const MAX_CONSECUTIVE_INSTANCE_ERRORS: usize = 50;

/// The session's pipe, named and not yet served.
pub struct Bound {
    link: Link,
    file: PathBuf,
}

impl Bound {
    /// The file that names the pipe.
    pub fn path(&self) -> &Path {
        &self.file
    }

    /// The pipe's name, the one the file will hold.
    pub fn name(&self) -> &str {
        &self.link.name
    }
}

/// Removes the file naming the pipe when the session stops listening, if it
/// still names this session's pipe. A session that is killed does not get
/// to: the file it leaves is replaced at the next start, and until then
/// names a pipe the host will not send anything to unless it holds the
/// secret.
struct Unlink {
    file: PathBuf,
    name: String,
}

impl Drop for Unlink {
    fn drop(&mut self) {
        if endpoint::read_link(&self.file).is_ok_and(|link| link.name == self.name) {
            let _ = std::fs::remove_file(&self.file);
        }
    }
}

/// Whether a session answers on `link` as this app's: the pipe is there and
/// proves it holds the secret. Anything else, a pipe made by another
/// account included, is not a session of this app.
fn answers(link: Link) -> bool {
    let (tell, told) = std::sync::mpsc::channel();
    // Its own thread and runtime, as this is called outside any.
    std::thread::spawn(move || {
        let proved = Builder::new_current_thread()
            .enable_all()
            .build()
            .is_ok_and(|runtime| {
                runtime.block_on(async {
                    matches!(
                        timeout(HANDSHAKE_LIMIT, async {
                            let mut pipe = loop {
                                match ClientOptions::new().open(&link.name) {
                                    Ok(pipe) => break pipe,
                                    Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                                        sleep(Duration::from_millis(25)).await;
                                    }
                                    Err(error) => return Err(error),
                                }
                            };
                            handshake::as_host(&mut pipe, &link.name, &link.secret).await
                        })
                        .await,
                        Ok(Ok(()))
                    )
                })
            });
        let _ = tell.send(proved);
    });
    told.recv_timeout(HANDSHAKE_LIMIT * 2).unwrap_or(false)
}

/// Chooses the session's pipe, named by the file at `file`. The pipe itself
/// is made when the session is served. A file left by a session that is gone
/// is replaced, and so is one that names a pipe somebody else made; only one
/// that names a pipe that proves it is this app's is another running
/// session.
pub fn bind(file: &Path) -> io::Result<Bound> {
    if let Some(folder) = file.parent() {
        std::fs::create_dir_all(folder)?;
    }
    if endpoint::read_link(file).is_ok_and(answers) {
        return Err(in_use());
    }
    Ok(Bound {
        link: Link::new()?,
        file: file.to_owned(),
    })
}

fn in_use() -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, "another session is listening")
}

fn instance(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    osm_win_pipe_acl::create_owner_only_pipe(name, first)
}

/// Serves the session's pipe until dropped: each connection brings one
/// request to the desk and is told how it ended. Dropping it closes every
/// connection and removes the file that names the pipe.
pub async fn serve(bound: Bound, desk: Arc<Desk>) -> io::Result<()> {
    let Bound { link, file } = bound;
    let Link { name, secret } = link;
    // The first instance is made by this session with an owner-only SID DACL
    // or not at all: if somebody made the pipe first under this name, this fails.
    let mut server = instance(&name, true)?;
    // Only now can the host find it.
    Link {
        name: name.clone(),
        secret: secret.clone(),
    }
    .write(&file)?;
    let _unlink = Unlink {
        file,
        name: name.clone(),
    };
    let (name, secret) = (Arc::<str>::from(name), Arc::new(secret));
    let mut conversations = JoinSet::new();
    loop {
        tokio::select! {
            connected = server.connect() => {
                // A pipe with no instance waiting refuses the next host, so
                // the next one is made before this one is served.
                let mut errors = 0usize;
                let next = loop {
                    match instance(&name, false) {
                        Ok(next) => break next,
                        Err(error) => {
                            errors += 1;
                            if errors >= MAX_CONSECUTIVE_INSTANCE_ERRORS {
                                return Err(error);
                            }
                            let backoff_ms = 50_u64.saturating_mul(errors as u64).min(500);
                            sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                };
                let mut stream = std::mem::replace(&mut server, next);
                // Past the limit a connection is closed unanswered.
                if connected.is_ok() && conversations.len() < MAX_CONNECTIONS {
                    let (desk, name, secret) = (desk.clone(), name.clone(), secret.clone());
                    conversations.spawn(async move {
                        // Any account can open the pipe; only a host that
                        // holds the secret gets to send a request.
                        let proved = matches!(
                            timeout(
                                HANDSHAKE_LIMIT,
                                handshake::as_session(&mut stream, &name, &secret),
                            )
                            .await,
                            Ok(Ok(()))
                        );
                        if proved {
                            converse(stream, &desk).await;
                        }
                    });
                }
            }
            Some(_) = conversations.join_next() => {}
        }
    }
}
