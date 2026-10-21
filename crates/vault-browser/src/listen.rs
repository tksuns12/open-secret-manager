use std::{
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use osm_browser_link::{
    endpoint,
    frame::{self, Body, Prefix},
    Forwarded, ForwardedCard, Refusal, Response, Waiting,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    task::JoinSet,
    time::{interval_at, sleep_until, timeout, Instant},
};
use zeroize::Zeroizing;

use crate::{broker::Asked, Desk};

/// How many connections are served at once. Each carries one request and
/// only one request waits at a time, so more than a few are never needed.
const MAX_CONNECTIONS: usize = 8;

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
                    conversations.spawn(async move { converse(stream, &desk).await });
                }
            }
            Some(_) = conversations.join_next() => {}
        }
    }
}

async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Body> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).await?;
    let mut body = Zeroizing::new(vec![0_u8; Prefix::Socket.length(prefix)?]);
    reader.read_exact(&mut body).await?;
    Ok(body)
}

async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    response: &Response,
    within: Duration,
) -> io::Result<()> {
    let framed = Prefix::Socket.frame(&frame::encode(response)?)?;
    timeout(within, async {
        writer.write_all(&framed).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

/// Whether the connection comes from the account this session runs as.
fn is_own_account(stream: &UnixStream) -> bool {
    stream
        .peer_cred()
        .is_ok_and(|peer| peer.uid() == endpoint::own_user())
}

async fn converse(mut stream: UnixStream, desk: &Desk) {
    if !is_own_account(&stream) {
        return;
    }
    let config = desk.config;
    // One request, promptly, or nothing: a connection that sends something
    // else is closed unanswered.
    let Ok(Ok(body)) = timeout(config.exchange_within, read_frame(&mut stream)).await else {
        return;
    };
    // A login's request, or a card's.
    let (caller, asked) = match serde_json::from_slice::<Forwarded>(&body) {
        Ok(Forwarded { caller, request }) => (caller, Asked::Login(request)),
        Err(_) => match serde_json::from_slice::<ForwardedCard>(&body) {
            Ok(ForwardedCard { caller, card }) => (caller, Asked::Card(card)),
            Err(_) => return,
        },
    };
    let request_id = asked.request_id().to_owned();
    let (ticket, deadline, mut answered) = match desk.submit(caller, asked) {
        Ok(taken) => taken,
        Err(failure) => {
            let refusal = Response::Error(failure);
            let _ = write_frame(&mut stream, &refusal, config.exchange_within).await;
            return;
        }
    };

    // However this ends, the request does not outlive its connection.
    let _withdraw = Withdraw(desk, ticket);

    let (mut reader, mut writer) = stream.split();
    let waiting = Response::Waiting(Waiting {
        request_id: request_id.clone(),
    });
    let mut reminders = interval_at(Instant::now() + config.remind_every, config.remind_every);
    let mut told = write_frame(&mut writer, &waiting, config.exchange_within).await;
    let mut unexpected = [0_u8; 1];
    let last = loop {
        if told.is_err() {
            break None;
        }
        tokio::select! {
            biased;
            // The owner decided, or the desk ended the request.
            decided = &mut answered => break decided.ok(),
            _ = sleep_until(Instant::from_std(deadline)) => {
                break Some(expired(desk, ticket, &request_id, &mut answered));
            }
            // Nothing more is expected on this connection. If it closes,
            // the request was withdrawn; if it sends more, it is not the
            // host. Either way it is told nothing further.
            _ = reader.read(&mut unexpected) => break None,
            _ = reminders.tick() => {
                told = write_frame(&mut writer, &waiting, config.exchange_within).await;
            }
        }
    };
    match last {
        Some(last) => {
            let _ = write_frame(&mut writer, &last, config.exchange_within).await;
        }
        // A decision the owner made at this very instant is not read from
        // `answered`: it is dropped with it, unsent.
        None => desk.withdraw(ticket),
    }
}

/// Withdraws a request when the connection that brought it is done.
struct Withdraw<'a>(&'a Desk, u64);

impl Drop for Withdraw<'_> {
    fn drop(&mut self) {
        self.0.withdraw(self.1);
    }
}

/// Ends a request whose time is up and says what its connection is told:
/// that it expired, unless the owner decided in the same instant, in which
/// case the decision stands.
fn expired(
    desk: &Desk,
    ticket: u64,
    request_id: &str,
    answered: &mut oneshot::Receiver<Response>,
) -> Response {
    desk.withdraw(ticket);
    // The desk answers and withdraws under one lock, so by now a decision
    // has either arrived or will never be made.
    answered
        .try_recv()
        .unwrap_or_else(|_| Response::refusal(request_id, Refusal::Expired))
}
