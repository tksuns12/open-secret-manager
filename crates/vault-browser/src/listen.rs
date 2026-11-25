use std::{io, time::Duration};

use osm_browser_link::{
    frame::{self, Body, Prefix},
    Forwarded, ForwardedCard, ForwardedPasskey, Refusal, Response, Waiting,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::oneshot,
    time::{interval_at, sleep_until, timeout, Instant},
};
use zeroize::Zeroizing;

use crate::{broker::Asked, Desk};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{bind, serve, Bound};
#[cfg(windows)]
pub use windows::{bind, serve, Bound};

/// How many connections are served at once. Each carries one request and
/// only one request waits at a time, so more than a few are never needed.
const MAX_CONNECTIONS: usize = 8;

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

pub(crate) async fn converse(mut stream: impl AsyncRead + AsyncWrite + Unpin, desk: &Desk) {
    let config = desk.config;
    // One request, promptly, or nothing: a connection that sends something
    // else is closed unanswered.
    let Ok(Ok(body)) = timeout(config.exchange_within, read_frame(&mut stream)).await else {
        return;
    };
    // A login's request, a card's, or a passkey's (strict duplicate-key rejection).
    let (caller, asked) =
        if let Ok(Forwarded { caller, request }) = osm_browser_link::read_strict(&body) {
            (caller, Asked::Login(request))
        } else if let Ok(ForwardedCard { caller, card }) = osm_browser_link::read_strict(&body) {
            (caller, Asked::Card(card))
        } else if let Ok(ForwardedPasskey {
            caller,
            ceremony,
            passkey,
        }) = osm_browser_link::read_strict(&body)
        {
            (caller, Asked::Passkey(ceremony, passkey))
        } else {
            return;
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

    let (mut reader, mut writer) = tokio::io::split(stream);
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
