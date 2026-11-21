# The browser link on Windows is a named pipe, and a secret in a file that both ends prove they hold

Status: accepted, 2026-11-21; amended the same day after review (see below). Not yet exercised with a real browser.

## Context

On macOS and Linux the desktop session listens on a Unix socket that is a
file in the account's data folder. The host connects only to a socket owned
by its own account, and the session answers only a connection whose peer is
that account. The operating system enforces both.

Windows has no such file. Named pipes live in one namespace shared by every
account, so any account can create `\\.\pipe\<name>` before the app does,
and the host that connects to it would be talking to that account.

## Options

- **Owner-only access list on the pipe, and a check that the pipe's server
  runs as this account.** The Windows way, but the Rust bindings for both
  (`SECURITY_ATTRIBUTES`, token and process queries) are `unsafe`, and the
  project forbids `unsafe` in its own code. Doing it means an exception to
  that rule, in a small crate of its own.
- **Loopback TCP with a shared secret in a file.** No `unsafe`, but a secret
  sent to whatever listens on the port, which is the habit this project has
  avoided.
- **A pipe whose name is the secret.** The app makes a new random name each
  time it starts and writes it to a file in the account's data folder, and
  the host connects to that name. *This was the first decision, and review
  found it wrong:* pipe names are listed by `dir \\.\pipe\` for every
  account, so a name is not a secret. While the app runs, nobody can make
  the pipe first; once it has quit (or been killed, which leaves the file
  behind) the name is free, and an account that had read it from the list
  can make a pipe of that name that the host connects to and sends its
  requests to, and whose replies it believes.
- **A pipe, and a secret in the file that both ends prove they hold.** The
  one chosen.

## Decision

The last. The app makes, each time it starts, a random pipe name and a
random 32-byte secret, and writes both to a file in the account's data
folder, which only the account (and administrators, who can do anything
anyway) can read. The secret never crosses the pipe. Before anything else,
the host sends a random number; the session answers with its own number and
an HMAC-SHA-256 of both numbers and the pipe's name under the secret; the
host checks it, and only then sends its own proof and, after it, the
request. A pipe that cannot prove it holds the secret has been sent one
random number and nothing else, and its replies are never read. The session
in turn serves only a connection whose host proves the same. The two proofs
carry different labels, so one cannot be played back as the other.

The pipe is also made as its first instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`)
and with remote clients rejected, the file is written, whole or not at all,
only after the pipe exists, and the host connects to nothing that is not a
name of exactly the app's form, with the connection's impersonation level
left at its default of identification. The file is removed when the session
stops listening; one left behind by a session that was killed names a pipe
that cannot prove it is the app's, and is replaced at the next start (the
start also does not mistake an impostor's pipe for a copy of the app that is
already running).

This is the same shape as the Unix design (a capability in a file in the
owner's folder), with the secret taking the place of the socket's owner.

## What it does not give

- Windows' default access list on the pipe lets other accounts open it. They
  can see its name, and they can hold connections open without the secret.
  The session closes a connection that has not proved the secret within two
  seconds, but it serves at most eight at once, so another account that
  keeps eight open can stop fills from reaching the app, which then says
  nothing: the host reports that the desktop session is unavailable. It
  cannot read a request or send one. A pipe closed to other accounts needs
  an access list, which is `unsafe` to set, and is the first option and its
  exception, in its own decision.
- Any program running as the owner can read the file and use the pipe, as
  any program running as the owner can use the Unix socket. The owner still
  confirms every fill in the app.
- The secret is as private as the account's data folder. If that folder is
  redirected to a share, the share's permissions are what protect it.

## Verification

GitHub's Windows runner runs the pipe's tests, tests of the proof (a pipe
made under the file's name by something that does not hold the secret is
sent a random number and no request, and does not stop the next session from
starting), and a test that starts the host as a process and fills through
the real desk. It is one account with administrator rights, so it cannot show
that another account is refused or that it cannot open the pipe, and it does
not start a browser. None of that has been checked on Windows.
