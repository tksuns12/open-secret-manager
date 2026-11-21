# The browser link on Windows is a named pipe whose name is the secret

Status: accepted, 2026-11-21. Not yet exercised with a real browser.

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
  time it starts and writes it to a file in the account's data folder. The
  host reads the name from that file, and connects to nothing that is not a
  name of exactly that form.

## Decision

The third. The data folder is readable only by the account (and
administrators, who can do anything anyway), so an account that cannot read
the file cannot create the pipe first, because it does not know the name,
and cannot pick the pipe out among the others. The pipe is made with
`FILE_FLAG_FIRST_PIPE_INSTANCE`, with remote clients rejected, and with
Windows' default access list, under which other accounts have read access
and cannot make further instances. The file is written only after the pipe
exists, and removed when the session stops.

This is the same shape as the Unix design (a capability in a file in the
owner's folder), with the name taking the place of the socket's owner.

## What it does not give

- The pipe's names are listed by `dir \\.\pipe\`, so another account can see
  the name while the app runs. It can then open the pipe read-only, which
  carries no request, and hold one of the eight connections for a moment.
  It cannot send a request or make a pipe with that name. If this matters,
  the answer is the first option and its `unsafe` exception, in its own
  decision.
- Any program running as the owner can read the file and use the pipe, as
  any program running as the owner can use the Unix socket. The owner still
  confirms every fill in the app.

## Verification

GitHub's Windows runner runs the pipe's tests and a test that starts the
host as a process and fills through the real desk. It is one account with
administrator rights, so it cannot show that another account is refused, and
it does not start a browser. Neither has been checked on Windows.
