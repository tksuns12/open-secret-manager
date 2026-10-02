# Native messaging host

This is the process a browser starts when the extension asks for a login to
be filled. It has no vault and no key, and it links none of the vault code.
It does three things:

- It reads the extension's messages from standard input in the browser's
  framing (a 32-bit length in the machine's byte order, then JSON), with a
  64 KiB limit. A frame of no length, of too much, or cut short ends the
  process without an answer.
- It checks each request: the protocol version, the form of the request and
  document IDs, that the request is for the page itself and not a frame
  inside it, and that the origin is an HTTPS origin exactly as a browser
  writes one. It answers only the one allowed extension of each browser,
  which the browser names on the command line.
- It passes a checked request to the desktop session over the session's
  socket and hands back only a response that answers that request: the same
  request ID and, for a login, the same tab, frame, document, and origin.

If no desktop session is listening, or what answers does not answer the
request, the extension gets `desktop_session_unavailable` and no login. The
owner chooses the login in the desktop app; the host never sees a list of
logins and has nothing to choose from.

Standard output carries only framed responses. The host writes no
diagnostics.

The messages and the socket are described in
[the format contract](../../docs/formats.md#implemented-fill-protocol-phase-5-stop-1).
`examples/org.opensecretmanager.native.json` shows the two kinds of entry a
manifest has: `allowed_origins` is what a Chromium browser reads and
`allowed_extensions` what Firefox reads. The desktop app's Browser panel
writes the manifest for a browser, with one of the two, when the owner
connects it.
