# Native messaging host

This process owns only the browser framing boundary. It enforces the browser's
32-bit native-messaging length prefix, a 64 KiB frame limit, JSON shape, and
HTTPS exact-origin equality plus the per-document nonce and request ID. The
camelCase field names match the WebExtension protocol. It does not have ambient vault access. Until the
desktop supplies a session-bound authenticated IPC adapter, valid requests
return `desktop_session_unavailable` and no credential is emitted.

That fail-closed state is deliberate: registering a host that can read a vault
without a verified unlocked desktop session would turn every allowed web page
into a local secret oracle. The Tauri adapter must bind a one-use request ID,
the extension identity, current tab/frame, and exact origin before enabling
the fill response. Diagnostics stay off stdout because stdout is the framed
protocol.
