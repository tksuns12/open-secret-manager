# Browser integration

The Chromium and Firefox manifests point to the same source modules. The
extension asks for a native-host fill only after an explicit context-menu
selection and a page prompt. The desktop host is expected to be unlocked and
to return a single origin-bound response.

The content script checks HTTPS, exact origin (scheme, host, and effective
port), a per-document nonce, and the current page again immediately before
assigning values. The alpha targets the top-level frame and rejects opaque or
cross-origin contexts. It never submits a form and never writes credentials to
extension storage.

The native host registration files live beside the host binary and must be
installed per-browser using the platform's documented native-messaging
location. An installer must substitute the absolute executable path; the
repository does not silently grant a broad local IPC endpoint.
