# Security

Open Secret Manager holds passwords, so a weakness in it matters more than
most bugs. Please report one privately first, not in a public issue.

## Reporting a weakness

Use GitHub's private reporting: the repository's **Security** tab, then
**Report a vulnerability**. Only the maintainer sees the report. Say what
an attacker can do, what they need for it (a stolen file, a place on the
network, a web page the owner visits, an app on the phone), and how to see
it happen, with the version or commit.

The project is run by one person, in their own time. A report is answered
as soon as it can be, and a fix is made in public once it is ready, with
credit to the reporter unless they would rather not.

## What counts

Anything that breaks what [the threat model](docs/threat-model.md) says the
design protects against, for example:

- reading a vault's or a backup's contents without its password or
  recovery key;
- a device, or anyone on the network, that was never enrolled getting
  plaintext, or a device that was removed getting later keys;
- a change to an item or to the vault's devices that is accepted without
  being noticed, from a peer, a relay, or someone who can write the vault's
  file, beyond the rollback the threat model already names;
- a page or an app being filled, or told of, a login it should not get: a
  page another origin's, an app one its owner did not choose for it;
- the browser extension, the native host, or the phone apps' fill and save
  screens doing what the owner did not ask.

Its [limits](docs/threat-model.md#limits-that-must-remain-explicit) and
the [remaining risks](docs/release.md#remaining-risks) are known and
published: an unlocked device under someone else's control, for one, is
outside what the design protects. A report that one of them is worse than
the documents say is still welcome.

## Versions

Only the newest release, and the main branch, are fixed. Nobody outside the
project has reviewed it yet ([review-packet.md](docs/review-packet.md) is
the request); reviewing it is welcome.
