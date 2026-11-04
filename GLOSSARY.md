# Open Secret Manager

A password manager whose vault lives on the owner's own devices, which sync with each other directly. These are the words for what the vault holds and for how it fills other apps and pages.

## Filling and saving

**Requester**:
Whoever asks the vault to fill a form or to save what a form sent, as the device's system names it: a page, an app, or no one named. Never what the asking app says of itself.
_Avoid_: caller, client, asker (for this concept)

**Page**:
A requester that the system vouches for by its origin: a trusted browser's page over https, or an address iOS names.
_Avoid_: site, web requester

**App**:
A requester known by what the system says of it (its package and signing certificate, or its App ID), with no origin a login's address could be checked against.
_Avoid_: application requester, package

**Offer**:
The logins a requester is shown for a form, which fill at once: for a page, those saved for its origin; for an app, its app choices.
_Avoid_: matches, candidates (for this concept)

**App choice**:
A login the owner chose for an app on the phone's own screen, which that app is offered from then on, on that phone only.
_Avoid_: remembered login, app login, binding

**Suggested login**:
A login saved for a site that the system verified names the app as its own: shown to the app apart from its offer, and its app choice only once the owner chooses it.
_Avoid_: linked login, match

**Save candidate**:
A login that what a form sent could be saved into: one the same form could be filled with, under the username it sent.
_Avoid_: update target
