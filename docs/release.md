# Release

What a release of Open Secret Manager is, where it runs, what risks remain
in it, and how a package is built and checked. This page is the published
statement of the supported configurations and the remaining risks; the
evidence behind each statement is in
[implementation-status.md](implementation-status.md).

## What the first release is

Version 0.1.0 of the desktop app, for macOS (and as a Linux package not yet
tried on a Linux desktop), with the browser extension for Chromium-based
browsers and Firefox; and version 0.1.0 of the Android app. It has not been
reviewed by anyone outside the project ([review-packet.md](review-packet.md)
is the request), and it must not be described as audited. Each platform's
release is tagged on its own: `desktop-v0.1.0`, `android-v0.1.0`.

The project joins no app store's or platform vendor's paid program, so that
nothing it publishes depends on one. The macOS app is therefore not
notarized: macOS refuses a downloaded copy until the owner chooses Open
Anyway in System Settings › Privacy & Security. iOS has no release: whoever
wants the app builds it with an Apple developer team of their own
([phone-trial.md](phone-trial.md#getting-the-app-onto-the-phone)). The
Android app is published on GitHub and through F-Droid, which builds it from
this repository ([F-Droid](#f-droid)).

There is no updater in the app. An update is a new package, downloaded and
installed over the old one. Vaults written by this release (vault format 7,
backup format 4) are read by every later release; older formats from
before the release are upgraded when opened.

## Supported configurations

| Configuration | Status |
| --- | --- |
| macOS 26 on Apple Silicon | **Supported.** Built, tested, and run on macOS 26.6.2 (arm64). |
| macOS 14 and 15 on Apple Silicon | The app installs (its minimum is macOS 14), but it was not run on them. |
| macOS on Intel | Not built. |
| Linux, x86_64 (`.deb`) | **Built, not verified.** Made in a container from Ubuntu 22.04, so it needs no newer system libraries than 22.04 has. No Linux desktop has run it. Locking when the computer sleeps or the screen locks, and keeping copied codes out of clipboard history, exist on macOS and, since Phase 10, on Linux (through logind and the clipboard's password-manager hint), where they were tried in a container against a stand-in for logind, not on a Linux desktop. Under Wayland, copies are made through the compositor's data-control protocol where it offers one, as wlroots compositors do (Sway was tried in a container); elsewhere, as on GNOME, they go through Xwayland, untried. |
| Linux, arm64 | The packaging script builds it on request; not built for the release. A build of the Phase 9 code ran in an Ubuntu 22.04 container under a virtual display with a window manager: a vault made, a login added, Firefox 157 connected and filled through its extension. Not a desktop session (no GNOME or KDE), and the same limits as x86_64. |
| Windows | **Not supported.** The app was never built for Windows, and its browser fill does not exist there. |
| Android (9 and later, 64-bit ARM) | **Released as 0.1.0**, on GitHub and, once it is accepted there, F-Droid. The release build, shrunk and signed as it ships, joined a desktop-side device and synced on an Android 16 emulator; the owner's Galaxy S23 Ultra runs it since 2026-10-14, after a debug build there since 2026-10-12, and no other phone has ([phone-trial.md](phone-trial.md) is what is left). It is signed with the owner's key, certificate SHA-256 `17:26:C7:48:A0:13:35:9D:39:E8:81:18:23:05:19:F0:86:8A:E8:05:EC:1F:9D:86:E2:8C:B5:D5:47:0F:B9:E2`. Other kinds of phone refuse to install it. Passkeys need Android 14 or later (Phase 18); before 14 everything else works, and the phone offers none. |
| iOS (17 and later, iPhone) | **No release.** Built for iPhones unsigned; tested only in iOS simulators (iOS 26.5 most recently). Running it on any iPhone needs an Apple developer team; the project joins no paid program, so whoever wants it builds it with their own. Inserting an item's field as text, a card's number for one, needs iOS 18 or later (Phase 17). |
| Browsers | Chromium-based browsers and Firefox 128 or later (for passkeys, since Phase 18), tested headless (Chrome for Testing 153, Firefox 157; passkeys in Playwright's Chromium and Firefox 158). The extension was submitted to Firefox's add-ons site and the Chrome Web Store on 2026-11-16; until each accepts it, it loads unpacked in Chromium and as a temporary add-on in Firefox. The Chrome Web Store's copy has an ID of its own, which the desktop app accepts from 0.1.1 on. |
| Networks | Devices reach each other directly by address: on a network they share, over a VPN such as Tailscale, or at an open IPv6 address. An invitation names up to four of the inviter's addresses, and each device tells the others its own whenever they connect, so devices that have synced once on a network they share reach each other afterwards over a VPN they both use. Across real networks this was tried only with the owner's Android phone on its mobile network and this Mac at home, over Tailscale. Where nothing can be reached directly, the app can use a relay the owner runs (`osm-relay`), which passes the devices' own encrypted connections along; it was tried on this Mac and in a container, never on a server. There is no discovery, hole punching, or port mapping. |
| Devices in a vault | Tested with up to four. With two, both must be online to add or remove a device; with three or more, one can be away. |

## Remaining risks

These are the risks we know of and publish. Each one is described with its
evidence in the delivery matrix and the threat model.

**Review and packaging**
- No outside review of the design or the code.
- The macOS app is signed ad hoc and not notarized: macOS refuses a
  downloaded copy unless the owner overrides it, and nothing but the file
  system guards the app's files, the native host inside it included.
- 603 crates and two sets of npm packages are trusted without review of
  what their code does. Their advisories and licenses are checked.

**On a device**
- While a vault is unlocked, whoever controls that device (an
  administrator, a debugger, malware, the operating system) can read it.
  Copies of secrets in the window's JavaScript cannot be wiped.
- Rows taken out of a vault file, or an item set back inside it, are found
  at the next unlock and reported. On the computer, so is the whole file
  set back to an earlier copy, from a count kept in the Keychain or the
  Secret Service; not when the copy differs only by writes that add no
  item version, device, or key (a password change, for one), nor when the
  keystore was set back with it, as restoring the whole home folder does.
  On Linux without a Secret Service, and on the phones, a file set back is
  not found.
- The vault locks after five minutes without input and when its window is
  hidden; on macOS and Linux also on sleep, screen lock, and user switch.
  Those last locks were checked through the code (on Linux also in a
  container with a stand-in for logind), not with a real sleep or lock. A
  computer can go to sleep before a vault operation in progress finishes,
  and the vault then locks on waking.
- A copied one-time code stays on the clipboard for up to 30 seconds. On
  macOS and Linux it is marked for clipboard history apps to leave out,
  which only apps that honor the mark do: on Linux, KDE's Klipper does, and
  CopyQ 6, the version Ubuntu 22.04 ships, keeps it.

**Between devices**
- A device that was lost keeps everything it had. Removing it, starting
  over, or restoring a backup stops it from receiving anything new; it does
  not take back what it read.
- A vault with two voting devices cannot remove one that is lost; it starts
  over as a new vault instead. A device invited without a vote can always
  be removed by the voting ones.
- A vault's only voting device cannot be removed, also not by a device
  without a vote. To retire it, invite another computer that votes first,
  or start over as a new vault.
- Devices on builds from before 2026-10-13 sync with each other, and so do
  devices on later builds, but not one kind with the other: the way they
  compare what they hold changed. Update every device of a vault together.
  Until then the sync status says the other device runs a version that
  cannot sync with this one; adding and removing devices still works.
- A locked device that holds received revisions a peer lacks cannot send
  them before it has checked them, so the bucket they are in differs at
  every sync until it is unlocked, and the IDs of that bucket are sent each
  time.
- A sync session ends when nothing has moved for a minute. Processing many
  received revisions at once, as at the first unlock after a long time
  locked, can take that long; the next session goes on from what was done.
- The membership control plane tolerates crashes and partitions, not a
  malicious member. Whoever copies a device's transport key and control
  database can act as that device in it and stall changes; keys and
  authority still follow signed enrollment.
- The prompt on a device left behind by a recovery rests on an
  unauthenticated observation and does not always appear.

**Browser fill**
- A login is filled only into the exact origin of its stored address, over
  HTTPS, after the owner picks it in the app. Forms inside shadow roots are
  not found. Two-step and unusual forms may need the owner to finish by
  hand. The extension is unpublished, so its ID in Chromium is the
  development one.

**Backups and recovery**
- A backup is as old as the moment it was made, and holds every item's
  history, earlier versions of deleted items included. Whoever has the
  recovery key and a backup has the vault as it was then.
- The computer reminds the owner to back up 30 days after the latest
  backup from any device of the vault, or the day after it began counting
  for a vault never backed up; the reminder cannot be put off, only
  answered with a backup. The phones neither save backups nor remind.

## How to verify a download

Each release folder has `SHA256SUMS`, `app-contents.sha256`, and
`build-info.txt` beside the disk image.

1. Check the image against its sum:
   `shasum -a 256 -c SHA256SUMS`.
2. For a signed release, check the signature and notarization of the app
   once it is copied to Applications:
   `codesign --verify --deep --strict --verbose=2 "/Applications/Open Secret Manager.app"` and
   `spctl --assess --type execute --verbose "/Applications/Open Secret Manager.app"`.
3. To check that the package was built from the published source, build the
   same commit with `scripts/release-macos.sh` and compare your
   `app-contents.sha256` with the published one. It lists every file of the
   app with its SHA-256 after taking the signatures out, so a build signed by
   the project and one signed ad hoc at home can be compared;
   `scripts/app-contents.sh` makes the same list for any copy of the app. The
   disk image itself differs between builds (it records when it was made);
   the app inside it must not. The tools must be the versions in
   `build-info.txt`.

## How a phone release is built

The Android app is released; the iOS build only shows that a release would
build.

- `scripts/release-android.sh` builds the APK from an archive of the
  commit, in a container that is x86_64 Debian 12 as F-Droid's build
  server is (`packaging/android/Dockerfile`: its OpenJDK 17, the Android
  SDK, and the Rust and NDK that `apps/mobile/android/prepare-release.sh`
  names), shrunk with R8 (the rules that keep what JNA calls by name are in
  `apps/mobile/android/vault/consumer-rules.pro`), into
  `dist/android/<commit>/` with its SHA-256, the list of the APK's files
  without its signature (`apk-contents.sha256`), and `build-info.txt`. With
  `OSM_ANDROID_KEYSTORE`, `OSM_ANDROID_KEYSTORE_PASSWORD`,
  `OSM_ANDROID_KEY_ALIAS`, and `OSM_ANDROID_KEY_PASSWORD` it signs the APK
  with that key on the Mac, after the build (the key never goes into the
  container); without them the APK is unsigned. An update must be signed
  with the same key, so the keystore is kept as carefully as a Developer
  ID. `scripts/reproduce-android.sh` builds twice and compares the file
  lists. The Docker context (`OSM_DOCKER_CONTEXT`) must run linux/amd64
  containers; on an Apple Silicon Mac, a colima machine with Rosetta does.
  A release is never built on the Mac itself: the APK's other files come
  out the same there, but not the shared code's library, as Cargo puts the
  kind of machine that builds into every crate's hash and rustc orders the
  library's functions by names that carry those hashes. Within Linux,
  `prepare-release.sh` takes the build machine's folders and the
  compilers' names out of the library, and Gradle strips no library, so
  that F-Droid's server makes the same APK as the container.
  `scripts/test-mobile-join.sh android-release` signs the release with a key
  made for the run and has it join a desktop-side device on an emulator.
- `scripts/release-ios.sh` builds from an export at
  `/private/tmp/open-secret-manager-ios-release`. With `OSM_APPLE_TEAM` (a
  team whose account is signed in to Xcode) it makes a signed archive and an
  IPA for App Store Connect; without it, the app built for iPhones unsigned,
  which installs nowhere and only shows that the release builds. Xcode's
  asset compiler needs a simulator runtime of the SDK's exact version even
  to build for iPhones; without it the unsigned build leaves out the app
  icon and the signed one refuses to start (`xcodebuild -downloadPlatform
  iOS` installs it).

Before an iOS app is submitted, the owner answers one question: each upload
asks whether the app uses encryption that is not exempt, which is a legal
answer about export rules, not a technical one. The app's privacy manifests
(`PrivacyInfo.xcprivacy`) declare reading files' metadata and the app
group's user defaults. On iOS the shared code uses iOS's own SQLite, linked
with `-lsqlite3`, rather than the copy it builds in elsewhere (Phase 7,
stop 6): SQLite calls `statfs` and `fstatfs` on the files it opens, which
fall under the "disk space" category of declared reasons, and none of
Apple's reasons for that category describes them, but calls made inside
Apple's own library need no declaration. The app and the extension built for
iPhones link `/usr/lib/libsqlite3.dylib`, contain no SQLite of their own,
and call neither function. iOS 17 has SQLite 3.39, which
has everything the vault uses (strict tables from 3.37, dropping columns
from 3.35); the shared code's tests ran against the simulator's.

## F-Droid

F-Droid builds the Android app from this repository, with the recipe in its
own repository (`metadata/org.opensecretmanager.app.yml` in
[fdroiddata](https://gitlab.com/fdroid/fdroiddata)) and the listing in
`fastlane/metadata/android/` here. It publishes the APK signed with the
project's key from the GitHub release, and only if the APK it built itself
is the same once the signature is set aside; otherwise it publishes nothing.
The project's key therefore stays the only one that signs the app, and an
APK from GitHub and one from F-Droid update each other.

A new Android version:

1. Raise `versionCode` and `versionName` in
   `apps/mobile/android/app/build.gradle.kts`, and write what changed in
   `fastlane/metadata/android/<language>/changelogs/<versionCode>.txt`.
2. Commit, and build that commit with `scripts/release-android.sh` and the
   project's key.
3. Tag the commit `android-v<versionName>`, push the tag, and publish a
   GitHub release of it with `Open-Secret-Manager-<versionName>-android-arm64.apk`,
   `SHA256SUMS`, `apk-contents.sha256`, and `build-info.txt`.
4. F-Droid finds the tag itself, builds it, and compares.

The recipe installs the Rust that `prepare-release.sh` names; a change to
the NDK there is also a change to the recipe's `ndk`.

## How a release is built

From a commit with nothing uncommitted:

1. `scripts/check.sh --network --browsers --linux` passes (`--linux` needs a
   Docker engine; `OSM_COLIMA_PROFILE` names a colima machine to start for it).
2. `scripts/release-macos.sh`, with `OSM_SIGNING_IDENTITY` (a Developer ID
   Application identity) and `OSM_NOTARY_PROFILE` (a notarytool keychain
   profile) set for a signed and notarized release. Without them the app is
   signed ad hoc, which runs on the Mac that built it and is refused by
   others once downloaded. The result is in `dist/macos/<commit>/`.
3. `scripts/reproduce-macos.sh` builds the commit twice, each time from a
   fresh export with nothing kept from the build before, and fails unless
   the two apps are the same, file for file.
4. `scripts/package-linux.sh` builds the Linux package in a container
   (`OSM_DOCKER_CONTEXT` picks the Docker context); the result is in
   `dist/linux/<commit>/`.

The builds pin what they can: the lockfiles (`--locked`, `npm ci`), the
Rust and Node versions in the Linux image, and `SOURCE_DATE_EPOCH` from the
commit. The macOS build is made from an export of the commit at one fixed
path, `/private/tmp/open-secret-manager-release`: Cargo puts the absolute
path of the crates the desktop app takes from outside its own workspace into
the app's symbols, so a build at another path is a different program. The
path of the Cargo home is taken out of the programs, and so are object-file
paths the linker would otherwise put into each program's UUID.
