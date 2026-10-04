# Release

What a release of Open Secret Manager is, where it runs, what risks remain
in it, and how a package is built and checked. This page is the published
statement of the supported configurations and the remaining risks; the
evidence behind each statement is in
[implementation-status.md](implementation-status.md).

## What the first release is

Version 0.1.0 of the desktop app, for macOS, with the browser extension for
Chromium-based browsers and Firefox. It has not been reviewed by anyone
outside the project ([review-packet.md](review-packet.md) is the request),
and it must not be described as audited.

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
| Linux, x86_64 (`.deb`) | **Built, not verified.** Made in a container from Ubuntu 22.04, so it needs no newer system libraries than 22.04 has. No Linux desktop has run it. Locking when the computer sleeps or the screen locks, and keeping copied codes out of clipboard history, exist only on macOS. |
| Linux, arm64 | The packaging script builds it on request; not built for the release. |
| Windows | **Not supported.** The app was never built for Windows, and its browser fill does not exist there. |
| Android (9 and later, 64-bit ARM) | **Not yet a release.** The release build, shrunk and signed as it ships, joined a desktop-side device and synced on an Android 16 emulator; no real phone has run it ([phone-trial.md](phone-trial.md) is what is left). Other kinds of phone refuse to install it. |
| iOS (17 and later, iPhone) | **Not yet a release.** Built for iPhones unsigned; tested only in an iOS 26.3 simulator. Running it on any iPhone needs an Apple developer team, which the project does not have yet. |
| Browsers | Chromium-based browsers and Firefox, tested headless (Chrome for Testing 153, Firefox 157). The extension is not published in either store: in Chromium it loads unpacked under its development ID, and in Firefox only as a temporary add-on. |
| Networks | Devices reach each other directly by address on a network they share. There is no relay and no discovery beyond the address in an invitation. |
| Devices in a vault | Tested with up to four. With two, both must be online to add or remove a device; with three or more, one can be away. |

## Remaining risks

These are the risks we know of and publish. Each one is described with its
evidence in the delivery matrix and the threat model.

**Review and packaging**
- No outside review of the design or the code.
- Until packages are signed with a developer identity and notarized, macOS
  refuses a downloaded copy unless the owner overrides it, and nothing but
  the file system guards the app's files, the native host inside it
  included.
- 603 crates and two sets of npm packages are trusted without review of
  what their code does. Their advisories and licenses are checked.

**On a device**
- While a vault is unlocked, whoever controls that device (an
  administrator, a debugger, malware, the operating system) can read it.
  Copies of secrets in the window's JavaScript cannot be wiped.
- A vault file can be rolled back to an earlier copy, or have rows taken
  out, by someone who can write it; the app cannot tell.
- The vault locks after five minutes without input and when its window is
  hidden; on macOS also on sleep, screen lock, and user switch. Those last
  locks were checked through the code, not with a real sleep or lock. A
  computer can go to sleep before a vault operation in progress finishes,
  and the vault then locks on waking.
- A copied one-time code stays on the clipboard for up to 30 seconds. On
  Linux it is plain text that clipboard history apps can keep.

**Between devices**
- A device that was lost keeps everything it had. Removing it, starting
  over, or restoring a backup stops it from receiving anything new; it does
  not take back what it read.
- A vault with two voting devices cannot remove one that is lost; it starts
  over as a new vault instead. A device invited without a vote can always
  be removed by the voting ones.
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
- The app does not remind the owner to back up.

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

Neither phone app is released yet; these build what a release would be.

- `scripts/release-android.sh` builds the APK and the bundle for Google Play
  from an export of the commit at `/private/tmp/open-secret-manager-android-release`,
  shrunk with R8 (the rules that keep what JNA calls by name are in
  `apps/mobile/android/vault/consumer-rules.pro`), into `dist/android/<commit>/`
  with their SHA-256, the list of the APK's files without its signature
  (`apk-contents.sha256`), and `build-info.txt`. With `OSM_ANDROID_KEYSTORE`,
  `OSM_ANDROID_KEYSTORE_PASSWORD`, `OSM_ANDROID_KEY_ALIAS`, and
  `OSM_ANDROID_KEY_PASSWORD` both are signed with that key; without them
  they are unsigned. An update must be signed with the same key, so the
  keystore is kept as carefully as a Developer ID.
  `scripts/reproduce-android.sh` builds twice and compares the file lists.
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

Before an iOS app is submitted, two things wait for the owner. Each upload
asks whether the app uses encryption that is not exempt, which is a legal
answer about export rules, not a technical one. And the app's privacy
manifests (`PrivacyInfo.xcprivacy`) declare reading files' metadata and the
app group's user defaults, but not the "disk space" category: the bundled
SQLite calls `statfs` to choose how to lock a file and, on Apple systems
whatever it is built with, `fstatfs` on every file it opens to recognize
FAT volumes, and none of Apple's listed reasons for that category describes
either. Building SQLite without its locking-style detection
(`SQLITE_ENABLE_LOCKING_STYLE=0`) removes only the first. What would remove
both is linking iOS's own SQLite instead of the bundled one, since calls
inside Apple's library need no declaration: iOS 17 has SQLite 3.39, which
has everything the vault uses (strict tables from 3.37, dropping columns
from 3.35); the vault's tests would then have to run against it. The other
way is to ask Apple for a reason that fits.

## How a release is built

From a commit with nothing uncommitted:

1. `scripts/check.sh --network --browsers` passes.
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
