# Phone apps

The phone apps run the vault's shared Rust code through `crates/mobile`,
whose Kotlin and Swift bindings UniFFI generates at build time.

## Android

`android/` is a Gradle project with three modules:

- `vault`: the shared code's library for arm64 and its Kotlin bindings,
  both put in place by `android/prepare.sh <scratch folder>` before a
  build. Neither is committed.
- `app`: the app. It joins a vault from a computer by invitation and
  comparison of codes, unlocks with its own password or, once turned on,
  a fingerprint, lists and searches the items, copies a username,
  password, or one-time code, creates, edits, and deletes logins and
  secure notes, and shows an item's history and the items deleted,
  restoring a login or note from either. It locks and stops taking part
  when it leaves the screen, and keeps the vault out of screenshots; while
  it is closed it syncs now and then without unlocking, unless that is
  turned off. Once picked as the phone's autofill service, it fills
  logins into other apps and
  into pages of the browsers it trusts (`res/raw/trusted_browsers.json`,
  made by `android/trusted-browsers.mjs`), after the owner unlocks and
  chooses the login on its fill screen (and its one-time code into a field
  that asks for one), and offers to save a login those apps and pages
  send, where the owner chooses on its save screen.
- `loginfixture`: a stand-in for another app with login forms, which the
  autofill tests fill and sign in to. Never shipped.

To fill with it, pick Open Secret Manager in the phone's settings (or
from "Fill logins in other apps…" in the app). Chrome 135 and later uses
it only after "Autofill using another service" is chosen in Chrome's
settings, under Autofill services.

```text
android/prepare.sh "$(mktemp -d)"
cd android && ./gradlew :app:assembleDebug
```

`scripts/test-mobile.sh android` runs the bindings' tests and the app's
screens and autofill on a running emulator or device (it installs the
stand-in app, and makes this app the autofill service for each autofill
test, putting the earlier one back after it); `scripts/test-mobile.sh join`
has the app join a desktop-side device on the same machine;
`scripts/test-mobile-chrome.sh` has real Chrome fill and save on a test
site, after a setup by hand that the script describes. A debug
build made with `-Posm.screenshots=true` lets its screens be captured
for review; no other build does.

`scripts/release-android.sh` builds the release, shrunk and signed with the
owner's key when one is given, and `scripts/test-mobile-join.sh
android-release` tries it on an emulator; see `docs/release.md`.

## iOS

`ios/` is an Xcode project (`OpenSecretManager.xcodeproj`, its folders
synchronized with these):

- `App`: the app, in SwiftUI. It joins a vault from a computer by
  invitation and comparison of codes, unlocks with its own password or,
  once turned on, Face ID or Touch ID, lists and searches the items,
  copies a username, password, or one-time code, creates, edits, and
  deletes logins and secure notes, and shows an item's history and the
  items deleted, restoring a login or note from either. It locks, stops taking
  part, and closes the vault's files when it leaves the screen, and hides
  the vault in the app switcher.
- `AutoFill`: the AutoFill extension. Once turned on (the app asks iOS
  from "Fill logins in other apps…"), it fills a login into another app or
  a page after the owner unlocks and chooses it on its own screen, and,
  from iOS 26.2, saves a login another app or a page sent, where the owner
  chooses.
- `Shared`: what both use: the vault's folder in the container they share,
  Face ID and Touch ID, who asks for a login, and the generated bindings.
- `LoginFixture` and `UITests`: a stand-in for another app with a login
  form, and the UI tests.

`ios/prepare.sh <scratch folder>` puts in place what the project is built
from: the shared code's static library for the simulator and for iPhones as
`build/OSMVaultFFI.xcframework`, the Swift bindings in `Shared/Generated`,
and a copy of the frozen vault for the tests. None of it is committed.

```text
ios/prepare.sh "$(mktemp -d)"
open ios/OpenSecretManager.xcodeproj
```

`scripts/test-mobile-ios.sh` builds the project and runs the UI tests in a
simulator of its own; `scripts/test-mobile-join.sh ios` has the app join a
desktop-side device on the same machine. xcodebuild runs UI tests only on
simulators of the default device set, so the script installs the apps and
starts XCTest's runner itself, with the configuration Xcode would write
(`ios/Tests/configure-ui-tests.swift`); a later Xcode may change what that
needs. `ios/Tests/main.swift` checks the Swift bindings alone
(`scripts/test-mobile.sh ios` runs both). A debug build reads
`OSM_TEST_VAULT`, `OSM_TEST_BIOMETRICS`, and `OSM_TEST_CHANGE_WHILE_EDITING`
at launch, for the tests; a release build has none of them. `scripts/release-ios.sh` builds the release
(signed with `OSM_APPLE_TEAM`, otherwise unsigned to check it builds), and
`scripts/measure-ios-memory.sh` measures the app and the extension
unlocking a vault at the real cost. What is left to try on real phones is
in `docs/phone-trial.md`.
