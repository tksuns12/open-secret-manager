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
  a fingerprint, lists and searches the items, and copies a username,
  password, or one-time code. It locks and stops taking part when it
  leaves the screen, and keeps the vault out of screenshots. Once picked
  as the phone's autofill service, it fills logins into other apps and
  into pages of the browsers it trusts (`res/raw/trusted_browsers.json`,
  made by `android/trusted-browsers.mjs`), after the owner unlocks and
  chooses the login on its fill screen.
- `loginfixture`: a stand-in for another app with login forms, which the
  autofill tests fill. Never shipped.

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
has the app join a desktop-side device on the same machine. A debug
build made with `-Posm.screenshots=true` lets its screens be captured
for review; no other build does.

## iOS

`ios/Tests/main.swift` checks the Swift bindings in a simulator
(`scripts/test-mobile.sh ios`). The iOS app is a later stop.
