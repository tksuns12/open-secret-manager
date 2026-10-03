# Phone apps

The phone apps run the vault's shared Rust code through `crates/mobile`,
whose Kotlin and Swift bindings UniFFI generates at build time.

## Android

`android/` is a Gradle project with two modules:

- `vault`: the shared code's library for arm64 and its Kotlin bindings,
  both put in place by `android/prepare.sh <scratch folder>` before a
  build. Neither is committed.
- `app`: the app. It joins a vault from a computer by invitation and
  comparison of codes, unlocks with its own password or, once turned on,
  a fingerprint, lists and searches the items, and copies a username,
  password, or one-time code. It locks and stops taking part when it
  leaves the screen, and keeps the vault out of screenshots.

```text
android/prepare.sh "$(mktemp -d)"
cd android && ./gradlew :app:assembleDebug
```

`scripts/test-mobile.sh android` runs the bindings' tests and the app's
screens on a running emulator or device; `scripts/test-mobile.sh join`
has the app join a desktop-side device on the same machine. A debug
build made with `-Posm.screenshots=true` lets its screens be captured
for review; no other build does.

## iOS

`ios/Tests/main.swift` checks the Swift bindings in a simulator
(`scripts/test-mobile.sh ios`). The iOS app is a later stop.
