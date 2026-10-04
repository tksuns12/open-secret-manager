#!/bin/sh
# Runs the phone tests on a simulator and an emulator.
#
#   scripts/test-mobile.sh [ios] [android] [join] [join-ios]
#
# ios      the phone interface through its Swift bindings, in an iOS
#          simulator, on a copy of the frozen format 7 vault: what
#          crates/mobile/tests/frozen_vault.rs checks in Rust; then the
#          iOS app's UI tests in a simulator (scripts/test-mobile-ios.sh).
# android  the same through the Kotlin bindings, then the Android app's
#          screens, on a running emulator or attached device (adb). On an
#          emulator with a fingerprint enrolled, its sensor is touched
#          throughout, so that unlocking with a fingerprint is tested too.
# join     the Android app joining a desktop-side device on this machine
#          over the network (scripts/test-mobile-join.sh).
# join-ios the same with the iOS app.
#
# Without arguments: ios and android. iOS needs `rustup target add
# aarch64-apple-ios-sim aarch64-apple-ios` and Xcode; each simulator is made
# for the run in a device set of its own and deleted. Android needs `rustup target add
# aarch64-linux-android` and the Android SDK and NDK. OSM_DEVICE_PIN
# unlocks a device or emulator that has a screen lock.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
platforms=${*:-ios android}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The bindings are generated from the library built for this machine, with
# the names in crates/mobile/uniffi.toml.
cargo build --locked -q -p osm-mobile
library=target/debug/libosm_mobile.dylib
[ -f "$library" ] || library=target/debug/libosm_mobile.so
bindgen() {
    cargo run --locked -q -p osm-mobile --features bindgen --bin uniffi-bindgen -- \
        generate --library "$library" --no-format \
        --language "$1" --out-dir "$2"
}
frozen=crates/vault-core/fixtures/format-7/vault.sqlite3

for platform in $platforms; do
case $platform in
ios)
    echo "== iOS simulator"
    bindgen swift "$work/swift"
    # The oldest iOS the app is meant for, for the C code built with it too.
    IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build --locked -q -p osm-mobile --target aarch64-apple-ios-sim
    mkdir -p "$work/include" "$work/device"
    cp "$work/swift/OSMVaultFFI.h" "$work/include/"
    cp "$work/swift/OSMVaultFFI.modulemap" "$work/include/module.modulemap"
    sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
    # The static library, linked in: the program must load nothing from
    # this disk when it starts.
    xcrun --sdk iphonesimulator swiftc -target arm64-apple-ios17.0-simulator -sdk "$sdk" \
        -I "$work/include" -module-name OSMVaultTests \
        "$work/swift/OSMVault.swift" apps/mobile/ios/Tests/main.swift \
        target/aarch64-apple-ios-sim/debug/libosm_mobile.a -framework Security \
        -o "$work/osm-vault-tests"
    cp "$frozen" "$work/device/vault.sqlite3"
    # A simulator of the run's own, on the internal disk: one may wait
    # without end for a file on an external disk.
    set_dir="$work/devices"
    mkdir -p "$set_dir"
    runtime=$(xcrun simctl list runtimes -j | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s).runtimes.filter(r=>r.platform==="iOS"&&r.isAvailable);console.log(r[r.length-1].identifier)})')
    device=$(xcrun simctl --set "$set_dir" create "Open Secret Manager bindings" \
        com.apple.CoreSimulator.SimDeviceType.iPhone-17 "$runtime")
    xcrun simctl --set "$set_dir" boot "$device"
    xcrun simctl --set "$set_dir" bootstatus "$device" -b >/dev/null
    status=0
    xcrun simctl --set "$set_dir" spawn "$device" "$work/osm-vault-tests" "$work/device" || status=$?
    xcrun simctl --set "$set_dir" shutdown "$device" >/dev/null 2>&1 || true
    xcrun simctl --set "$set_dir" delete "$device" >/dev/null 2>&1 || true
    [ "$status" = 0 ] || exit "$status"
    echo "== iOS app"
    scripts/test-mobile-ios.sh
    ;;
android)
    echo "== Android"
    "$root/apps/mobile/android/prepare.sh" "$work"
    adb=${ADB:-adb}
    command -v "$adb" >/dev/null || adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
    # The app is tested in front, with the input focus: the screen on and
    # unlocked, and no system dialog over it.
    "$adb" shell input keyevent KEYCODE_WAKEUP
    if [ -n "${OSM_DEVICE_PIN:-}" ]; then
        "$adb" shell input keyevent KEYCODE_MENU
        "$adb" shell input text "$OSM_DEVICE_PIN"
        "$adb" shell input keyevent KEYCODE_ENTER
    fi
    "$adb" shell wm dismiss-keyguard
    "$adb" shell am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS >/dev/null 2>&1 || true
    # An emulator's fingerprint sensor, touched until the tests end.
    (while :; do "$adb" emu finger touch 1 >/dev/null 2>&1; sleep 2; done) &
    toucher=$!
    status=0
    (cd apps/mobile/android && ./gradlew --quiet :vault:connectedDebugAndroidTest :app:connectedDebugAndroidTest) || status=$?
    kill "$toucher" 2>/dev/null || true
    wait "$toucher" 2>/dev/null || true
    [ "$status" = 0 ] || exit "$status"
    ;;
join)
    echo "== Android app joins a desktop-side device"
    scripts/test-mobile-join.sh android
    ;;
join-ios)
    echo "== iOS app joins a desktop-side device"
    scripts/test-mobile-join.sh ios
    ;;
*)
    echo "unknown platform: $platform" >&2
    exit 2
    ;;
esac
done
