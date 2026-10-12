#!/bin/sh
# Runs the phone tests on a simulator and an emulator.
#
#   scripts/test-mobile.sh [ios] [android] [join] [join-ios] [relay]
#
# ios      the phone interface through its Swift bindings, in an iOS
#          simulator, on a copy of the frozen format 7 vault: what
#          crates/mobile/tests/frozen_vault.rs checks in Rust; then the
#          iOS app's UI tests in a simulator (scripts/test-mobile-ios.sh).
# android  the same through the Kotlin bindings, then the Android app's
#          screens, on a running emulator or attached device (adb). On an
#          emulator with a fingerprint enrolled, its sensor is touched
#          throughout, so that unlocking with a fingerprint is tested too.
#          What the screen showed at a failed wait of the autofill tests,
#          and the system's log of the run (with autofill's in full), are
#          brought back into OSM_TEST_FAILURES/android, if set. Google Play
#          services' changes to the system's settings wait until the run
#          ends, as each change to autofill's ends every autofill session.
#          The Android tests are given OSM_ANDROID_TIME_LIMIT seconds (an
#          hour if not set), after which they are stopped and fail: an
#          emulator that stopped answering once held a run for hours.
# join     the Android app joining a desktop-side device on this machine
#          over the network (scripts/test-mobile-join.sh).
# join-ios the same with the iOS app.
# relay    the Android app syncing with a desktop-side device through a
#          relay once neither can reach the other directly
#          (scripts/test-mobile-relay.sh).
#
# Without arguments: ios and android. iOS needs `rustup target add
# aarch64-apple-ios-sim aarch64-apple-ios` and Xcode; each simulator is made
# for the run in a device set of its own and deleted. Android needs `rustup target add
# aarch64-linux-android` and the Android SDK and NDK. OSM_DEVICE_PIN
# unlocks a device or emulator that has a screen lock, before the tests and
# in the one that turns the screen off (skipped on such a device without
# it); scripts/make-test-emulator.sh makes the emulator the tests expect.
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
    # this disk when it starts. On iOS the shared code uses the system's
    # SQLite.
    xcrun --sdk iphonesimulator swiftc -target arm64-apple-ios17.0-simulator -sdk "$sdk" \
        -I "$work/include" -module-name OSMVaultTests \
        "$work/swift/OSMVault.swift" apps/mobile/ios/Tests/main.swift \
        target/aarch64-apple-ios-sim/debug/libosm_mobile.a -framework Security -lsqlite3 \
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
    # A device that does not answer, as an emulator short of memory can
    # stop doing, fails every test at its first wait, which says nothing.
    within() { perl -e 'alarm shift; exec @ARGV' "$@"; }
    if [ "$(within 60 "$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != 1 ]; then
        echo "The device did not answer within a minute, or has not finished starting." >&2
        exit 1
    fi
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
    "$adb" shell rm -rf /data/local/tmp/osm-failures
    # Autofill's own log in full while the tests run, as it was after: a
    # session the system ends says why only there.
    log_level=$("$adb" shell cmd autofill get log_level 2>/dev/null | tr -d '\r')
    "$adb" shell cmd autofill set log_level verbose >/dev/null 2>&1 || true
    # Google Play services changes the system's own settings for autofill
    # when it likes, most often soon after the phone starts, and on each
    # change Android ends every autofill session, one waiting on the fill
    # screen included. Such changes wait until the tests end.
    config_sync=$("$adb" shell device_config get_sync_disabled_for_tests 2>/dev/null | tr -d '\r')
    "$adb" shell device_config set_sync_disabled_for_tests until_reboot >/dev/null 2>&1 || true
    since=$("$adb" shell "date '+%m-%d %H:%M:%S.000'" | tr -d '\r')
    # An emulator's fingerprint sensor, touched until the tests end.
    # Each touch gives up after 20 seconds, as the emulator's console can
    # stop answering.
    (while :; do perl -e 'alarm shift; exec @ARGV' 20 "$adb" emu finger touch 1 >/dev/null 2>&1; sleep 2; done) &
    toucher=$!
    status=0
    limit=${OSM_ANDROID_TIME_LIMIT:-3600}
    pin_argument=
    [ -n "${OSM_DEVICE_PIN:-}" ] && pin_argument="-Pandroid.testInstrumentationRunnerArguments.pin=$OSM_DEVICE_PIN"
    (cd apps/mobile/android && perl -e 'alarm shift; exec @ARGV' "$limit" ./gradlew --quiet $pin_argument :vault:connectedDebugAndroidTest :app:connectedDebugAndroidTest) || status=$?
    # Stopped by the alarm.
    [ "$status" = 142 ] && echo "The Android tests were stopped after $limit seconds: the emulator may have stopped answering." >&2
    kill "$toucher" 2>/dev/null || true
    wait "$toucher" 2>/dev/null || true
    "$adb" shell cmd autofill set log_level "${log_level:-off}" >/dev/null 2>&1 || true
    "$adb" shell device_config set_sync_disabled_for_tests "${config_sync:-none}" >/dev/null 2>&1 || true
    if [ "$status" != 0 ] && [ -n "$("$adb" shell ls /data/local/tmp/osm-failures 2>/dev/null)" ]; then
        if [ -n "${OSM_TEST_FAILURES:-}" ]; then
            mkdir -p "$OSM_TEST_FAILURES/android"
            "$adb" pull /data/local/tmp/osm-failures/. "$OSM_TEST_FAILURES/android" >/dev/null
            "$adb" logcat -d -v time -T "$since" >"$OSM_TEST_FAILURES/android/logcat.txt" 2>/dev/null || true
            echo "What the screen showed at each failed wait, and the system's log: $OSM_TEST_FAILURES/android" >&2
        else
            echo "What the screen showed at each failed wait is on the device in /data/local/tmp/osm-failures (or set OSM_TEST_FAILURES)." >&2
        fi
    fi
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
relay)
    echo "== Android app syncs through a relay"
    scripts/test-mobile-relay.sh
    ;;
*)
    echo "unknown platform: $platform" >&2
    exit 2
    ;;
esac
done
