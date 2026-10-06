#!/bin/sh
# The iOS app's UI tests, in a simulator made for the run in a device set of
# its own and deleted after: the app's screens, Face ID, AutoFill into
# another app, and how the AutoFill extension reads who asks.
#
#   scripts/test-mobile-ios.sh [Class or Class/method ...]
#
# xcodebuild runs UI tests only on simulators of the default device set, so
# the script builds the targets, installs them, and starts XCTest's runner
# itself, with the configuration Xcode would give it
# (apps/mobile/ios/Tests/configure-ui-tests.swift). Variables named
# OSM_TEST_* are passed on to the tests. OSM_IOS_OPTIMIZED=1 builds the apps
# and the shared code optimized, as a release, keeping only the debug
# build's hooks for the tests. OSM_IOS_ROOT_CERT names a certificate
# authority for the simulator to trust. Needs Xcode, an iOS simulator runtime, and
# `rustup target add aarch64-apple-ios-sim aarch64-apple-ios`.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
set_dir="$work/devices"
device=""
cleanup() {
    if [ -n "$device" ]; then
        xcrun simctl --set "$set_dir" shutdown "$device" >/dev/null 2>&1 || true
        xcrun simctl --set "$set_dir" delete "$device" >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

configuration=Debug
profile=debug
optimized=""
if [ "${OSM_IOS_OPTIMIZED:-}" = 1 ]; then
    configuration=Release
    profile=release
    optimized=SWIFT_ACTIVE_COMPILATION_CONDITIONS=DEBUG
fi
apps/mobile/ios/prepare.sh "$work/prepare" "$profile"
# Without the app icon if this Mac lacks the simulator runtime Xcode's asset
# compiler needs (see icon-flags.sh); the tests do not need it.
# shellcheck disable=SC2046
(cd apps/mobile/ios && xcodebuild -project OpenSecretManager.xcodeproj \
    -target UITests -target OpenSecretManager -target LoginFixture \
    -sdk iphonesimulator -configuration "$configuration" \
    SYMROOT="$work/build" OBJROOT="$work/obj" $(./icon-flags.sh) $optimized \
    -quiet build 2>&1 | grep -v appintentsmetadataprocessor) || true
products="$work/build/$configuration-iphonesimulator"
[ -d "$products/UITests-Runner.app" ] || { echo "the iOS project did not build" >&2; exit 1; }
xcrun --sdk iphonesimulator swiftc -target arm64-apple-ios17.0-simulator \
    apps/mobile/ios/Tests/configure-ui-tests.swift -o "$work/configure-ui-tests"

mkdir -p "$set_dir"
runtime=$(xcrun simctl list runtimes -j | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s).runtimes.filter(r=>r.platform==="iOS"&&r.isAvailable);console.log(r[r.length-1].identifier)})')
device=$(xcrun simctl --set "$set_dir" create "Open Secret Manager UI tests" \
    com.apple.CoreSimulator.SimDeviceType.iPhone-17 "$runtime")
xcrun simctl --set "$set_dir" boot "$device"
xcrun simctl --set "$set_dir" bootstatus "$device" -b >/dev/null
# A certificate authority for a test site the tests should trust
# (scripts/test-mobile-safari.sh).
if [ -n "${OSM_IOS_ROOT_CERT:-}" ]; then
    xcrun simctl --set "$set_dir" keychain "$device" add-root-cert "$OSM_IOS_ROOT_CERT"
fi
for app in OpenSecretManager LoginFixture UITests-Runner; do
    xcrun simctl --set "$set_dir" install "$device" "$products/$app.app"
done

platform="$(xcode-select -p)/Platforms/iPhoneSimulator.platform/Developer"
runner=$(xcrun simctl --set "$set_dir" get_app_container "$device" org.opensecretmanager.app.uitests.xctrunner app)
app=$(xcrun simctl --set "$set_dir" get_app_container "$device" org.opensecretmanager.app app)
SIMCTL_CHILD_XCTEST_FRAMEWORK="$runner/Frameworks/XCTest.framework/XCTest" \
SIMCTL_CHILD_AUTOMATION_FRAMEWORK="$runner/Frameworks/XCTAutomationSupport.framework" \
SIMCTL_CHILD_DYLD_FRAMEWORK_PATH="$runner/Frameworks" \
SIMCTL_CHILD_DYLD_LIBRARY_PATH="$platform/usr/lib" \
    xcrun simctl --set "$set_dir" spawn "$device" "$work/configure-ui-tests" \
    "$runner/PlugIns/UITests.xctest" "$app" org.opensecretmanager.app "$work/tests.xctestconfiguration" "$@"

for name in $(env | sed -n 's/^\(OSM_TEST_[A-Z_]*\)=.*/\1/p'); do
    eval "export SIMCTL_CHILD_$name=\"\$$name\""
done
SIMCTL_CHILD_XCTestConfigurationFilePath="$work/tests.xctestconfiguration" \
SIMCTL_CHILD_DYLD_FRAMEWORK_PATH="$platform/Library/Frameworks:$platform/Library/PrivateFrameworks" \
SIMCTL_CHILD_DYLD_LIBRARY_PATH="$platform/usr/lib" \
    xcrun simctl --set "$set_dir" launch --console-pty "$device" org.opensecretmanager.app.uitests.xctrunner \
    >"$work/tests.log" 2>&1 || true
grep -E "^Test Case .*(passed|failed|skipped)|error: |^[[:space:]]+Executed .* tests?," "$work/tests.log" | sed 's/^[[:space:]]*//' | uniq
# "All tests", or "Selected tests" when some were named.
grep -Eq "^Test Suite '(All|Selected) tests' passed" "$work/tests.log"
