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
# authority for the simulator to trust, and OSM_IOS_RUNTIME an iOS runtime
# other than the newest; OSM_IOS_AUTOFILL_ON=1 turns AutoFill on before
# the tests (see below). OSM_IOS_DARK=1 sets the simulator to the dark
# appearance, to look at the screens (OSM_TEST_SCREENS). Needs Xcode, an iOS simulator runtime, and
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
OSM_IOS_TEST_FIXTURES=1 apps/mobile/ios/prepare.sh "$work/prepare" "$profile"
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
# The newest iOS runtime installed, or the one OSM_IOS_RUNTIME names (its
# identifier, as `xcrun simctl list runtimes` shows it).
runtime=${OSM_IOS_RUNTIME:-}
[ -n "$runtime" ] || runtime=$(xcrun simctl list runtimes -j | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s).runtimes.filter(r=>r.platform==="iOS"&&r.isAvailable);console.log(r[r.length-1].identifier)})')
device=$(xcrun simctl --set "$set_dir" create "Open Secret Manager UI tests" \
    com.apple.CoreSimulator.SimDeviceType.iPhone-17 "$runtime")
xcrun simctl --set "$set_dir" boot "$device"
xcrun simctl --set "$set_dir" bootstatus "$device" -b >/dev/null
# The screens in the dark appearance, for a person to look at.
if [ "${OSM_IOS_DARK:-}" = 1 ]; then
    xcrun simctl --set "$set_dir" ui "$device" appearance dark
fi
# The keyboard's tip about sliding to type, which iOS 27 shows once over
# the keyboard and which takes the tap on its Passwords key, as seen.
xcrun simctl --set "$set_dir" spawn "$device" defaults write com.apple.keyboard.preferences \
    DidShowContinuousPathIntroduction -bool true
# A certificate authority for a test site the tests should trust
# (scripts/test-mobile-safari.sh).
if [ -n "${OSM_IOS_ROOT_CERT:-}" ]; then
    xcrun simctl --set "$set_dir" keychain "$device" add-root-cert "$OSM_IOS_ROOT_CERT"
fi
for app in OpenSecretManager LoginFixture UITests-Runner; do
    xcrun simctl --set "$set_dir" install "$device" "$products/$app.app"
done
# Where the system cannot show its own offer to turn AutoFill on, as the
# iOS 26.5 simulator under Xcode 27 cannot (SpringBoard refuses the
# offer's agent), OSM_IOS_AUTOFILL_ON=1 turns the app's extension on as
# Settings would, and the tests then find it on.
if [ "${OSM_IOS_AUTOFILL_ON:-}" = 1 ]; then
    xcrun simctl --set "$set_dir" spawn "$device" pluginkit -e use -i org.opensecretmanager.app.autofill
fi

platform="$(xcode-select -p)/Platforms/iPhoneSimulator.platform/Developer"
runner=$(xcrun simctl --set "$set_dir" get_app_container "$device" org.opensecretmanager.app.uitests.xctrunner app)
app=$(xcrun simctl --set "$set_dir" get_app_container "$device" org.opensecretmanager.app app)
# Xcode 27 no longer copies XCTest into the runner; it is then the
# platform's own.
frameworks="$runner/Frameworks"
automation="$frameworks/XCTAutomationSupport.framework"
if [ ! -e "$frameworks/XCTest.framework" ]; then
    frameworks="$platform/Library/Frameworks"
    automation="$platform/Library/PrivateFrameworks/XCTAutomationSupport.framework"
fi
SIMCTL_CHILD_XCTEST_FRAMEWORK="$frameworks/XCTest.framework/XCTest" \
SIMCTL_CHILD_AUTOMATION_FRAMEWORK="$automation" \
SIMCTL_CHILD_DYLD_FRAMEWORK_PATH="$frameworks:$platform/Library/PrivateFrameworks" \
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
