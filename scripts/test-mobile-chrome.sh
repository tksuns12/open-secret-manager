#!/bin/sh
# The Android app filling and saving in real Chrome, not a stand-in, on an
# emulator.
#
#   scripts/test-mobile-chrome.sh <folder kept between runs>
#
# The folder holds a certificate authority made for these tests only and the
# test site's certificate, which the first run makes
# (scripts/test-site-certs.sh; scripts/test-mobile-safari.sh shares them).
# Android lets two things be done only through its screens, once per
# emulator:
#
#   1. Install the certificate authority, which the first run puts in
#      Download as osm-phone-test-ca.crt, as a CA certificate: Settings ›
#      Security & privacy › More security & privacy › Encryption &
#      credentials › Install a certificate › CA certificate.
#   2. In Chrome 135 or later, with this app as the phone's autofill
#      service: Settings › Autofill services › Autofill using another
#      service.
#
# Each run then serves the test site (scripts/test-site.py) on
# 127.0.0.1:8443, has Chrome reach login.osm.test there through its
# command line (which Chrome reads once it is the debug app), runs
# ChromeTest, and checks what the site received. OSM_DEVICE_PIN unlocks an
# emulator with a screen lock. Use only a test emulator: the certificate
# authority is trusted by everything on it.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
keep=${1:?usage: scripts/test-mobile-chrome.sh <folder kept between runs>}
mkdir -p "$keep"
keep=$(cd "$keep" && pwd)
adb=${ADB:-adb}
command -v "$adb" >/dev/null || adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"

if [ "$(scripts/test-site-certs.sh "$keep")" = made ]; then
    "$adb" push "$keep/ca.crt" /sdcard/Download/osm-phone-test-ca.crt >/dev/null
    echo "Made a test CA. Install /sdcard/Download/osm-phone-test-ca.crt as a CA certificate"
    echo "on the emulator, choose this app in Chrome's autofill services, and run again."
    exit 2
fi

work=$(mktemp -d)
python3 scripts/test-site.py "$keep" >"$work/site.out" 2>&1 &
site=$!
trap 'kill "$site" 2>/dev/null || true; wait "$site" 2>/dev/null || true; rm -rf "$work"' EXIT
: >"$keep/server.log"

# Chrome reads its command line from this file once it is the debug app.
"$adb" shell am set-debug-app --persistent com.android.chrome
"$adb" shell "echo '_ --disable-fre --no-default-browser-check --no-first-run --host-resolver-rules=\"MAP login.osm.test 10.0.2.2\"' > /data/local/tmp/chrome-command-line"
"$adb" shell am force-stop com.android.chrome

"$root/apps/mobile/android/prepare.sh" "$work/prepared"
"$adb" shell input keyevent KEYCODE_WAKEUP
if [ -n "${OSM_DEVICE_PIN:-}" ]; then
    "$adb" shell input keyevent KEYCODE_MENU
    "$adb" shell input text "$OSM_DEVICE_PIN"
    "$adb" shell input keyevent KEYCODE_ENTER
fi
"$adb" shell wm dismiss-keyguard
"$adb" logcat -c
status=0
(cd apps/mobile/android && ./gradlew --quiet :app:connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=org.opensecretmanager.app.ChromeTest \
    -Pandroid.testInstrumentationRunnerArguments.chromeSite=https://login.osm.test:8443) || status=$?
"$adb" logcat -d -s OSMChrome:I | sed -n 's/.*\(CHROME-.*\)/\1/p'
echo "the site received:"
cat "$keep/server.log"
[ "$status" = 0 ] || exit "$status"

# What Chrome sent is what the vault filled, and what was typed.
code=$("$adb" logcat -d -s OSMChrome:I | sed -n 's/.*CHROME-CODE //p' | tail -1 | tr -d '\r')
grep -qx 'LOGIN username=site-user password=site-pass-1' "$keep/server.log"
grep -qx "CODE code=$code" "$keep/server.log"
grep -qx 'LOGIN username=new-user password=new-pass-1' "$keep/server.log"
echo "Chrome filled the login and its code, and the login typed into it was saved"
