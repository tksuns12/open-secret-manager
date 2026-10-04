#!/bin/sh
# Joins a phone app to a desktop-side device on this machine, over the
# network, as a phone joins a computer: the desktop (`osm-peer device`)
# makes a vault with one item and invites a device without a vote; the
# app's test pastes the invitation into the app's join screen and shows the
# code, the script answers for the owner on the desktop side only if the two
# codes match, the test sets the phone's password, and the app shows the
# item once it has synced.
#
#   scripts/test-mobile-join.sh [android|android-release|ios]
#
# android          the app on a running emulator (adb); port 47820 must be
#                  free here: adb carries connections between the emulator
#                  and this machine in both directions.
# android-release  the same with the release build, shrunk as it ships and
#                  signed with a key made for the run, which replaces the
#                  installed app and is removed after. It has no test
#                  hooks, so the script works its screens from outside.
#                  Shrinking that broke how the app reaches the shared
#                  code, which JNA does by name, would show here.
# ios              the app in a simulator of its own
#                  (scripts/test-mobile-ios.sh), which shares this
#                  machine's network.
set -eu
cd "$(dirname "$0")/.."
platform=${1:-android}
adb=${ADB:-adb}
command -v "$adb" >/dev/null || adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
work=$(mktemp -d)
peer=target/debug/osm-peer
export OSM_PASSWORD="desktop password"
desktop=""
cleanup() {
    if [ "$platform" != ios ]; then
        "$adb" reverse --remove-all >/dev/null 2>&1 || true
        "$adb" forward --remove tcp:47820 >/dev/null 2>&1 || true
    fi
    if [ "$platform" = android-release ]; then
        "$adb" uninstall org.opensecretmanager.app >/dev/null 2>&1 || true
    fi
    if [ -n "$desktop" ]; then
        kill "$desktop" 2>/dev/null || true
        wait "$desktop" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

# Waits for a line starting with `$1` from the desktop and prints the rest.
expect() {
    for _ in $(seq 1 "${2:-240}"); do
        line=$(grep "^$1" "$work/out" | tail -1 || true)
        if [ -n "$line" ]; then
            echo "${line#"$1"}" | sed 's/^ //'
            return
        fi
        sleep 0.5
    done
    echo "the desktop never said $1:" >&2
    cat "$work/out" >&2
    exit 1
}

# The phone's screen as the accessibility tree has it, and what is on it.
dump() {
    "$adb" exec-out uiautomator dump /dev/tty 2>/dev/null | sed 's/UI hierchary dumped to.*//' >"$work/ui.xml"
}
# Prints the text of the first node whose text matches the pattern `$1`
# and its centre, or fails.
find_text() {
    node -e '
        const xml = require("fs").readFileSync(process.argv[1], "utf8");
        const entities = { quot: "\"", amp: "&", lt: "<", gt: ">", apos: "'"'"'", "#39": "'"'"'" };
        for (const [node] of xml.matchAll(/<node [^>]*>/g)) {
            const text = (node.match(/ text="([^"]*)"/) || [])[1]?.replace(/&(\w+|#\d+);/g, (_, e) => entities[e] ?? _);
            const b = node.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
            if (text && b && new RegExp(process.argv[2]).test(text)) {
                console.log(`${(+b[1] + +b[3]) >> 1} ${(+b[2] + +b[4]) >> 1} ${text}`);
                process.exit(0);
            }
        }
        process.exit(1);' "$work/ui.xml" "$1"
}
# Waits up to $2 seconds (60) for text matching `$1`, and prints as find_text.
wait_text() {
    for _ in $(seq 1 "${2:-60}"); do
        dump
        if find_text "$1"; then return; fi
        sleep 1
    done
    echo "the phone never showed $1" >&2
    grep -o 'text="[^"]*"' "$work/ui.xml" | sed 's/^text=//' | grep -v '^""$' >&2 || true
    exit 1
}
tap_text() {
    set -- $(wait_text "$1")
    "$adb" shell input tap "$1" "$2"
}
hide_keyboard() {
    if "$adb" shell dumpsys input_method | grep -q "mInputShown=true"; then
        "$adb" shell input keyevent KEYCODE_BACK
    fi
}
# Types into the focused field, a little at a time: `input text` drops
# characters of a long text. A space is %s to it.
type_text() {
    rest=$1
    while [ -n "$rest" ]; do
        chunk=$(printf %s "$rest" | cut -c1-20)
        rest=$(printf %s "$rest" | cut -c21-)
        "$adb" shell "input text '$(printf %s "$chunk" | sed 's/ /%s/g')'"
        sleep 0.3
    done
}

case $platform in
android) apps/mobile/android/prepare.sh "$work" ;;
android-release)
    apps/mobile/android/prepare.sh "$work" release
    (cd apps/mobile/android && ./gradlew --quiet :app:assembleRelease)
    build_tools=$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/build-tools/* | tail -1)
    keytool -genkeypair -keystore "$work/test.jks" -storepass "test only" -keypass "test only" \
        -alias test -keyalg EC -groupname secp256r1 -validity 1 \
        -dname "CN=Open Secret Manager test only" >/dev/null 2>&1
    "$build_tools/apksigner" sign --ks "$work/test.jks" --ks-pass "pass:test only" --ks-key-alias test \
        --out "$work/release.apk" apps/mobile/android/app/build/outputs/apk/release/app-release-unsigned.apk
    "$adb" uninstall org.opensecretmanager.app >/dev/null 2>&1 || true
    "$adb" install "$work/release.apk" >/dev/null
    ;;
esac
cargo build --locked -q -p osm-vault-peer --bin osm-peer
"$peer" create "$work/desktop.db" >/dev/null
mkfifo "$work/in"
"$peer" device "$work/desktop.db" "$work/peers.db" "$work/control.db" 127.0.0.1:0 \
    <"$work/in" >"$work/out" 2>&1 &
desktop=$!
exec 3>"$work/in"
expect READY >/dev/null
echo found >&3
expect FOUNDED >/dev/null
echo "add Mail" >&3
expect ADDED >/dev/null
if [ "$platform" = android-release ]; then
    echo "invite without-vote" >&3
    invitation=$(expect INVITE)
    for port in $(lsof -nP -a -p "$desktop" -iTCP -sTCP:LISTEN | awk 'NR > 1 { sub(/.*:/, "", $9); print $9 }'); do
        "$adb" reverse "tcp:$port" "tcp:$port" >/dev/null
    done
    "$adb" forward tcp:47820 tcp:47820 >/dev/null
    "$adb" shell input keyevent KEYCODE_WAKEUP
    "$adb" shell am start -W -n org.opensecretmanager.app/.MainActivity >/dev/null
    # An error from the shared code first: its errors cross as classes too.
    tap_text '^Invitation$'
    type_text "not an invitation"
    tap_text '^Continue$'
    wait_text 'That is not an invitation' 30 >/dev/null
    "$adb" shell am force-stop org.opensecretmanager.app
    "$adb" shell am start -W -n org.opensecretmanager.app/.MainActivity >/dev/null
    tap_text '^Invitation$'
    type_text "$invitation"
    wait_text "^$invitation\$" 20 >/dev/null
    tap_text '^Continue$'
    desktop_code=$(expect SAS)
    phone_code=$(wait_text '^[0-9]{3} [0-9]{3}$' | cut -d' ' -f3-)
    echo "desktop shows $desktop_code, phone shows $phone_code"
    if [ "$phone_code" = "$desktop_code" ]; then echo y >&3; else echo n >&3; fi
    tap_text '^New password for this phone$'
    type_text "phone password, long enough"
    tap_text '^The same again$'
    type_text "phone password, long enough"
    hide_keyboard
    tap_text 'Codes match'
    wait_text '^Mail$' 180 >/dev/null
    echo "the release build shows the desktop's item"
    # The most memory the app's process has held, the password's hashing
    # for the new device password included.
    pid=$("$adb" shell pidof org.opensecretmanager.app | tr -d '\r')
    echo "the app's process: $("$adb" shell cat "/proc/$pid/status" | grep -E '^(VmHWM|VmRSS)' | tr -s ' \t\r' ' ' | tr '\n' ' ')"
elif [ "$platform" = ios ]; then
    # The test says when the app is up, after the build, so that the
    # invitation is fresh when it is pasted.
    mkdir "$work/join"
    OSM_TEST_JOIN="$work/join" scripts/test-mobile-ios.sh JoinTests >"$work/ios.log" 2>&1 &
    phone=$!
    for _ in $(seq 1 3600); do
        [ -e "$work/join/ready" ] && break
        kill -0 "$phone" 2>/dev/null || break
        sleep 0.5
    done
    [ -e "$work/join/ready" ] || { cat "$work/ios.log" >&2; exit 1; }
    echo "invite without-vote" >&3
    expect INVITE >"$work/join/invitation.partial"
    mv "$work/join/invitation.partial" "$work/join/invitation"
    desktop_code=$(expect SAS)
    for _ in $(seq 1 240); do
        [ -s "$work/join/phone-code" ] && break
        sleep 0.5
    done
    phone_code=$(cat "$work/join/phone-code" 2>/dev/null || true)
    echo "desktop shows $desktop_code, phone shows $phone_code"
    if [ "$phone_code" = "$desktop_code" ]; then echo y >&3; else echo n >&3; fi
    status=0
    wait "$phone" || status=$?
    cat "$work/ios.log"
    [ "$status" = 0 ] || exit "$status"
else
    echo "invite without-vote" >&3
    invitation=$(expect INVITE)

    # The emulator reaches the desktop's listeners on its own localhost, and
    # the desktop reaches the phone's on port 47820 of this machine's.
    for port in $(lsof -nP -a -p "$desktop" -iTCP -sTCP:LISTEN | awk 'NR > 1 { sub(/.*:/, "", $9); print $9 }'); do
        "$adb" reverse "tcp:$port" "tcp:$port" >/dev/null
    done
    "$adb" forward tcp:47820 tcp:47820 >/dev/null
    "$adb" logcat -c

    (cd apps/mobile/android && ./gradlew --quiet :app:connectedDebugAndroidTest \
        -Pandroid.testInstrumentationRunnerArguments.class=org.opensecretmanager.app.JoinDesktopTest \
        "-Pandroid.testInstrumentationRunnerArguments.invitation=$invitation") >"$work/gradle.log" 2>&1 &
    phone=$!

    desktop_code=$(expect SAS)
    phone_code=""
    for _ in $(seq 1 240); do
        phone_code=$("$adb" logcat -d -s OSMJoin:I | sed -n 's/.*PHONE-CODE //p' | tail -1 | tr -d '\r')
        [ -n "$phone_code" ] && break
        sleep 0.5
    done
    echo "desktop shows $desktop_code, phone shows $phone_code"
    if [ "$phone_code" = "$desktop_code" ]; then echo y >&3; else echo n >&3; fi

    status=0
    wait "$phone" || status=$?
    "$adb" logcat -d -s OSMJoin:I | sed -n 's/.*\(PHONE-HAS .*\)/\1/p' | tail -1
    if [ "$status" != 0 ]; then
        tail -30 "$work/gradle.log" >&2
        exit "$status"
    fi
fi

# The desktop has the phone as its second member, without a vote.
echo status >&3
sleep 1
line=$(expect STATUS)
echo "desktop: $line"
case "$line" in
    *members=2*voters=1*) ;;
    *) echo "the desktop does not have the phone as a member without a vote" >&2; exit 1 ;;
esac
