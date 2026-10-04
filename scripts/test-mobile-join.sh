#!/bin/sh
# Joins a phone app to a desktop-side device on this machine, over the
# network, as a phone joins a computer: the desktop (`osm-peer device`)
# makes a vault with one item and invites a device without a vote; the
# app's test pastes the invitation into the app's join screen and shows the
# code, the script answers for the owner on the desktop side only if the two
# codes match, the test sets the phone's password, and the app shows the
# item once it has synced.
#
#   scripts/test-mobile-join.sh [android|ios]
#
# android  the app on a running emulator (adb); port 47820 must be free
#          here: adb carries connections between the emulator and this
#          machine in both directions.
# ios      the app in a simulator of its own (scripts/test-mobile-ios.sh),
#          which shares this machine's network.
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
    if [ "$platform" = android ]; then
        "$adb" reverse --remove-all >/dev/null 2>&1 || true
        "$adb" forward --remove tcp:47820 >/dev/null 2>&1 || true
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

[ "$platform" = android ] && apps/mobile/android/prepare.sh "$work"
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
if [ "$platform" = ios ]; then
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
