#!/bin/sh
# Joins the Android app on an emulator to a desktop-side device on this
# machine, over the network, as a phone joins a computer: the desktop
# (`osm-peer device`) makes a vault with one item and invites a device
# without a vote; the app's test pastes the invitation into the app's join
# screen and shows the code, the script answers for the owner on the
# desktop side only if the two codes match, the test sets the phone's
# password, and the app shows the item once it has synced.
#
#   scripts/test-mobile-join.sh
#
# Needs a running emulator (adb) and port 47820 free here: adb carries
# connections between the emulator and this machine in both directions.
set -eu
cd "$(dirname "$0")/.."
adb=${ADB:-adb}
command -v "$adb" >/dev/null || adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
work=$(mktemp -d)
peer=target/debug/osm-peer
export OSM_PASSWORD="desktop password"
desktop=""
cleanup() {
    "$adb" reverse --remove-all >/dev/null 2>&1 || true
    "$adb" forward --remove tcp:47820 >/dev/null 2>&1 || true
    if [ -n "$desktop" ]; then
        kill "$desktop" 2>/dev/null || true
        wait "$desktop" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

# Waits for a line starting with `$1` from the desktop and prints the rest.
expect() {
    for _ in $(seq 1 240); do
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

apps/mobile/android/prepare.sh "$work"
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
# The desktop has the phone as its second member, without a vote.
echo status >&3
sleep 1
line=$(expect STATUS)
echo "desktop: $line"
case "$line" in
    *members=2*voters=1*) ;;
    *) echo "the desktop does not have the phone as a member without a vote" >&2; exit 1 ;;
esac
