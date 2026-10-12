#!/bin/sh
# The Android app syncing with a desktop-side device through a relay, once
# neither can reach the other directly, on a running emulator.
#
#   scripts/test-mobile-relay.sh
#
# A relay (`osm-relay`) listens on port 47830 of this machine. The desktop
# side (`osm-peer device`) makes a vault with one item and invites the app,
# whose test (RelayDesktopTest) joins it as in scripts/test-mobile-join.sh.
# The desktop then sets the relay in the vault and uses it; the app takes
# it in with its next sync. The script then cuts every direct path between
# them (adb no longer carries the desktop's ports to the emulator, nor the
# phone's to this machine, and the desktop stops listening), and the
# desktop writes a login: the app must take it in through the relay and
# send one back, and, locked and away from the screen, its background sync
# must take in another the same way. The emulator reaches the relay at
# 127.0.0.1:47830 through adb, as this machine does.
#
# With OSM_RELAY_IN=linux the relay is built and run in a Linux container
# from the working tree, as on a server (OSM_DOCKER_CONTEXT and
# OSM_LINUX_PLATFORM as for scripts/test-linux.sh), its port published on
# this machine's 127.0.0.1; otherwise it runs here. Port 47820 and 47830
# must be free here.
set -eu
cd "$(dirname "$0")/.."
adb=${ADB:-adb}
command -v "$adb" >/dev/null || adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
docker() { command docker ${OSM_DOCKER_CONTEXT:+--context "$OSM_DOCKER_CONTEXT"} "$@"; }
work=$(mktemp -d)
peer=target/debug/osm-peer
export OSM_PASSWORD="desktop password"
relay_port=47830
desktop=""
relay=""
container=""
phone=""
flags="osm-relay-set osm-direct-cut osm-desktop-wrote"
# Keeps the status the script ends with: a failure stays one.
cleanup() {
    status=$?
    "$adb" reverse --remove-all >/dev/null 2>&1 || true
    "$adb" forward --remove tcp:47820 >/dev/null 2>&1 || true
    for flag in $flags; do "$adb" shell rm -f "/data/local/tmp/$flag" >/dev/null 2>&1 || true; done
    # A test still running would otherwise go on, and remove the app when
    # it ends, under the next run.
    if [ -n "$phone" ] && kill -0 "$phone" 2>/dev/null; then
        kill "$phone" 2>/dev/null || true
        wait "$phone" 2>/dev/null || true
        "$adb" shell am force-stop org.opensecretmanager.app >/dev/null 2>&1 || true
    fi
    if [ -n "$desktop" ]; then
        kill "$desktop" 2>/dev/null || true
        wait "$desktop" 2>/dev/null || true
    fi
    if [ -n "$relay" ]; then
        kill "$relay" 2>/dev/null || true
        wait "$relay" 2>/dev/null || true
    fi
    if [ -n "$container" ]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
    exit "$status"
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
# Waits for the app's test to log `$1`, while it runs.
phone_says() {
    for _ in $(seq 1 600); do
        "$adb" logcat -d -s OSMJoin:I | grep -q "$1" && return
        kill -0 "$phone" 2>/dev/null || break
        sleep 0.5
    done
    echo "the app never said $1" >&2
    tail -30 "$work/gradle.log" >&2
    exit 1
}
# Has the desktop write a login named `$1`, and waits until it has.
desktop_adds() {
    added=$(grep -c "^ADDED" "$work/out" || true)
    echo "add $1" >&3
    for _ in $(seq 1 240); do
        [ "$(grep -c "^ADDED" "$work/out" || true)" -gt "$added" ] && return
        sleep 0.5
    done
    echo "the desktop could not write $1: $(grep "^FAILED" "$work/out" | tail -1)" >&2
    exit 1
}

apps/mobile/android/prepare.sh "$work"
cargo build --locked -q -p osm-vault-peer --bin osm-peer --bin osm-relay

# The relay, and the code it prints.
if [ "${OSM_RELAY_IN:-}" = linux ]; then
    platform=${OSM_LINUX_PLATFORM:-linux/amd64}
    index=$(mktemp)
    cp "$(git rev-parse --git-path index)" "$index"
    GIT_INDEX_FILE=$index git add -A
    tree=$(GIT_INDEX_FILE=$index git write-tree)
    rm -f "$index"
    docker build -q --platform "$platform" -t osm-linux-build packaging/linux >/dev/null
    container=$(docker create --platform "$platform" -p "127.0.0.1:$relay_port:$relay_port" osm-linux-build sh -c "
        cd /src && cargo build --locked --release -q -p osm-vault-peer --bin osm-relay \
        && exec target/release/osm-relay /tmp/relay 0.0.0.0:$relay_port 127.0.0.1:$relay_port")
    git archive --format=tar "$tree" | docker cp - "$container:/src"
    docker start "$container" >/dev/null
    echo "building the relay in a Linux container ($platform)"
    for _ in $(seq 1 1800); do
        docker logs "$container" >"$work/relay.out" 2>&1 || true
        grep -q "^RELAY-CODE" "$work/relay.out" && break
        [ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ] || break
        sleep 1
    done
else
    target/debug/osm-relay "$work/relay" "127.0.0.1:$relay_port" "127.0.0.1:$relay_port" >"$work/relay.out" 2>&1 &
    relay=$!
    for _ in $(seq 1 60); do
        grep -q "^RELAY-CODE" "$work/relay.out" && break
        sleep 0.5
    done
fi
code=$(sed -n 's/^RELAY-CODE //p' "$work/relay.out" | head -1)
[ -n "$code" ] || { echo "the relay did not start:" >&2; cat "$work/relay.out" >&2; exit 1; }
echo "the relay is up"

# The desktop side, and the invitation.
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

# At home: the emulator reaches the desktop's listeners on its own
# localhost, the desktop reaches the phone's on port 47820 of this
# machine's, and both reach the relay on 47830.
desktop_ports=$(lsof -nP -a -p "$desktop" -iTCP -sTCP:LISTEN | awk 'NR > 1 { sub(/.*:/, "", $9); print $9 }')
for port in $desktop_ports; do
    "$adb" reverse "tcp:$port" "tcp:$port" >/dev/null
done
"$adb" forward tcp:47820 tcp:47820 >/dev/null
"$adb" reverse "tcp:$relay_port" "tcp:$relay_port" >/dev/null
"$adb" logcat -c
for flag in $flags; do "$adb" shell rm -f "/data/local/tmp/$flag"; done

(cd apps/mobile/android && ./gradlew --quiet :app:connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=org.opensecretmanager.app.RelayDesktopTest \
    "-Pandroid.testInstrumentationRunnerArguments.relayInvitation=$invitation") >"$work/gradle.log" 2>&1 &
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

# The desktop sets the relay; the app's next sync at home brings it.
phone_says PHONE-JOINED
echo "relay $code" >&3
expect RELAY-CONNECTED >/dev/null
"$adb" shell touch /data/local/tmp/osm-relay-set
phone_says PHONE-SYNCED-HOME
echo "the phone synced at home, and took in the relay"

# Away: every direct path is cut, and the desktop writes a login.
for port in $desktop_ports; do
    "$adb" reverse --remove "tcp:$port" >/dev/null 2>&1 || true
done
"$adb" forward --remove tcp:47820 >/dev/null
echo unlisten >&3
expect UNLISTENED >/dev/null
desktop_adds "Through the relay"
"$adb" shell touch /data/local/tmp/osm-direct-cut
phone_says "PHONE-HAS Through the relay"
echo "the phone took in the desktop's login through the relay"
phone_says "PHONE-MADE Sent through the relay"
for _ in $(seq 1 120); do
    echo list >&3
    sleep 0.5
    grep -q "^ITEM Sent through the relay" "$work/out" && break
done
grep -q "^ITEM Sent through the relay" "$work/out" || { echo "the phone's login never reached the desktop" >&2; exit 1; }
echo "the desktop has the phone's login, sent through the relay"

# Locked and away from the screen: the background sync, through the relay.
phone_says PHONE-AWAY
desktop_adds "Relayed while locked"
"$adb" shell touch /data/local/tmp/osm-desktop-wrote

status=0
wait "$phone" || status=$?
"$adb" logcat -d -s OSMJoin:I | sed -n 's/.*\(PHONE-SYNCED-AWAY\)/\1/p' | tail -1
"$adb" logcat -d -s OSMJoin:I | sed -n 's/.*\(PHONE-HAS .*\)/\1/p' | tail -1
if [ "$status" != 0 ]; then
    tail -30 "$work/gradle.log" >&2
    exit "$status"
fi
echo "the locked phone's background sync took in the desktop's login through the relay"
