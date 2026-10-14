#!/bin/sh
# The desktop app's own Linux code, tested on Linux in a container: what
# the session crate hears from logind (a stand-in on a bus of the test's
# own) and what it puts on the clipboard, as another program reads it on a
# virtual display, and then as a Wayland program reads it under a headless
# Sway (which offers the data-control protocol, as wlroots and KDE do); and
# the keystore that seals the device's TLS key and keeps the count of what
# the vault's file held, with no Secret Service and with GNOME Keyring's on
# a session bus of the test's own.
#
#   scripts/test-linux.sh
#
# OSM_DOCKER_CONTEXT and OSM_LINUX_PLATFORM as for scripts/package-linux.sh.
# Tests the current commit; OSM_ALLOW_CHANGES=1 tests the working tree as
# it is, new files included (through an index of its own: the repository's
# is left alone).
set -eu
cd "$(dirname "$0")/.."

platform=${OSM_LINUX_PLATFORM:-linux/amd64}
docker() { command docker ${OSM_DOCKER_CONTEXT:+--context "$OSM_DOCKER_CONTEXT"} "$@"; }

tree=HEAD
if [ -n "$(git status --porcelain)" ]; then
    if [ "${OSM_ALLOW_CHANGES:-}" != 1 ]; then
        echo "The working tree has changes: set OSM_ALLOW_CHANGES=1 to test them." >&2
        exit 1
    fi
    index=$(mktemp)
    cp "$(git rev-parse --git-path index)" "$index"
    GIT_INDEX_FILE=$index git add -A
    tree=$(GIT_INDEX_FILE=$index git write-tree)
    rm -f "$index"
fi

docker build --platform "$platform" -t osm-linux-build packaging/linux
docker build --platform "$platform" -t osm-linux-test - <<'EOF'
FROM osm-linux-build
RUN apt-get update \
 && apt-get install -y --no-install-recommends dbus xvfb xclip sway wl-clipboard gnome-keyring \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m tester
EOF
# Sway refuses to run as root, so it runs as `tester`; the tests, as root,
# can still reach its socket.
container=$(docker create --platform "$platform" osm-linux-test sh -c '
    set -e
    Xvfb :99 -screen 0 1024x768x24 >/tmp/xvfb.log 2>&1 &
    sleep 1
    cd apps/desktop/src-tauri
    DISPLAY=:99 cargo test --locked -p osm-desktop-session
    mkdir -p /tmp/wayland && chown tester /tmp/wayland && chmod 700 /tmp/wayland
    echo "xwayland disable" > /tmp/sway.config
    runuser -u tester -- env XDG_RUNTIME_DIR=/tmp/wayland WLR_BACKENDS=headless \
        WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman sway -c /tmp/sway.config >/tmp/sway.log 2>&1 &
    tries=0
    until [ -S /tmp/wayland/wayland-1 ]; do
        tries=$((tries + 1))
        [ "$tries" -le 60 ] || { cat /tmp/sway.log; exit 1; }
        sleep 0.5
    done
    env -u DISPLAY XDG_RUNTIME_DIR=/tmp/wayland WAYLAND_DISPLAY=wayland-1 OSM_TEST_WAYLAND=1 \
        cargo test --locked -p osm-desktop-session --test wayland
    env -u DBUS_SESSION_BUS_ADDRESS cargo test --locked --lib -- --ignored \
        keystore::tests::without rows_seen::tests::without
    dbus-run-session -- sh -c "printf unlock | gnome-keyring-daemon --unlock --components=secrets >/dev/null \
        && cargo test --locked --lib -- --ignored keystore::tests::the_system rows_seen::tests::the_system"')
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

git archive --format=tar "$tree" | docker cp - "$container:/src"
docker start --attach "$container"
