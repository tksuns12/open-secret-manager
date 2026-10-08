#!/bin/sh
# The real desktop app, end to end, on Linux in a container: built in debug
# with its window built in, then driven through that window by tauri-driver
# and WebKitWebDriver on a virtual display, as several devices each with a
# home folder of its own (apps/desktop/e2e). The system's file dialogs are
# answered with xdotool. macOS has no driver for its web view, so this runs
# only here.
#
#   scripts/test-linux-app.sh
#
# OSM_DOCKER_CONTEXT and OSM_LINUX_PLATFORM as for scripts/package-linux.sh.
# Tests the current commit; OSM_ALLOW_CHANGES=1 tests the working tree as
# it is, new files included. The Rust build is kept in Docker volumes
# (osm-linux-app-target, osm-linux-app-cargo), so later runs build only
# what changed. With OSM_TEST_FAILURES naming a folder, what the windows
# showed when a wait ran out is brought back into its linux-app folder.
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
docker build --platform "$platform" -t osm-linux-app-test - <<'EOF'
FROM osm-linux-build
RUN apt-get update \
 && apt-get install -y --no-install-recommends dbus xvfb xdotool webkit2gtk-driver \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked tauri-driver
EOF
container=$(docker create --platform "$platform" \
    -v osm-linux-app-target:/src/apps/desktop/src-tauri/target \
    -v osm-linux-app-cargo:/root/.cargo/registry \
    -e OSM_E2E_TRACES=/tmp/traces \
    osm-linux-app-test sh -c '
    set -e
    Xvfb :99 -screen 0 1400x900x24 >/tmp/xvfb.log 2>&1 &
    export DISPLAY=:99
    cd apps/desktop
    npm ci --no-audit --no-fund
    npx tauri build --debug --no-bundle
    npm run --silent test:app')
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

git archive --format=tar "$tree" | docker cp - "$container:/src"
status=0
docker start --attach "$container" || status=$?
if [ "$status" != 0 ] && [ -n "${OSM_TEST_FAILURES:-}" ]; then
    mkdir -p "$OSM_TEST_FAILURES/linux-app"
    docker cp "$container:/tmp/traces/." "$OSM_TEST_FAILURES/linux-app" 2>/dev/null \
        && echo "What the windows showed: $OSM_TEST_FAILURES/linux-app" >&2
fi
exit "$status"
