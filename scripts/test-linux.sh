#!/bin/sh
# The desktop app's own Linux code, tested on Linux in a container: what
# the session crate hears from logind (a stand-in on a bus of the test's
# own) and what it puts on the clipboard, as another program reads it on a
# virtual display.
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
 && apt-get install -y --no-install-recommends dbus xvfb xclip \
 && rm -rf /var/lib/apt/lists/*
EOF
container=$(docker create --platform "$platform" osm-linux-test sh -c '
    Xvfb :99 -screen 0 1024x768x24 >/tmp/xvfb.log 2>&1 &
    export DISPLAY=:99
    sleep 1
    cd apps/desktop/src-tauri && cargo test --locked -p osm-desktop-session')
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

git archive --format=tar "$tree" | docker cp - "$container:/src"
docker start --attach "$container"
