#!/bin/sh
# Builds the Linux package (.deb) of the desktop app from the current commit,
# in a container, and puts it in dist/linux/. Linux is built but not
# verified; see docs/release.md.
#
#   scripts/package-linux.sh
#
# OSM_DOCKER_CONTEXT names the Docker context to build in (default: the
# current one), and OSM_LINUX_PLATFORM the system to build for (default:
# linux/amd64; linux/arm64 also works). OSM_ALLOW_CHANGES=1 builds the last
# commit even though the working tree has changes, which are left out.
set -eu
cd "$(dirname "$0")/.."

platform=${OSM_LINUX_PLATFORM:-linux/amd64}
docker() { command docker ${OSM_DOCKER_CONTEXT:+--context "$OSM_DOCKER_CONTEXT"} "$@"; }

if [ -n "$(git status --porcelain)" ] && [ "${OSM_ALLOW_CHANGES:-}" != 1 ]; then
    echo "The working tree has changes: a package is built from a commit." >&2
    exit 1
fi
commit=$(git rev-parse HEAD)
epoch=$(git log -1 --format=%ct)
out="dist/linux/$(git rev-parse --short "$commit")"
mkdir -p "$out"

docker build --platform "$platform" -t osm-linux-build packaging/linux
container=$(docker create --platform "$platform" -e SOURCE_DATE_EPOCH="$epoch" osm-linux-build)
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

# Only what the commit holds goes in.
git archive --format=tar "$commit" | docker cp - "$container:/src"
docker start --attach "$container"
docker cp "$container:/src/apps/desktop/src-tauri/target/release/bundle/deb/." - | tar -x -C "$out"

(cd "$out" && shasum -a 256 -- *.deb > SHA256SUMS)
printf 'commit %s\nplatform %s\nbuilt %s\n' "$commit" "$platform" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/build-info.txt"
echo "Built into $out (unverified: no Linux desktop has run it)."
cat "$out/SHA256SUMS"
