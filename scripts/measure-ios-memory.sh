#!/bin/sh
# Measures how much memory the iOS app and its AutoFill extension use when
# they unlock a vault made at the real password-hashing cost (Argon2id,
# 64 MiB), in a simulator of their own: iOS ends an AutoFill extension
# that uses more than it allows, reportedly about 120 MB. Prints each
# process's largest footprint, which the system tracks.
#
#   scripts/measure-ios-memory.sh
#
# OSM_IOS_OPTIMIZED=1 measures the apps built optimized, as a release.
#
# A simulator runs on this Mac's processor and enforces no limit: a phone's
# numbers may differ.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
sampler=""
cleanup() {
    if [ -n "$sampler" ]; then
        kill "$sampler" 2>/dev/null || true
        wait "$sampler" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

cargo build --locked -q -p osm-vault-peer --bin osm-peer
export OSM_PASSWORD="measured password"
target/debug/osm-peer create "$work/vault.sqlite3"
target/debug/osm-peer add "$work/vault.sqlite3" Mail

# Each process's footprint and its peak, every half second.
(while :; do
    for name in "OpenSecretManager.app/OpenSecretManager" "AutoFill.appex/AutoFill"; do
        for pid in $(pgrep -f "Containers/Bundle/Application/.*/$name" || true); do
            footprint --noCategories -f bytes -p "$pid" 2>/dev/null |
                sed -n "s/.*phys_footprint_peak: \([0-9]*\).*/$(basename "$name") \1/p"
        done
    done
    sleep 0.5
done) >"$work/samples" &
sampler=$!

OSM_TEST_MEMORY_VAULT="$work/vault.sqlite3" OSM_TEST_MEMORY_PASSWORD="$OSM_PASSWORD" \
    scripts/test-mobile-ios.sh MemoryTests
for process in OpenSecretManager AutoFill; do
    peak=$(awk -v p="$process" '$1 == p && $2 > max { max = $2 } END { print max + 0 }' "$work/samples")
    [ "$peak" -gt 0 ] || { echo "no sample of $process" >&2; exit 1; }
    echo "$process: at most $(( peak / 1048576 )) MiB"
done
