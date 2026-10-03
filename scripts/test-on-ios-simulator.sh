#!/bin/sh
# Runs crates' tests in an iOS simulator, built for it (aarch64-apple-ios-sim,
# `rustup target add aarch64-apple-ios-sim`). The simulator is made for the
# run in a device set of its own, booted without a window, and deleted
# afterwards; your own simulators are not touched. The test programs and
# each crate's fixtures are copied to a temporary folder first, and the
# tests are told where the fixtures are (OSM_TEST_CRATE_DIR).
#
#   scripts/test-on-ios-simulator.sh [crate ...] [-- test arguments]
#
# The crates default to those a phone would use: osm-vault-core,
# osm-vault-sync, osm-vault-membership, osm-vault-peer, osm-origin.
# OSM_SIMULATOR_TYPE and OSM_SIMULATOR_RUNTIME pick the device (default:
# iPhone 17 and the newest iOS runtime installed).
set -eu
cd "$(dirname "$0")/.."

crates=""
while [ $# -gt 0 ] && [ "$1" != "--" ]; do crates="$crates $1"; shift; done
[ "${1:-}" = "--" ] && shift
extra="$*"
crates=${crates:-osm-vault-core osm-vault-sync osm-vault-membership osm-vault-peer osm-origin}
kind=${OSM_SIMULATOR_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17}
runtime=${OSM_SIMULATOR_RUNTIME:-$(xcrun simctl list runtimes -j | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s).runtimes.filter(r=>r.platform==="iOS"&&r.isAvailable);console.log(r[r.length-1].identifier)})')}

# Copies on the internal disk: a simulator may wait without end for a file
# on an external one, asking for a permission nobody answers.
work=$(mktemp -d)
set_dir="$work/devices"
mkdir -p "$set_dir"
device=$(xcrun simctl --set "$set_dir" create "Open Secret Manager tests" "$kind" "$runtime")
cleanup() {
    xcrun simctl --set "$set_dir" shutdown "$device" >/dev/null 2>&1 || true
    xcrun simctl --set "$set_dir" delete "$device" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
xcrun simctl --set "$set_dir" boot "$device"
xcrun simctl --set "$set_dir" bootstatus "$device" -b >/dev/null

failed=0
for crate in $crates; do
    folder=$(cargo metadata --format-version 1 --no-deps |
        node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const p=JSON.parse(s).packages.find(p=>p.name===process.argv[1]);console.log(p.manifest_path.replace(/\/Cargo\.toml$/,""))})' "$crate")
    # The crate's test programs, and the programs its tests start.
    built=$(cargo test --no-run --locked --target aarch64-apple-ios-sim -p "$crate" --message-format=json 2>/dev/null |
        node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const l of s.split("\n")){try{const m=JSON.parse(l);if(m.reason==="compiler-artifact"&&m.executable)console.log((m.profile.test?"test":m.target.name)+"\t"+m.executable)}catch{}}})')
    programs=$(printf '%s\n' "$built" | awk -F'\t' '$1 == "test" { print $2 }')
    if [ -z "$programs" ]; then
        echo "No test programs were built for $crate." >&2
        exit 1
    fi
    mkdir -p "$work/$crate/tmp"
    if [ -d "$folder/fixtures" ]; then
        cp -R "$folder/fixtures" "$work/$crate/"
    fi
    printf '%s\n' "$built" | awk -F'\t' '$1 != "test" && $1 != "" { print }' |
        while IFS='	' read -r name program; do
            cp "$program" "$work/$crate/$name"
        done
    # One path a line; a path may hold spaces.
    IFS='
'
    for program in $programs; do
        name=$(basename "$program")
        cp "$program" "$work/$crate/$name"
        echo "== $crate: $name"
        # The simulator passes on variables named with this prefix.
        if ! SIMCTL_CHILD_OSM_TEST_CRATE_DIR="$work/$crate" SIMCTL_CHILD_TMPDIR="$work/$crate/tmp" \
            xcrun simctl --set "$set_dir" spawn "$device" "$work/$crate/$name" $extra; then
            failed=1
        fi
    done
    unset IFS
done
exit $failed
