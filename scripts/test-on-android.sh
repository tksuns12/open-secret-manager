#!/bin/sh
# Runs crates' tests on an Android device or emulator that adb reaches,
# built for arm64 with the Android NDK. Each crate's test programs and its
# fixtures are copied to the device, and the tests are told where the
# fixtures are (OSM_TEST_CRATE_DIR).
#
#   scripts/test-on-android.sh [crate ...]
#
# The crates default to those a phone would use: osm-vault-core,
# osm-vault-sync, osm-vault-membership, osm-vault-peer, osm-origin.
# Arguments after `--` go to every test program.
set -eu
cd "$(dirname "$0")/.."

crates=""
while [ $# -gt 0 ] && [ "$1" != "--" ]; do crates="$crates $1"; shift; done
[ "${1:-}" = "--" ] && shift
extra="$*"
crates=${crates:-osm-vault-core osm-vault-sync osm-vault-membership osm-vault-peer osm-origin}
adb=${ADB:-adb}
command -v "$adb" >/dev/null || adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
remote=/data/local/tmp/osm-tests
failed=0
# The newest NDK installed builds for Android 9 (API level 28) and later.
ndk=${ANDROID_NDK_HOME:-$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/ndk/* | tail -1)}
tools="$ndk/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$tools/aarch64-linux-android28-clang"
export CC_aarch64_linux_android="$tools/aarch64-linux-android28-clang"
export AR_aarch64_linux_android="$tools/llvm-ar"
# Programs go to the device without their debug information, which makes
# them several times smaller; a device or emulator may have little room.
stripped=$(mktemp -d)
trap 'rm -rf "$stripped"' EXIT

"$adb" shell "rm -rf $remote && mkdir -p $remote/tmp"
for crate in $crates; do
    folder=$(cargo metadata --format-version 1 --no-deps |
        node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const p=JSON.parse(s).packages.find(p=>p.name===process.argv[1]);console.log(p.manifest_path.replace(/\/Cargo\.toml$/,""))})' "$crate")
    # The crate's test programs, and the programs its tests start.
    built=$(cargo test --no-run --locked --target aarch64-linux-android -p "$crate" --message-format=json 2>/dev/null |
        node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const l of s.split("\n")){try{const m=JSON.parse(l);if(m.reason==="compiler-artifact"&&m.executable)console.log((m.profile.test?"test":m.target.name)+"\t"+m.executable)}catch{}}})')
    programs=$(printf '%s\n' "$built" | awk -F'\t' '$1 == "test" { print $2 }')
    if [ -z "$programs" ]; then
        echo "No test programs were built for $crate." >&2
        exit 1
    fi
    "$adb" shell "mkdir -p $remote/$crate"
    if [ -d "$folder/fixtures" ]; then
        "$adb" push "$folder/fixtures" "$remote/$crate/" >/dev/null
    fi
    printf '%s\n' "$built" | awk -F'\t' '$1 != "test" && $1 != "" { print }' |
        while IFS='	' read -r name program; do
            "$tools/llvm-strip" --strip-debug -o "$stripped/$name" "$program"
            "$adb" push "$stripped/$name" "$remote/$crate/$name" >/dev/null
            rm -f "$stripped/$name"
        done
    # One path a line; a path may hold spaces.
    IFS='
'
    for program in $programs; do
        name=$(basename "$program")
        "$tools/llvm-strip" --strip-debug -o "$stripped/$name" "$program"
        "$adb" push "$stripped/$name" "$remote/$crate/$name" >/dev/null
        rm -f "$stripped/$name"
        echo "== $crate: $name"
        if ! "$adb" shell "cd $remote/$crate && OSM_TEST_CRATE_DIR=$remote/$crate TMPDIR=$remote/tmp ./$name $extra 2>&1; echo \"exit \$?\"" | tee /dev/stderr | grep -q '^exit 0'; then
            failed=1
        fi
    done
    unset IFS
    "$adb" shell "rm -rf $remote/$crate"
done
"$adb" shell "rm -rf $remote"
exit $failed
