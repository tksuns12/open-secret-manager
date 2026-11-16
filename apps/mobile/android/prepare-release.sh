#!/bin/sh
# Puts in place what a release of the Android app is built from, as
# prepare.sh does, in such a way that two x86_64 Linux machines build the
# same library from the same commit: the container of
# scripts/release-android.sh (packaging/android/Dockerfile), and F-Droid's
# build server, which builds the app from source and publishes the APK the
# owner signed only if what it built is the same, file for file
# (docs/release.md). `./gradlew :app:assembleRelease` then builds the APK.
# Another kind of machine builds another library: Cargo puts the machine's
# kind into every crate's hash, and rustc orders functions by names that
# carry those hashes.
#
#   apps/mobile/android/prepare-release.sh
set -eu
cd "$(dirname "$0")"
android=$PWD
root=$(cd ../../.. && pwd)

# The Rust and the NDK a release is built with: other versions build
# another library. scripts/release-android.sh reads them from here.
rust=1.95.0
ndk=30.0.16248370
export RUSTUP_TOOLCHAIN="$rust"
case $(rustc --version) in
"rustc $rust "*) ;;
*)
    echo "A release is built with Rust $rust, not $(rustc --version)." >&2
    exit 1
    ;;
esac
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk/$ndk}"
if [ "$(sed -n 's/^Pkg\.Revision *= *//p' "$ANDROID_NDK_HOME/source.properties" 2>/dev/null)" != "$ndk" ]; then
    echo "A release is built with NDK $ndk, which is not at $ANDROID_NDK_HOME." >&2
    exit 1
fi

# No clock and no folder of the machine that builds it in the library: the
# time of the commit, which scripts/release-android.sh gives, as it builds
# from an export of the commit that is no repository.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
sep=$(printf '\037')
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$root=/osm$sep--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$android/prepare.sh" "$work" release
