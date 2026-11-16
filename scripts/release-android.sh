#!/bin/sh
# Builds the Android release of the phone app from the current commit, in a
# container that is x86_64 Debian as F-Droid's build server is
# (packaging/android/Dockerfile), signs it here, and puts in
# dist/android/<commit>/: the APK to install, its SHA-256, the list of the
# APK's files without its signature (apk-contents.sha256, what a rebuild is
# compared with), and what built it. See docs/release.md.
#
#   scripts/release-android.sh
#
# OSM_ANDROID_KEYSTORE  the owner's keystore, with OSM_ANDROID_KEYSTORE_PASSWORD,
#                       OSM_ANDROID_KEY_ALIAS, and OSM_ANDROID_KEY_PASSWORD:
#                       the APK is signed with it on this machine, after the
#                       build; the key never goes into the container.
#                       Without it the APK is unsigned, and no phone installs
#                       it until it is signed.
# OSM_DOCKER_CONTEXT    the Docker context to build in (default: the current
#                       one). It must run linux/amd64 containers: on an
#                       Apple Silicon Mac, a colima machine with Rosetta.
# OSM_ALLOW_CHANGES=1   build although the working tree has changes, which
#                       are then built too; the result is not a release.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
docker() { command docker ${OSM_DOCKER_CONTEXT:+--context "$OSM_DOCKER_CONTEXT"} "$@"; }

if [ -n "$(git status --porcelain)" ] && [ "${OSM_ALLOW_CHANGES:-}" != 1 ]; then
    echo "The working tree has changes: a release is built from a commit." >&2
    exit 1
fi
commit=$(git rev-parse HEAD)
short=$(git rev-parse --short HEAD)
version=$(sed -n 's/.*versionName = "\(.*\)".*/\1/p' apps/mobile/android/app/build.gradle.kts)
out="$root/dist/android/$short"
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
container=""
trap '[ -z "$container" ] || docker rm -f "$container" >/dev/null 2>&1; rm -rf "$work"' EXIT

# What the commit holds, and with OSM_ALLOW_CHANGES the working tree's
# changes too.
mkdir "$work/src"
git archive --format=tar "$commit" | tar -x -C "$work/src"
if [ "${OSM_ALLOW_CHANGES:-}" = 1 ]; then
    git diff --binary HEAD | (cd "$work/src" && git apply --allow-empty)
    git ls-files --others --exclude-standard -z |
        xargs -0 -I{} sh -c 'mkdir -p "$(dirname "$1/{}")" && cp -p "{}" "$1/{}"' _ "$work/src"
fi

# The Rust and the NDK that prepare-release.sh names, which refuses others.
rust=$(sed -n 's/^rust=//p' apps/mobile/android/prepare-release.sh)
ndk=$(sed -n 's/^ndk=//p' apps/mobile/android/prepare-release.sh)
docker build --platform linux/amd64 --build-arg RUST_VERSION="$rust" --build-arg NDK_VERSION="$ndk" \
    -t osm-android-build packaging/android
# What Gradle and Cargo download is kept between builds; it changes nothing
# they build.
container=$(docker create --platform linux/amd64 -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")" \
    -v osm-android-gradle:/root/.gradle -v osm-android-cargo:/root/.cargo/registry osm-android-build)
# Without the Mac's extended attributes, which the container cannot take.
COPYFILE_DISABLE=1 tar --no-xattrs -C "$work/src" -c . | docker cp - "$container:/src"
docker start --attach "$container"
docker cp "$container:/src/apps/mobile/android/app/build/outputs/apk/release/app-release-unsigned.apk" "$work/unsigned.apk"

name="Open-Secret-Manager-$version-android-arm64"
signed=no
if [ -n "${OSM_ANDROID_KEYSTORE:-}" ]; then
    # Signature schemes 2 and 3, as Gradle signs an app for Android 9 and
    # later: the APK's own files are left as built.
    tools="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools/35.0.0"
    "$tools/apksigner" sign --ks "$OSM_ANDROID_KEYSTORE" --ks-key-alias "$OSM_ANDROID_KEY_ALIAS" \
        --ks-pass env:OSM_ANDROID_KEYSTORE_PASSWORD --key-pass env:OSM_ANDROID_KEY_PASSWORD \
        --v1-signing-enabled false --out "$out/$name.apk" "$work/unsigned.apk"
    "$tools/apksigner" verify "$out/$name.apk"
    signed=yes
else
    cp "$work/unsigned.apk" "$out/$name.apk"
fi

# Each file in the APK with its SHA-256, the signature's own files left out.
unzip -Z1 "$out/$name.apk" | grep -Ev '^META-INF/([^/]+\.(SF|RSA|EC|DSA)|MANIFEST\.MF)$' | LC_ALL=C sort |
    while IFS= read -r entry; do
        printf '%s  %s\n' "$(unzip -p "$out/$name.apk" "$entry" | shasum -a 256 | cut -d' ' -f1)" "$entry"
    done >"$out/apk-contents.sha256"

(cd "$out" && shasum -a 256 -- *.apk > SHA256SUMS)
{
    echo "commit $commit"
    if [ -n "$(git status --porcelain)" ]; then echo "with uncommitted changes: not a release"; fi
    echo "version $version"
    echo "architecture arm64-v8a"
    echo "built in packaging/android/Dockerfile (linux/amd64)"
    echo "signed $signed"
    echo "source date $(git log -1 --format=%ct "$commit")"
    echo "NDK $ndk"
    sed -n 's/^distributionUrl=.*gradle-\(.*\)-all.zip/Gradle \1/p' apps/mobile/android/gradle/wrapper/gradle-wrapper.properties
    docker run --rm --platform linux/amd64 osm-android-build sh -c 'java -version 2>&1 | head -1; rustc --version; cargo --version'
} > "$out/build-info.txt"
echo "Built into $out"
cat "$out/SHA256SUMS"
