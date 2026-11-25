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
#                       Apple Silicon Mac, one with Rosetta or emulation.
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
index=""
trap '[ -z "$container" ] || docker rm -f "$container" >/dev/null 2>&1; [ -z "$index" ] || rm -f "$index"; rm -rf "$work"' EXIT

# Export the commit (or working tree via a temporary index with
# OSM_ALLOW_CHANGES=1), avoiding any shell interpolation of filenames.
tree=$commit
if [ "${OSM_ALLOW_CHANGES:-}" = 1 ] && [ -n "$(git status --porcelain)" ]; then
    index=$(mktemp)
    cp "$(git rev-parse --git-path index)" "$index"
    GIT_INDEX_FILE=$index git add -A
    tree=$(GIT_INDEX_FILE=$index git write-tree)
    rm -f "$index"
    index=""
fi

# The Rust and the NDK that prepare-release.sh names, which refuses others.
rust=$(sed -n 's/^rust=//p' apps/mobile/android/prepare-release.sh)
ndk=$(sed -n 's/^ndk=//p' apps/mobile/android/prepare-release.sh)
docker build --platform linux/amd64 --build-arg RUST_VERSION="$rust" --build-arg NDK_VERSION="$ndk" \
    -t osm-android-build packaging/android
# Unless OSM_ANDROID_FRESH_CACHE=1 (used by scripts/reproduce-android.sh),
# Gradle and Cargo downloads are cached in named volumes between builds.
if [ "${OSM_ANDROID_FRESH_CACHE:-0}" = 1 ]; then
    container=$(docker create --platform linux/amd64 -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")" \
        osm-android-build)
else
    container=$(docker create --platform linux/amd64 -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$commit")" \
        -v osm-android-gradle:/root/.gradle -v osm-android-cargo:/root/.cargo/registry osm-android-build)
fi
# Stream the git archive directly into the container with no macOS xattrs.
git archive --format=tar "$tree" | docker cp - "$container:/src"
docker start --attach "$container"
docker cp "$container:/src/apps/mobile/android/app/build/outputs/apk/release/app-release-unsigned.apk" "$work/unsigned.apk"

name="Open-Secret-Manager-$version-android-arm64"
signed=no
if [ -n "${OSM_ANDROID_KEYSTORE:-}" ]; then
    # Signature schemes 2 and 3 (Gradle used 2 alone for the releases
    # before), no v4 file beside the APK, which nothing publishes, and the
    # APK otherwise byte for byte as built: F-Droid copies this signature
    # onto its own build and checks it there, which fails if apksigner
    # aligned the entries anew (as it does without --alignment-preserved).
    tools="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools/35.0.0"
    "$tools/apksigner" sign --ks "$OSM_ANDROID_KEYSTORE" --ks-key-alias "$OSM_ANDROID_KEY_ALIAS" \
        --ks-pass env:OSM_ANDROID_KEYSTORE_PASSWORD --key-pass env:OSM_ANDROID_KEY_PASSWORD \
        --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
        --v4-signing-enabled false --alignment-preserved --out "$out/$name.apk" "$work/unsigned.apk"
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
