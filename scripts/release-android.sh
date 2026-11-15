#!/bin/sh
# Builds the Android release of the phone app from the current commit and
# puts in dist/android/<commit>/: the APK to install, its SHA-256, the list
# of the APK's files without its signature (apk-contents.sha256, what a rebuild is compared with), and what
# built it. See docs/release.md.
#
#   scripts/release-android.sh
#
# OSM_ANDROID_KEYSTORE  the owner's keystore, with OSM_ANDROID_KEYSTORE_PASSWORD,
#                       OSM_ANDROID_KEY_ALIAS, and OSM_ANDROID_KEY_PASSWORD.
#                       Without it the APK is unsigned, and
#                       no phone installs the APK until it is signed.
# OSM_ALLOW_CHANGES=1   build although the working tree has changes, which
#                       are then built too; the result is not a release.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

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

# From an export of the commit at one fixed path, as the macOS release.
build=/private/tmp/open-secret-manager-android-release
rm -rf "$build"
mkdir -p "$build"
git archive --format=tar "$commit" | tar -x -C "$build"
if [ "${OSM_ALLOW_CHANGES:-}" = 1 ]; then
    git diff --binary HEAD | (cd "$build" && git apply --allow-empty)
    git ls-files --others --exclude-standard -z |
        xargs -0 -I{} sh -c 'mkdir -p "$(dirname "$1/{}")" && cp -p "{}" "$1/{}"' _ "$build"
fi

# The shared code's library as F-Droid's build server makes it too.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$commit")
export SOURCE_DATE_EPOCH
"$build/apps/mobile/android/prepare-release.sh"
(cd "$build/apps/mobile/android" && ./gradlew --quiet --no-build-cache :app:assembleRelease)

outputs="$build/apps/mobile/android/app/build/outputs"
signed=no
if [ -n "${OSM_ANDROID_KEYSTORE:-}" ]; then
    signed=yes
    apk="$outputs/apk/release/app-release.apk"
else
    apk="$outputs/apk/release/app-release-unsigned.apk"
fi
name="Open-Secret-Manager-$version-android-arm64"
cp "$apk" "$out/$name.apk"

# Each file in the APK with its SHA-256, the signature's own files left out.
unzip -Z1 "$out/$name.apk" | grep -Ev '^META-INF/([^/]+\.(SF|RSA|EC|DSA)|MANIFEST\.MF)$' | LC_ALL=C sort |
    while IFS= read -r entry; do
        printf '%s  %s\n' "$(unzip -p "$out/$name.apk" "$entry" | shasum -a 256 | cut -d' ' -f1)" "$entry"
    done >"$out/apk-contents.sha256"

(cd "$out" && shasum -a 256 -- *.apk > SHA256SUMS)
rust=$(sed -n 's/^rust=//p' apps/mobile/android/prepare-release.sh)
ndk=$(sed -n 's/^ndk=//p' apps/mobile/android/prepare-release.sh)
{
    echo "commit $commit"
    if [ -n "$(git status --porcelain)" ]; then echo "with uncommitted changes: not a release"; fi
    echo "version $version"
    echo "architecture arm64-v8a"
    echo "built at $build"
    echo "signed $signed"
    echo "source date $SOURCE_DATE_EPOCH"
    echo "NDK $ndk"
    sed -n 's/^distributionUrl=.*gradle-\(.*\)-all.zip/Gradle \1/p' apps/mobile/android/gradle/wrapper/gradle-wrapper.properties
    java -version 2>&1 | head -1
    RUSTUP_TOOLCHAIN="$rust" rustc --version
    RUSTUP_TOOLCHAIN="$rust" cargo --version
} > "$out/build-info.txt"
echo "Built into $out"
cat "$out/SHA256SUMS"
