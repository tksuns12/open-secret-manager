#!/bin/sh
# Builds the Android release of the current commit twice, each time from a
# fresh export, and compares the lists of the APK's files without its
# signature. They must be the same.
#
#   scripts/reproduce-android.sh
#
# OSM_ALLOW_CHANGES=1  include the working tree's changes in both builds.
set -eu
cd "$(dirname "$0")/.."
short=$(git rev-parse --short HEAD)
kept=$(mktemp -d)
trap 'rm -rf "$kept"' EXIT

for build in 1 2; do
    OSM_ANDROID_FRESH_CACHE=1 scripts/release-android.sh
    cp "dist/android/$short/apk-contents.sha256" "$kept/$build"
done
if diff -u "$kept/1" "$kept/2"; then
    echo "Two builds of $short are the same, file for file ($(wc -l < "$kept/1" | tr -d ' ') files)."
else
    echo "Two builds of $short differ." >&2
    exit 1
fi
