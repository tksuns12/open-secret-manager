#!/bin/sh
# Builds the macOS app of the current commit twice, each time from a fresh
# export with nothing kept from the build before, and compares the lists of
# the app's files without signatures. They must be the same. Takes as long
# as two full release builds.
#
#   scripts/reproduce-macos.sh
#
# OSM_ALLOW_CHANGES=1  include the working tree's changes in both builds, to
#                      check work not yet committed.
#
# Both builds happen at the one path scripts/release-macos.sh builds at: the
# desktop app built at another path is another program (see that script).
set -eu
cd "$(dirname "$0")/.."
short=$(git rev-parse --short HEAD)
kept=$(mktemp -d)
trap 'rm -rf "$kept"' EXIT

for build in 1 2; do
    scripts/release-macos.sh
    cp "dist/macos/$short/app-contents.sha256" "$kept/$build"
done
if diff -u "$kept/1" "$kept/2"; then
    echo "Two builds of $short are the same, file for file ($(wc -l < "$kept/1" | tr -d ' ') files)."
else
    echo "Two builds of $short differ." >&2
    exit 1
fi
