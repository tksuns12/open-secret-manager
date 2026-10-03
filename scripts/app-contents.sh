#!/bin/sh
# Lists every file of a macOS app with its SHA-256, after taking the code
# signatures out of a copy, so that two builds of one commit can be compared
# whether, and by whom, they were signed.
#
#   scripts/app-contents.sh <path to .app>
set -eu
app=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ditto --norsrc --noextattr --noacl "$app" "$work/app"
# What signing adds: the seal of the bundle, and a signature in each program.
find "$work/app" -name _CodeSignature -type d -prune -exec rm -rf {} +
find "$work/app" -type f -perm -u+x | while IFS= read -r file; do
    if file -b "$file" | grep -q '^Mach-O'; then
        codesign --remove-signature "$file"
    fi
done
cd "$work/app"
find . -type f | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
done
