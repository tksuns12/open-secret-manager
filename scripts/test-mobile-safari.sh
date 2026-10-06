#!/bin/sh
# The iOS app filling and saving in real Safari, not a stand-in, in a
# simulator.
#
#   scripts/test-mobile-safari.sh <folder kept between runs>
#
# Serves the test site (scripts/test-site.py) on 127.0.0.1:8443, which the
# simulator reaches as https://localhost:8443, with its certificates from
# the folder (scripts/test-site-certs.sh makes them on the first run, and
# scripts/test-mobile-chrome.sh shares them); runs SafariTests in a
# simulator of its own that trusts the folder's certificate authority
# (scripts/test-mobile-ios.sh, through OSM_IOS_ROOT_CERT); and checks what
# the site received. Nothing is set up by hand: the simulator is made for
# the run and deleted after.
set -eu
cd "$(dirname "$0")/.."
keep=${1:?usage: scripts/test-mobile-safari.sh <folder kept between runs>}
mkdir -p "$keep"
keep=$(cd "$keep" && pwd)
scripts/test-site-certs.sh "$keep" >/dev/null

work=$(mktemp -d)
python3 scripts/test-site.py "$keep" >"$work/site.out" 2>&1 &
site=$!
trap 'kill "$site" 2>/dev/null || true; wait "$site" 2>/dev/null || true; rm -rf "$work"' EXIT
: >"$keep/server.log"

status=0
OSM_IOS_ROOT_CERT="$keep/ca.crt" OSM_TEST_SAFARI_SITE=https://localhost:8443 \
    scripts/test-mobile-ios.sh SafariTests || status=$?
echo "the site received:"
cat "$keep/server.log"
[ "$status" = 0 ] || exit "$status"

# What Safari sent is what the vault filled, and what was typed.
grep -qx 'LOGIN username=site-user password=site-pass-1' "$keep/server.log"
grep -qx 'LOGIN username=new-user password=new-pass-1' "$keep/server.log"
echo "Safari filled the login, and the login typed into it was saved"
