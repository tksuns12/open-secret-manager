#!/bin/sh
# Builds the browser extension from the current commit and puts in
# dist/extension/<commit>/ what the browsers' stores take: the Firefox
# add-on for addons.mozilla.org, the Chromium extension for the Chrome Web
# Store, and the source AMO's reviewers rebuild it from. See
# apps/browser-extension/README.md.
#
#   scripts/package-extension.sh
#
# The Chrome Web Store gives an extension an ID of its own and takes no
# `key` in its manifest, so the package for it leaves the key out; the
# extension loaded unpacked keeps the ID the key gives it.
# OSM_ALLOW_CHANGES=1 builds although the working tree has changes; the
# source archive is still the commit's.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

if [ -n "$(git status --porcelain)" ] && [ "${OSM_ALLOW_CHANGES:-}" != 1 ]; then
    echo "The working tree has changes: the extension is packaged from a commit." >&2
    exit 1
fi
commit=$(git rev-parse HEAD)
short=$(git rev-parse --short HEAD)
version=$(node -p 'require("./apps/browser-extension/manifest.firefox.json").version')
chromium_version=$(node -p 'require("./apps/browser-extension/manifest.chromium.json").version')
if [ "$version" != "$chromium_version" ]; then
    echo "The manifests have two versions (Firefox $version, Chromium $chromium_version): make them one." >&2
    exit 1
fi
out="$root/dist/extension/$short"
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd apps/browser-extension && npm ci --no-audit --no-fund >/dev/null && npm run -s build)

# One file, its entries in a fixed order and without the Mac's metadata.
pack() {
    (cd "$1" && find . -type f ! -name .DS_Store | LC_ALL=C sort | sed 's|^\./||' |
        COPYFILE_DISABLE=1 zip -q -X -@ "$2")
}
pack apps/browser-extension/dist/firefox "$out/open-secret-manager-firefox-$version.zip"
cp -R apps/browser-extension/dist/chromium "$work/chromium"
node -e '
const fs = require("fs");
const path = process.argv[1];
const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
delete manifest.key;
fs.writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
' "$work/chromium/manifest.json"
pack "$work/chromium" "$out/open-secret-manager-chromium-$version.zip"
git archive --format=zip --prefix=open-secret-manager-extension/ -o "$out/open-secret-manager-extension-$version-source.zip" \
    "$commit" apps/browser-extension LICENSE

(cd "$out" && shasum -a 256 -- *.zip > SHA256SUMS)
{
    echo "commit $commit"
    if [ -n "$(git status --porcelain)" ]; then echo "with uncommitted changes: not a release"; fi
    echo "version $version"
    echo "node $(node --version), npm $(npm --version)"
} > "$out/build-info.txt"
echo "Packaged into $out"
cat "$out/SHA256SUMS"
