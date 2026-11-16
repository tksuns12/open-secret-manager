#!/bin/sh
# Builds the macOS release of the desktop app from the current commit and
# puts in dist/macos/<commit>/: the disk image holding the app, its SHA-256,
# the list of the app's files without signatures (app-contents.sha256, what
# a rebuild is compared with), and what built it. See docs/release.md.
#
#   scripts/release-macos.sh
#
# OSM_SIGNING_IDENTITY  a "Developer ID Application: ..." identity in the
#                       keychain. Without one the app is signed ad hoc: it
#                       runs on this Mac, and macOS refuses it on another
#                       once downloaded.
# OSM_NOTARY_PROFILE    a notarytool keychain profile (made once with
#                       `xcrun notarytool store-credentials`). With it and an
#                       identity the disk image is notarized and stapled.
# OSM_ALLOW_CHANGES=1   build although the working tree has changes, which
#                       are then built too; the result is not a release.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

if [ -n "$(git status --porcelain)" ] && [ "${OSM_ALLOW_CHANGES:-}" != 1 ]; then
    echo "The working tree has changes: a release is built from a commit." >&2
    exit 1
fi
if [ -n "${OSM_NOTARY_PROFILE:-}" ] && [ -z "${OSM_SIGNING_IDENTITY:-}" ]; then
    echo "Notarizing needs a signing identity (OSM_SIGNING_IDENTITY)." >&2
    exit 1
fi
commit=$(git rev-parse HEAD)
short=$(git rev-parse --short HEAD)
version=$(node -p "require('./apps/desktop/src-tauri/tauri.conf.json').version")
arch=$(uname -m)
out="$root/dist/macos/$short"
rm -rf "$out"
mkdir -p "$out"

# The commit is built from an export of it at one fixed path. Cargo puts the
# absolute path of the crates the desktop app takes from outside its own
# workspace into the app's symbols, so the same commit built at another path
# makes another program.
build=/private/tmp/open-secret-manager-release
rm -rf "$build"
mkdir -p "$build"
git archive --format=tar "$commit" | tar -x -C "$build"
if [ "${OSM_ALLOW_CHANGES:-}" = 1 ]; then
    git diff --binary HEAD | (cd "$build" && git apply --allow-empty)
    git ls-files --others --exclude-standard -z |
        xargs -0 -I{} sh -c 'mkdir -p "$(dirname "$1/{}")" && cp -p "{}" "$1/{}"' _ "$build"
fi

# No clock and no home folder in what is built. Paths are also taken out of
# the symbol table the linker computes the program's UUID from (strip
# removes that table only afterwards).
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export ZERO_AR_DATE=1
sep=$(printf '\037')
# And without chained fixups: with the app's minimum macOS (14.0, which
# Tauri gives the build as MACOSX_DEPLOYMENT_TARGET), Xcode 27.2's linker
# writes the proc macros' libraries with them, and Rust 1.95 then refuses
# its own macro libraries ("can't find crate for `zeroize_derive`").
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$build=/osm$sep--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo$sep-Clink-arg=-Wl,-oso_prefix,$build/$sep-Clink-arg=-Wl,-no_fixup_chains"
if [ -n "${OSM_SIGNING_IDENTITY:-}" ]; then
    # Tauri signs the app and the host inside it, with the hardened runtime.
    export APPLE_SIGNING_IDENTITY="$OSM_SIGNING_IDENTITY"
fi
(cd "$build/apps/desktop" && npm ci --no-audit --no-fund && npm run tauri:build -- --bundles app)

app="$build/apps/desktop/src-tauri/target/release/bundle/macos/Open Secret Manager.app"
scripts/app-contents.sh "$app" > "$out/app-contents.sha256"
if [ -z "${OSM_SIGNING_IDENTITY:-}" ]; then
    # With the hardened runtime, as a release is signed.
    codesign --force --deep --options runtime --sign - "$app"
fi
codesign --verify --deep --strict "$app"

# The disk image: the app and a link to the Applications folder.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
ditto "$app" "$stage/Open Secret Manager.app"
ln -s /Applications "$stage/Applications"
dmg="$out/Open-Secret-Manager-$version-macos-$arch.dmg"
hdiutil create -quiet -volname "Open Secret Manager" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"
notarized=no
if [ -n "${OSM_SIGNING_IDENTITY:-}" ]; then
    codesign --sign "$OSM_SIGNING_IDENTITY" --timestamp "$dmg"
    if [ -n "${OSM_NOTARY_PROFILE:-}" ]; then
        xcrun notarytool submit "$dmg" --keychain-profile "$OSM_NOTARY_PROFILE" --wait
        xcrun stapler staple "$dmg"
        notarized=yes
    fi
fi

(cd "$out" && shasum -a 256 -- *.dmg > SHA256SUMS)
{
    echo "commit $commit"
    if [ -n "$(git status --porcelain)" ]; then echo "with uncommitted changes: not a release"; fi
    echo "version $version"
    echo "architecture $arch"
    echo "built at $build"
    echo "signed ${OSM_SIGNING_IDENTITY:-ad hoc}"
    echo "notarized $notarized"
    echo "source date $SOURCE_DATE_EPOCH"
    echo "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    xcrun clang --version | head -1
    rustc --version
    cargo --version
    echo "node $(node --version), npm $(npm --version)"
} > "$out/build-info.txt"
echo "Built into $out"
cat "$out/SHA256SUMS"
