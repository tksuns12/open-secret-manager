#!/bin/sh
# Builds the iOS release of the phone app from the current commit into
# dist/ios/<commit>/. With an Apple developer team: a signed archive and the
# IPA exported from it for App Store Connect (TestFlight or the App Store).
# Without one: the app built for iPhones, unsigned, which shows that the
# release builds but installs nowhere. See docs/release.md.
#
#   scripts/release-ios.sh
#
# OSM_APPLE_TEAM       the team's ID. Xcode signs with the team's
#                      certificates and makes the profiles it needs, so an
#                      account of the team must be signed in to Xcode.
# OSM_ALLOW_CHANGES=1  build although the working tree has changes, which
#                      are then built too; the result is not a release.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

if [ -n "$(git status --porcelain)" ] && [ "${OSM_ALLOW_CHANGES:-}" != 1 ]; then
    echo "The working tree has changes: a release is built from a commit." >&2
    exit 1
fi
icon=$(apps/mobile/ios/icon-flags.sh)
if [ -n "${OSM_APPLE_TEAM:-}" ] && [ -n "$icon" ]; then
    echo "Xcode lacks the simulator runtime its asset compiler needs for the app icon:" >&2
    echo "install it with \`xcodebuild -downloadPlatform iOS\` before a signed release." >&2
    exit 1
fi
commit=$(git rev-parse HEAD)
short=$(git rev-parse --short HEAD)
version=$(sed -n 's/.*MARKETING_VERSION = \([^;]*\);.*/\1/p' apps/mobile/ios/OpenSecretManager.xcodeproj/project.pbxproj | head -1)
out="$root/dist/ios/$short"
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
index=""
trap '[ -z "$index" ] || rm -f "$index"; rm -rf "$work"' EXIT

# Export the commit (or working tree with OSM_ALLOW_CHANGES=1) inside the
# private temporary directory so no predictable /private/tmp path is shared.
build="$work/src"
mkdir -m 0700 "$build"
tree=$commit
if [ "${OSM_ALLOW_CHANGES:-}" = 1 ] && [ -n "$(git status --porcelain)" ]; then
    index=$(mktemp)
    cp "$(git rev-parse --git-path index)" "$index"
    GIT_INDEX_FILE=$index git add -A
    tree=$(GIT_INDEX_FILE=$index git write-tree)
    rm -f "$index"
    index=""
fi
git archive --format=tar "$tree" | tar -x -C "$build"

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
export ZERO_AR_DATE=1
sep=$(printf '\037')
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$build=/osm$sep--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
"$build/apps/mobile/ios/prepare.sh" "$work/prepare" release
cd "$build/apps/mobile/ios"
name="Open-Secret-Manager-$version-ios"
if [ -n "${OSM_APPLE_TEAM:-}" ]; then
    xcodebuild -project OpenSecretManager.xcodeproj -scheme OpenSecretManager -configuration Release \
        -destination generic/platform=iOS -archivePath "$out/$name.xcarchive" -derivedDataPath "$work/derived" \
        -allowProvisioningUpdates CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$OSM_APPLE_TEAM" -quiet archive
    cat > "$work/export.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>app-store-connect</string>
	<key>teamID</key>
	<string>$OSM_APPLE_TEAM</string>
	<key>signingStyle</key>
	<string>automatic</string>
	<key>destination</key>
	<string>export</string>
</dict>
</plist>
PLIST
    xcodebuild -exportArchive -archivePath "$out/$name.xcarchive" -exportPath "$work/export" \
        -exportOptionsPlist "$work/export.plist" -allowProvisioningUpdates -quiet
    cp "$work/export/OpenSecretManager.ipa" "$out/$name.ipa"
    (cd "$out" && shasum -a 256 -- *.ipa > SHA256SUMS)
    signed="team $OSM_APPLE_TEAM"
else
    # shellcheck disable=SC2086
    xcodebuild -project OpenSecretManager.xcodeproj -target OpenSecretManager -sdk iphoneos -configuration Release \
        SYMROOT="$work/sym" OBJROOT="$work/obj" CODE_SIGNING_ALLOWED=NO $icon -quiet build 2>&1 |
        grep -v appintentsmetadataprocessor || true
    [ -d "$work/sym/Release-iphoneos/OpenSecretManager.app" ] || { echo "the iOS release did not build" >&2; exit 1; }
    ditto -c -k --keepParent "$work/sym/Release-iphoneos/OpenSecretManager.app" "$out/$name-unsigned.zip"
    (cd "$out" && shasum -a 256 -- *.zip > SHA256SUMS)
    signed="no: built to check, installs nowhere"
fi
cd "$root"
{
    echo "commit $commit"
    if [ -n "$(git status --porcelain)" ]; then echo "with uncommitted changes: not a release"; fi
    echo "version $version"
    echo "built at $build"
    echo "signed $signed"
    if [ -n "$icon" ]; then echo "without the app icon: this Mac lacks the simulator runtime Xcode needs for it"; fi
    echo "source date $SOURCE_DATE_EPOCH"
    xcodebuild -version | tr '\n' ' '; echo
    rustc --version
    cargo --version
} > "$out/build-info.txt"
echo "Built into $out"
cat "$out/SHA256SUMS"
