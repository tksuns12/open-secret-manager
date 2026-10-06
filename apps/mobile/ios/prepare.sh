#!/bin/sh
# Puts in place what the iOS project is built from and tested with: the
# shared code's static library for the simulator and for iPhones, as
# build/OSMVaultFFI.xcframework, its Swift bindings, and a copy of the
# frozen format 7 vault for the UI tests. None of it is committed.
#
#   apps/mobile/ios/prepare.sh <scratch folder> [release]
#
# release  the libraries built optimized, as a release has them.
set -eu
cd "$(dirname "$0")"
ios=$PWD
cd ../../..
work=$1
profile=debug
[ "${2:-}" = release ] && profile=release

# The oldest iOS the app is meant for, for the C code built with it too.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
cargo build --locked -q -p osm-mobile
for target in aarch64-apple-ios-sim aarch64-apple-ios; do
    if [ "$profile" = release ]; then
        cargo build --locked -q --release -p osm-mobile --target "$target"
    else
        cargo build --locked -q -p osm-mobile --target "$target"
    fi
done

library=target/debug/libosm_mobile.dylib
cargo run --locked -q -p osm-mobile --features bindgen --bin uniffi-bindgen -- \
    generate --library "$library" --no-format --language swift --out-dir "$work/swift"
mkdir -p "$work/headers" "$ios/build" "$ios/Shared/Generated"
cp "$work/swift/OSMVaultFFI.h" "$work/headers/"
cp "$work/swift/OSMVaultFFI.modulemap" "$work/headers/module.modulemap"
cp "$work/swift/OSMVault.swift" "$ios/Shared/Generated/"

# Without debug information, which makes the libraries several times larger.
for target in aarch64-apple-ios-sim aarch64-apple-ios; do
    mkdir -p "$work/$target"
    strip -S -o "$work/$target/libosm_mobile.a" "target/$target/$profile/libosm_mobile.a" 2>/dev/null
done
rm -rf "$ios/build/OSMVaultFFI.xcframework"
xcodebuild -create-xcframework \
    -library "$work/aarch64-apple-ios-sim/libosm_mobile.a" -headers "$work/headers" \
    -library "$work/aarch64-apple-ios/libosm_mobile.a" -headers "$work/headers" \
    -output "$ios/build/OSMVaultFFI.xcframework" >/dev/null

mkdir -p "$ios/UITests/Fixtures"
cp crates/vault-core/fixtures/format-7/vault.sqlite3 "$ios/UITests/Fixtures/format-7-vault.sqlite3"
# A sealed vault with an earlier version of Mail taken out of its file, as
# anyone who can write the file could, for the screens that say so.
take_out() {
    cp crates/vault-core/fixtures/format-8/vault.sqlite3 "$1"
    sqlite3 "$1" "DROP TRIGGER revisions_no_delete; DELETE FROM revisions WHERE revision IN \
        (SELECT revision FROM revisions WHERE item_id='fixture-mail' AND parents='');"
}
take_out "$ios/UITests/Fixtures/sealed-taken-out-vault.sqlite3"
