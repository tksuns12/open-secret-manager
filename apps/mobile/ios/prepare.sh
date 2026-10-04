#!/bin/sh
# Puts in place what the iOS project is built from and tested with: the
# shared code's static library for the simulator and for iPhones, as
# build/OSMVaultFFI.xcframework, its Swift bindings, and a copy of the
# frozen format 7 vault for the UI tests. None of it is committed.
#
#   apps/mobile/ios/prepare.sh <scratch folder>
set -eu
cd "$(dirname "$0")"
ios=$PWD
cd ../../..
work=$1

# The oldest iOS the app is meant for, for the C code built with it too.
export IPHONEOS_DEPLOYMENT_TARGET=17.0
cargo build --locked -q -p osm-mobile
cargo build --locked -q -p osm-mobile --target aarch64-apple-ios-sim
cargo build --locked -q -p osm-mobile --target aarch64-apple-ios

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
    strip -S -o "$work/$target/libosm_mobile.a" "target/$target/debug/libosm_mobile.a" 2>/dev/null
done
rm -rf "$ios/build/OSMVaultFFI.xcframework"
xcodebuild -create-xcframework \
    -library "$work/aarch64-apple-ios-sim/libosm_mobile.a" -headers "$work/headers" \
    -library "$work/aarch64-apple-ios/libosm_mobile.a" -headers "$work/headers" \
    -output "$ios/build/OSMVaultFFI.xcframework" >/dev/null

mkdir -p "$ios/UITests/Fixtures"
cp crates/vault-core/fixtures/format-7/vault.sqlite3 "$ios/UITests/Fixtures/format-7-vault.sqlite3"
