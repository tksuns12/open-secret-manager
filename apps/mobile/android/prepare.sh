#!/bin/sh
# Puts in place what the vault module is built from and tested with: the
# shared code's library for arm64 Android, its Kotlin bindings, and a copy
# of the frozen format 7 vault for the tests. None of it is committed.
#
#   apps/mobile/android/prepare.sh <scratch folder>
set -eu
cd "$(dirname "$0")"
android=$PWD
cd ../../..
work=$1

ndk=${ANDROID_NDK_HOME:-$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/ndk/* | tail -1)}
tools="$ndk/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$tools/aarch64-linux-android28-clang"
export CC_aarch64_linux_android="$tools/aarch64-linux-android28-clang"
export AR_aarch64_linux_android="$tools/llvm-ar"
cargo build --locked -q -p osm-mobile --target aarch64-linux-android

libs="$android/vault/src/main/jniLibs/arm64-v8a"
mkdir -p "$libs"
# Without debug information, which makes it several times smaller.
"$tools/llvm-strip" --strip-debug -o "$libs/libosm_mobile.so" \
    target/aarch64-linux-android/debug/libosm_mobile.so

library=target/debug/libosm_mobile.dylib
[ -f "$library" ] || library=target/debug/libosm_mobile.so
cargo run --locked -q -p osm-mobile --features bindgen --bin uniffi-bindgen -- \
    generate --library "$library" --no-format --language kotlin --out-dir "$work/kotlin"
mkdir -p "$android/vault/src/main/java/org/opensecretmanager/vault"
cp "$work/kotlin/org/opensecretmanager/vault/osm_mobile.kt" \
    "$android/vault/src/main/java/org/opensecretmanager/vault/"

for module in vault app; do
    mkdir -p "$android/$module/src/androidTest/assets"
    cp crates/vault-core/fixtures/format-7/vault.sqlite3 \
        "$android/$module/src/androidTest/assets/format-7-vault.sqlite3"
done
