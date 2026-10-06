#!/bin/sh
# Puts in place what the vault module is built from and tested with: the
# shared code's library for arm64 Android, its Kotlin bindings, and the
# vaults the tests open: a copy of the frozen format 7 vault, and two made
# from the format 8 one. None of it is committed.
#
#   apps/mobile/android/prepare.sh <scratch folder> [release]
#
# release  the library built optimized, as a release has it.
set -eu
cd "$(dirname "$0")"
android=$PWD
cd ../../..
work=$1
profile=debug
[ "${2:-}" = release ] && profile=release

ndk=${ANDROID_NDK_HOME:-$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/ndk/* | tail -1)}
tools="$ndk/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$tools/aarch64-linux-android28-clang"
export CC_aarch64_linux_android="$tools/aarch64-linux-android28-clang"
export AR_aarch64_linux_android="$tools/llvm-ar"
# For this machine too: the bindings are generated from that library.
cargo build --locked -q -p osm-mobile
if [ "$profile" = release ]; then
    cargo build --locked -q --release -p osm-mobile --target aarch64-linux-android
else
    cargo build --locked -q -p osm-mobile --target aarch64-linux-android
fi

libs="$android/vault/src/main/jniLibs/arm64-v8a"
mkdir -p "$libs"
# Without debug information, which makes it several times smaller.
"$tools/llvm-strip" --strip-debug -o "$libs/libosm_mobile.so" \
    "target/aarch64-linux-android/$profile/libosm_mobile.so"

library=target/debug/libosm_mobile.dylib
[ -f "$library" ] || library=target/debug/libosm_mobile.so
cargo run --locked -q -p osm-mobile --features bindgen --bin uniffi-bindgen -- \
    generate --library "$library" --no-format --language kotlin --out-dir "$work/kotlin"
mkdir -p "$android/vault/src/main/java/org/opensecretmanager/vault"
cp "$work/kotlin/org/opensecretmanager/vault/osm_mobile.kt" \
    "$android/vault/src/main/java/org/opensecretmanager/vault/"

# A sealed vault with an earlier version of Mail taken out of its file, as
# anyone who can write the file could, for the screens that say so.
take_out() {
    cp crates/vault-core/fixtures/format-8/vault.sqlite3 "$1"
    sqlite3 "$1" "DROP TRIGGER revisions_no_delete; DELETE FROM revisions WHERE revision IN \
        (SELECT revision FROM revisions WHERE item_id='fixture-mail' AND parents='');"
}
for module in vault app; do
    mkdir -p "$android/$module/src/androidTest/assets"
    cp crates/vault-core/fixtures/format-7/vault.sqlite3 \
        "$android/$module/src/androidTest/assets/format-7-vault.sqlite3"
done
take_out "$android/app/src/androidTest/assets/sealed-taken-out-vault.sqlite3"
# A vault with a card and an identity, which no frozen vault holds and a
# phone cannot make, for the screens that show an item's other fields.
cargo run --locked -q -p osm-mobile --example cards_vault -- \
    crates/vault-core/fixtures/format-8 "$android/app/src/androidTest/assets/cards-vault.sqlite3"
