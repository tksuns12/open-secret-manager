#!/bin/sh
# Every check the project has, in one place. There is no CI: run this before
# a commit and before a release.
#
#   scripts/check.sh              what runs without the network
#   scripts/check.sh --network    also the advisory audits, npm audit, and
#                                 the licenses only the npm registry knows
#   scripts/check.sh --browsers   also the extension in headless Chromium
#                                 and Firefox (see its README)
#   scripts/check.sh --mobile     also the phone interface's bindings in an
#                                 iOS simulator and on a running Android
#                                 emulator or device
set -eu
cd "$(dirname "$0")/.."

network=no
browsers=no
mobile=no
for argument in "$@"; do
    case "$argument" in
        --network) network=yes ;;
        --browsers) browsers=yes ;;
        --mobile) mobile=yes ;;
        *) echo "unknown option: $argument" >&2; exit 2 ;;
    esac
done

desktop=apps/desktop/src-tauri/Cargo.toml
step() { printf '\n== %s\n' "$*"; }

step "Formatting"
for script in scripts/*.sh; do sh -n "$script"; done
cargo fmt --all -- --check
cargo fmt --manifest-path "$desktop" --all -- --check

step "Lints, with warnings as errors"
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path "$desktop" --workspace --all-targets --locked -- -D warnings

step "Rust tests"
cargo test --workspace --all-targets --locked
cargo test --manifest-path "$desktop" --workspace --locked

step "Desktop interface"
(cd apps/desktop && npm run --silent typecheck && npm run --silent build)

step "Browser extension"
(cd apps/browser-extension && npm run --silent typecheck && npm test && npm run --silent build)

step "Dependencies"
if [ "$network" = yes ]; then
    node scripts/dependencies.mjs
    cargo audit --deny warnings --file Cargo.lock
    cargo audit --deny warnings --file apps/desktop/src-tauri/Cargo.lock
    (cd apps/desktop && npm audit)
    (cd apps/browser-extension && npm audit)
else
    node scripts/dependencies.mjs --offline
    echo "Advisory audits skipped: they need the network (--network)."
fi

if [ "$browsers" = yes ]; then
    step "Extension in headless browsers"
    cargo build --locked -p osm-native-host -p osm-vault-browser
    (cd apps/browser-extension && npm run test:e2e && npm run test:e2e:firefox)
fi

if [ "$mobile" = yes ]; then
    step "Phone interface on a simulator and an emulator"
    scripts/test-mobile-bindings.sh
fi

step "All checks passed"
