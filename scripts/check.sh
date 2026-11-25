#!/bin/sh
# Every check the project has, in one place. There is no CI: run this before
# a commit and before a release.
#
#   scripts/check.sh              what runs without the network, the
#                                 desktop window's tests in headless WebKit
#                                 included (once: npx playwright install
#                                 webkit, in apps/desktop)
#   scripts/check.sh --network    also the advisory audits, npm audit, and
#                                 the licenses only the npm registry knows
#   scripts/check.sh --browsers   also the extension in headless Chromium
#                                 and Firefox (see its README)
#   scripts/check.sh --mobile     also the phone interface's bindings in an
#                                 iOS simulator, and those and the Android
#                                 app on a running emulator or device
#                                 (OSM_DEVICE_PIN if it has a screen lock)
#   scripts/check.sh --linux      also the desktop's Linux code in a Linux
#                                 container (scripts/test-linux.sh) and the
#                                 real app driven end to end there
#                                 (scripts/test-linux-app.sh), on the
#                                 working tree, on the current Docker
#                                 context (OSM_DOCKER_CONTEXT names another)
#   scripts/check.sh --fuzz       also coverage fuzzing of the parsers
#                                 (scripts/fuzz.sh, on a nightly
#                                 toolchain), OSM_FUZZ_SECONDS per target
#                                 (300 if unset: half an hour in all); what
#                                 it finds is added to fuzz/corpus, to be
#                                 committed
set -eu
cd "$(dirname "$0")/.."

network=no
browsers=no
mobile=no
linux=no
fuzz_run=no
for argument in "$@"; do
    case "$argument" in
        --network) network=yes ;;
        --browsers) browsers=yes ;;
        --mobile) mobile=yes ;;
        --linux) linux=yes ;;
        --fuzz) fuzz_run=yes ;;
        *) echo "unknown option: $argument" >&2; exit 2 ;;
    esac
done

desktop=apps/desktop/src-tauri/Cargo.toml
# The fuzz targets are formatted, linted, and audited here, and run only
# with --fuzz: running them needs a nightly toolchain (scripts/fuzz.sh).
fuzz=fuzz/Cargo.toml
step() { printf '\n== %s\n' "$*"; }

step "Formatting"
for script in scripts/*.sh apps/mobile/*/*.sh; do sh -n "$script"; done
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck scripts/*.sh apps/mobile/*/*.sh
else
    echo "shellcheck not installed; skipped."
fi
cargo fmt --all -- --check
cargo fmt --manifest-path "$desktop" --all -- --check
cargo fmt --manifest-path "$fuzz" --all -- --check

step "Lints, with warnings as errors"
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path "$desktop" --workspace --all-targets --locked -- -D warnings
cargo clippy --manifest-path "$fuzz" --all-targets --locked -- -D warnings

step "Rust tests"
cargo test --workspace --all-targets --locked
cargo test --manifest-path "$desktop" --workspace --locked

step "Desktop interface"
(cd apps/desktop && npm run --silent typecheck && npm run --silent build && npm run --silent test:window)

step "Browser extension"
(cd apps/browser-extension && npm run --silent typecheck && npm test && npm run --silent build)
node --test scripts/publish-extension.test.mjs

step "Dependencies"
if [ "$network" = yes ]; then
    node scripts/dependencies.mjs
    cargo audit --deny warnings --file Cargo.lock
    cargo audit --deny warnings --file apps/desktop/src-tauri/Cargo.lock
    cargo audit --deny warnings --file fuzz/Cargo.lock
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

if [ "$fuzz_run" = yes ]; then
    step "Coverage fuzzing, ${OSM_FUZZ_SECONDS:-300} seconds per target"
    scripts/fuzz.sh "${OSM_FUZZ_SECONDS:-300}"
fi

# Before the phones: an emulator can be killed for memory while one runs.
if [ "$linux" = yes ]; then
    step "Desktop's Linux code in a container"
    OSM_ALLOW_CHANGES=1 scripts/test-linux.sh
    OSM_ALLOW_CHANGES=1 scripts/test-linux-app.sh
fi

if [ "$mobile" = yes ]; then
    step "Phone interface on a simulator and an emulator"
    scripts/test-mobile.sh
fi

step "All checks passed"
