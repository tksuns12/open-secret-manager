#!/bin/sh
# Coverage-guided fuzzing of the parsers that take outside input
# (`fuzz/fuzz_targets/`), with cargo-fuzz and libFuzzer on a nightly
# toolchain:
#
#   rustup toolchain install nightly --profile minimal
#   cargo install cargo-fuzz --locked
#
#   scripts/fuzz.sh [seconds per target] [target ...]
#
# Each target runs for the time given (60 seconds if none), one after the
# other, starting from inputs made from the frozen fixtures and from what
# earlier runs found, kept in fuzz/corpus/<target> (not committed). An
# input that breaks a target is left in fuzz/artifacts/<target>, and the
# script stops there with libFuzzer's status. Not part of scripts/check.sh.
set -eu
cd "$(dirname "$0")/.."
seconds=${1:-60}
[ $# -gt 0 ] && shift
targets=${*:-origin recovery_key invitation peer_messages browser_messages import}

python3 - <<'EOF'
import json, os
here = "fuzz/corpus"
def seed(target, name, data):
    os.makedirs(f"{here}/{target}", exist_ok=True)
    with open(f"{here}/{target}/seed-{name}", "wb") as out:
        out.write(data if isinstance(data, bytes) else data.encode())
pairing = json.load(open("crates/vault-peer/fixtures/pairing.json"))
sync = json.load(open("crates/vault-peer/fixtures/sync.json"))
messages = json.load(open("crates/browser-link/fixtures/messages.json"))
for index, text in enumerate(["https://example.com", "https://example.com:8443", "https://bücher.example/login?x=1",
                              "https://user@example.com/", "http://example.com", "https://[::1]:8443", "https://127.0.0.1"]):
    seed("origin", str(index), text)
for vectors in ["crates/vault-core/fixtures/vectors.json", "crates/vault-core/fixtures/vectors-8.json"]:
    for index, key in enumerate(sorted(set(__import__("re").findall(r"OSM-RK1-[A-Za-z0-9_-]+", open(vectors).read())))):
        seed("recovery_key", f"{os.path.basename(vectors)}-{index}", key)
seed("invitation", "frozen", pairing["invitation_text"])
for name in ["join_request", "enrollment_grant", "enrollment_grant_with_nothing_optional"]:
    body = bytes.fromhex(pairing[name]["sent"]["body"])
    seed("peer_messages", name, body)
for name, value in sync.items():
    if isinstance(value, dict):
        seed("peer_messages", name, bytes.fromhex(value["body"]))
        seed("peer_messages", f"{name}-frame", bytes.fromhex(value["frame"]))
for name, text in messages["from_extension"].items():
    seed("browser_messages", name, text)
seed("import", "bitwarden", b"\x00" + json.dumps({"encrypted": False, "items": [{"type": 1, "name": "Bank", "notes": "n",
    "login": {"username": "a", "password": "p", "totp": "JBSWY3DPEHPK3PXP", "uris": [{"uri": "https://bank.example"}]},
    "fields": [{"name": "PIN", "value": "1234", "type": 1}]}, {"type": 2, "name": "Note", "notes": "text"}]}).encode())
seed("import", "chrome", b"\x01name,url,username,password,note\nBank,https://bank.example,a,p,\"multi\nline\"\n")
seed("import", "firefox", b"\x02url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
     b"https://bank.example,a,p,,https://bank.example,{x},1,2,3\n")
EOF

for target in $targets; do
    echo "== $target, $seconds seconds"
    cargo +nightly fuzz run "$target" "fuzz/corpus/$target" --fuzz-dir fuzz -- \
        -max_total_time="$seconds" -print_final_stats=1 2>&1 \
        | grep -E "^#[0-9]+[[:space:]]+(INITED|DONE)|^stat::number_of_executed_units|^stat::peak_rss|^==[0-9]+== ERROR|panicked|SUMMARY|Test unit written|^Done" || true
    if ls "fuzz/artifacts/$target"/* >/dev/null 2>&1; then
        echo "$target broke on what is in fuzz/artifacts/$target" >&2
        exit 1
    fi
done
