# Mobile feasibility spike (Phase 6b)

Whether the vault's Rust code runs on phones as it is, what it costs there,
and what that means for the mobile apps. Run on 2026-10-03 on an Android
emulator and an iOS simulator on the development Mac. No phone was used:
none is attached to this machine.

## What ran

The five crates a phone would use: `osm-vault-core` (the vault),
`osm-vault-sync` (key envelopes and invitations), `osm-vault-membership`
(the control plane), `osm-vault-peer` (pairing, sync, and the members'
channel over TLS), and `osm-origin`.

| Where | Tests |
| --- | --- |
| Android 16 emulator (Pixel 9 Pro XL image, arm64, 2 GB), built with NDK 29 for API level 28 | 178 passed, none failed: 76 in the vault and 2 crash tests that kill a process writing to a vault; 20 in sync; 23 in membership; 46 in peer, and 3 that run separate `osm-peer` device processes on the emulator which enroll, sync, remove a device, lose quorum, and take part while locked; 8 in origin |
| iOS 26.3 simulator (iPhone 17), built for `aarch64-apple-ios-sim` | The same 178 passed, none failed |

`scripts/test-on-android.sh` and `scripts/test-on-ios-simulator.sh` run
them again. The frozen-format tests ran too: the test programs read the
fixture copies pushed with them (`OSM_TEST_CRATE_DIR`).

No code had to change for the crates to build or pass on either system:
SQLite (built from source), the TLS stack (rustls with ring), and Argon2
built with the NDK's and Xcode's compilers as they are. The only changes
were in tests and scripts: where the tests find their fixture files and the
`osm-peer` program when they run on another machine.

## What a vault costs

`cargo run --release -p osm-vault-core --example unlock_cost` makes a vault,
stores 100 items, and unlocks it three times, at the real password hashing
cost (Argon2id, 64 MiB, three passes).

| Where | Make a vault | Unlock | List 100 items | Peak memory |
| --- | --- | --- | --- | --- |
| This Mac (Apple M1), idle | 114 ms | 89 to 94 ms | 6 ms | 71.5 MB |
| iOS simulator | 126 ms | 95 to 101 ms | 6 ms | not read there |
| Android emulator | 497 ms | 202 to 206 ms | 13 to 15 ms | 71.1 MB |

The emulator and the simulator run on the Mac's own processor, so these are
not a phone's numbers. A phone is slower; how much slower was not measured.
Memory is set by the password hashing, which takes 64 MiB on every system,
so the peak is about the same everywhere.

## What it means for the apps

- **Memory in the iOS AutoFill extension.** iOS fills passwords from an app
  extension, which gets much less memory than an app: about 120 MB,
  according to KeePassium's measurements
  (https://keepassium.com/articles/autofill-memory-limits/). An unlock
  peaks at about 70 MB before the extension's own interface. That fits, but
  not by much, and must be measured in the extension on a phone. Each
  device has its own password wrapper, so a phone can use a lower hashing
  cost without changing any other device, and a phone can unlock with a key
  the system keeps behind biometrics instead of hashing the password each
  time.
- **Android fills in the app's own process**, so the same limit does not
  apply there.
- **The code can be shared as it is.** The apps need a narrow interface to
  it (unlock, list, read, copy, pair, sync) and native shells for what only
  the system offers: autofill, secure key storage, lifecycle.
- **Membership.** Every member today is a voter, so a phone that is off or
  out of reach counts against the majority every change needs. Phones should
  be members that receive keys and sync without voting, which the control
  plane does not support yet.

## Not done

No real phone; no app around the code; no autofill; no measurement inside an
extension or under a phone's memory pressure; no background sync.
