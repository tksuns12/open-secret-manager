# Frozen vault files

These files pin the vault's storage formats. Tests read them with every
build (`src/fixture_tests.rs`, `src/vector_tests.rs`). They are never made
again and never edited: a test that fails because of them means the build no
longer reads what an earlier build wrote.

## What is here

| Folder | Written by commit | Vault format | Backup format |
| --- | --- | --- | --- |
| `format-1` | `a02747c` | 1 | 1 |
| `format-2` | `8294ef4` | 2 | 2 |
| `format-3` | `289d770` | 3 | 3 |
| `format-4` | `c8a755d` | 4 | 3 |
| `format-5` | `22b56b2` | 5 | 3 |
| `format-6` | `39d3563` | 6 | 4 |
| `format-7` | `fe01f0a` | 7 | 4 |

Each folder has `vault.sqlite3`, `backup.json` (a backup of that vault), and
`expected.json` (what a reader should find, with the password and the
recovery key). Each commit is the last one whose code wrote that format, and
the files were written by that commit's own, unchanged code, at the real
password hashing cost.

`vectors.json` holds the encodings the formats are built from: inputs anyone
can write down and what the code made of them. Another implementation can
check itself against it.

`SHA256SUMS` lists the binary files. Opening an older vault where it lies
upgrades it, so tests copy a file before they open it, and one test checks
the sums.

The password, the recovery keys, and every key in `vectors.json` open only
these files. None of them is a secret.

## How they were made

`examples/make_fixture.rs` writes one folder:

```text
cargo run -p osm-vault-core --example make_fixture -- <new folder> <commit>
```

For formats 1 to 6 its `basic` part alone was built inside a checkout of the
commit in the table (what `extras` uses did not exist yet). Format 7 has
both parts: besides the three items every fixture holds, it has a conflict
between two authors, a removed device, revisions held for review, a revision
staged while locked, two key epochs, a raised write fence, and a recovery
key not yet confirmed.

## When the format changes

Do not touch these folders. Add `format-8` with the new code, add its files
to `SHA256SUMS`, add the format to the tests' list, and write the test that
takes `format-7` through the upgrade. `docs/formats.md` has the whole rule.
