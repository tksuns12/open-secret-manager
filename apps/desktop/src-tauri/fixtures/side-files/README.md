The files the desktop app keeps beside the vault, as this code wrote them
when they were frozen (Phase 13), read back by `src/side_files_tests.rs`:

- `settings.json`: the auto-lock time set to 15 minutes.
- `backups.json`: a backup of the vault `abab…ab` saved at 1791500000, a
  day after the device began counting.
- `putting-away`: the marker of a copy being put away so that the device can
  join another vault (`left`), and the archive folder it is going to. The
  file names an absolute path; `@DIR@` stands for the vault's folder, which
  the test fills in.

None is made again: to add one, run the tests with `OSM_WRITE_NEW_FIXTURES=1`
while it does not exist.
