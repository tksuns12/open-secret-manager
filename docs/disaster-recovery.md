# Disaster recovery

This is for the owner of a vault: what to keep so that the vault survives
losing devices, what to do when something is lost, and what each step gives
back. The last section records the exercise that was run on these steps and
what it did not cover.

## What to keep

- **The recovery key** (`OSM-RK1-…`). The app shows it when a vault is
  created, and again after every unlock until you confirm that you stored
  it. Write it down and keep it offline, away from your devices. It opens
  backups, and it unlocks any device of the vault that has recovery turned
  on. Starting over and restoring a backup each make a new vault with a new
  recovery key; keep the old key as long as you keep backups made before,
  because only it opens them.
- **A recent backup.** In the app, unlocked: *Back up* in the sidebar, then
  choose where to save. The file holds every item with its history,
  encrypted, and opens only with the recovery key, not with a password. The
  app reads it back as soon as it is written and says how many items and
  versions it holds. Keep it apart from the recovery key (a backup and the
  key together are the vault) and apart from your devices, for example on a
  USB drive kept elsewhere. Changes made after a backup are not in it, so
  make a new one after important changes. The app never replaces a file: a
  new backup needs a new name.
- **Each device's password.** Each device has its own; forgetting one is
  recoverable with the recovery key (below).

A device that joined from another one starts with recovery turned off. It
cannot write a backup or reset its password until the recovery key is
entered once in its Devices panel.

## What to do

| What happened | What to do | What you get back | What is lost |
| --- | --- | --- | --- |
| You forgot one device's password | On its lock screen: *Forgot the password? Use the recovery key*. Enter the key and a new password. | That device, unlocked, with the new password. Your other devices keep their own passwords. | Nothing. If recovery is off on that device, remove it from another device and join it again instead. |
| One device is lost or stolen, and most of your devices are still reachable | On another device: *Devices*, then *Remove* on the lost one. Most of the devices that vote must be online for this; with two voting devices, both must be. A device that does not vote, such as a phone, never counts, so one voting computer removes a lost phone alone. | The vault moves to a new key the lost device never receives. | The lost device keeps what it had. Change the passwords stored in the vault that matter, since it could have read them. |
| Too many devices are lost to remove them, and one is left | On the one left: *Devices*, then *Start over as a new vault*, with its password. | A new vault with every item as that device shows it, a new recovery key, and that device as its only member. The old vault is moved to an archive folder beside it. Your other devices join the new vault by invitation. | Earlier history in the new vault (the archived copy keeps it). Edits that never reached this device. |
| Every device is lost | On a new computer, install the app. On its first screen: *Restore from a backup instead*. Choose the backup file, enter the recovery key and a new password for this computer. | A new vault with every item as it was in the backup, a new recovery key (shown once, and after each unlock until you confirm it), and this computer as its only member. The backup as it was, with its whole history, is in the *Archive*, where the new password opens it. Other new devices join by invitation. | Changes made after the backup. Changes held for review in the backup stay in the archived copy. |
| A device's vault file cannot be opened (damaged, or written by a newer version of the app) | The app says so on its first screen. If a newer version wrote it, install that version. Otherwise *Put it away*: the file moves, untouched, to an archive folder. Then join from another of your devices, or restore a backup if none is left. | A device without a vault, ready to join or restore. | What only that file held. |
| An old device turns up after you started over or restored | On it: *Devices*, then put its copy away. It then joins the new vault by invitation. | The device, in the new vault. | Its edits that never reached the new vault stay in its archived copy, from which the *Archive* dialog can copy items across. |

Nothing in these steps deletes a vault. Everything set aside goes to an
`archive-<time>` folder beside the vault, where the *Archive* dialog lists
it.

Starting over and restoring are not ways around your devices' agreement.
They make a new vault, and the old one's devices are not part of it until
they join.

## What these steps do not protect against

- A backup is as old as the moment it was made. The app does not remind you
  to make one and does not keep track of when you last did.
- Losing every device and every backup, or every backup and the recovery
  key, loses the vault. There is no copy anywhere else, by design.
- Anyone who has the recovery key and a backup, or the key and a device's
  vault file, can read the vault as it was in that file.
- A lost device keeps what it had. Removing it, starting over, or restoring
  stops it from receiving anything new; it does not take back what it
  already read.

## The exercise

Run on 2026-10-03, on macOS 26 (Darwin 25.6.0), with the app's own code
through its commands on Tauri's mock runtime: everything but the window.
It is automated in `apps/desktop/src-tauri/src/backup_tests.rs` and runs
with every `scripts/check.sh`, so it is repeated on every check.

1. A device created a vault and stored an item edited twice, an item that
   was then deleted, and a third item.
2. It saved a backup. Reading it back reported 3 items and 6 versions.
   Saving again under the same name was refused and left the file as it
   was; saving while locked was refused.
3. The device was shut down, standing for a lost computer.
4. On a second device with no vault: restoring without choosing a backup was
   refused; a text that is not a recovery key was refused; another vault's
   recovery key opened nothing and left no file and no archive folder.
5. With the right key and a new password, the backup was restored. The new
   vault showed both live items, the edited one with its last password; it
   had a new vault ID and a new recovery key, kept until confirmed; this
   device was its only member.
6. The archived copy opened in the Archive with the new password and showed
   both items. The old recovery key opened it too, and it held all 6
   versions under the old vault's identity.
7. A second restore on the same device was refused: it now had a vault.
8. A third device joined the restored vault by invitation and received both
   items. It could not write a backup, since recovery was off on it.
9. Separately: a device whose vault file had been overwritten with bytes
   that are no vault reported why it could not be opened. Restoring and
   creating a vault over it were refused, and the file was left as it was.
   *Put it away* moved it, unchanged, with the device's peer store, to an
   archive folder; the device then restored the backup.
10. Separately: a locked device given a text that is not a recovery key, and
    then another vault's key, stayed locked; given its own key and a new
    password, it unlocked; after locking, the old password was refused and
    the new one worked.

All of it passed, in 12 seconds.

Not covered by the exercise:

- The save and open dialogs, and the screens for restoring, for a forgotten
  password, and for a vault that cannot be opened, were not seen in a running
  window. The screen of the development machine was locked throughout.
- No restore was done on a second physical computer, and no backup was kept
  on removable media or carried between machines.
- The steps for a lost device, starting over, and an old device that turns
  up rest on earlier tests (see the delivery matrix in
  [implementation-status.md](implementation-status.md)), not on this
  exercise.
