# Getting started

Open Secret Manager is a password manager with no account and no server.
Your passwords live in an encrypted vault on each of your devices, and the
devices keep each other up to date directly. This page takes you from
nothing to a computer, a browser, and a phone sharing one vault.

Two things differ from the password managers you may know, and the rest of
this page follows from them:

- **A vault is made on a computer**, and a phone joins it from there. A phone
  cannot make a vault of its own.
- **Devices sync only when one can reach the other**: on the same Wi-Fi
  network, over a VPN you run, or through a relay you run
  ([how devices reach each other, and how to run a relay](reaching-devices.md)). A phone that is away from home
  on mobile data does not sync with your home computer until it is back,
  unless you set one of those up. Nothing is lost meanwhile; the phone keeps
  its own copy and catches up.

The project is young, and nobody outside it has reviewed its design or code
yet. Keep a copy of your passwords somewhere else too, at least at first.
See the [status in the README](../README.md).

## 1. Install the desktop app

Take the app for your computer from
[Releases](https://github.com/tksuns12/open-secret-manager/releases); the
[README](../README.md#getting-it) lists what is supported (macOS 14 or later
on Apple Silicon, and a Linux `.deb` that has not yet been tried on a Linux
desktop; Windows is not released: its code is built and tested, but there is
no installer and nobody has used it there).

The app is not notarized by Apple, as the project joins no vendor's paid
program. On a Mac, the first time you open it
macOS refuses: open **System Settings › Privacy & Security** and choose
**Open Anyway** for it, then open it again. Drag the app into **Applications**
and open it from there: the browser connection in step 4 does not work from
the disk image.

## 2. Create your vault

1. Open the app. It says *Create your encrypted vault*.
2. Choose this computer's password, **at least 12 characters**. It protects
   this computer's copy only; the other devices each have a password of their
   own, and there is no master account behind them. Nobody can reset it for
   you; the recovery key below can, on a computer.
3. The app then shows your **recovery key**, which begins `OSM-RK1-`. Write
   it on paper and keep it away from your devices. It opens your backups, and
   it is the way back in if you forget this computer's password or lose every
   device. The app
   shows it again after every unlock until you confirm that you stored it.

Keep the key and your backups in different places: together they are the
whole vault.

## 3. Bring in your passwords

You can start empty and add logins as you go, with **New item**. To bring in
the ones you have, choose the import button above the list and pick where
they come from:

| From | Export it as |
| --- | --- |
| Bitwarden | An unencrypted JSON export |
| Chrome | Passwords exported as CSV |
| Firefox | Logins exported as CSV |

The app shows what the import would add, and adds nothing until you confirm.
These exports hold your passwords in plain text: delete the file once the
import is done.

## 4. Connect your browser

The extension fills a login into the page you are on, when you press it,
through the desktop app, which has to be running. It does not save new
logins: add those in the app, or on a phone.

1. Install it: for Chromium-based browsers from the
   [Chrome Web Store](https://chromewebstore.google.com/detail/pnjdoenkfffomcidikbkcegcpgipdjog),
   for Firefox from
   [Firefox's add-ons site](https://addons.mozilla.org/addon/open-secret-manager/).
2. In the desktop app, open **Browser** and connect that browser.

The extension's own page, with what it does and does not do, is
[its README](../apps/browser-extension/README.md).

## 5. Add your phone

1. Install the app on the phone: on Android 9 or later (a 64-bit ARM phone,
   which most phones sold in recent years are; a 32-bit one cannot install
   it), from
   [F-Droid](https://f-droid.org/packages/org.opensecretmanager.app/) once
   it is accepted there, or the APK from Releases. For an iPhone there is no
   download: it is built with Xcode and signed with your own Apple developer
   team ([how](phone-trial.md#getting-the-app-onto-the-phone)).
2. Put the phone and the computer on **the same Wi-Fi network**.
3. In the desktop app open **Devices**, choose **Invite a device**, and pick
   a phone. A QR code appears.
4. In the phone app's *Join your vault* screen, choose **Scan the QR code**,
   allow the camera, and point it at the code. (Or bring the invitation's
   text to the phone some way you control, and paste it. It is good for one
   join and only together with the next step.) On an iPhone, allow the app to
   find devices on the local network when it asks; without that it cannot
   reach the computer.
5. Both screens show **six digits**. Confirm on the computer only if they
   are the same, and press **Codes match** on the phone: that is what tells
   you the phone is yours and nobody sat between the two.
6. Choose the phone's own password, at least 12 characters.

The items appear on the phone within a minute, and the computer's Devices
panel lists the phone. From then on, a change on one reaches the other while
the phone's app is open, or at once with **Sync now**. On Android the phone
also syncs now and then while the app is closed.

The phone can show, copy, create and edit logins, cards and notes, and fill
logins into other apps and pages (on Android, turn that on under **Settings**
in the app, *Fill logins in other apps*). Identities are shown on the phone,
and edited on a computer.

## 6. Make it safe to lose a device

- **Back up the vault**: *Back up* in the desktop app's sidebar, to a place of
  your choice. The file is encrypted and opens only with the recovery key.
  The app reminds you when it has been a month, and a day after a new vault
  was made without one.
- **Keep the recovery key** on paper, away from the backups.
- **If a phone is lost**: on the computer, in Devices, choose **Remove** on
  it. A phone does not vote, so with one voting computer that computer alone
  can do it; with two, both must be online. Then change the
  passwords of the logins that mattered, since the lost phone could have read
  them.

[Disaster recovery](disaster-recovery.md) goes through each case: a lost
device, a forgotten password, every device lost, and what each gives back.

## Words you will meet

- **Vault**: your items, encrypted. Every device holds a full copy.
- **Device password**: unlocks one device's copy. Each device has its own.
- **Recovery key** (`OSM-RK1-…`): opens backups and replaces a forgotten
  computer password. A device that joined later has recovery off until the
  key is entered once in its Devices panel, and a phone cannot use it at all:
  a phone whose password is forgotten is removed and joined again. Keep the
  key on paper.
- **Invitation**: what a new device uses to join: a phone scans its QR code,
  a computer pastes its text. Good for one join.
- **A device that votes**: your computers, unless you invite one as "often
  off". They decide together when devices are added or removed, so with two
  voting computers both must be reachable for that. A phone does not vote.
- **Relay**: a small program you run yourself, that lets devices reach each
  other across networks without being able to read what they say.
