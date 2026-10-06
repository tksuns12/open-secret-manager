# Trying the phone apps on real phones

The phone apps have run only on an Android 16 emulator and in an iOS 26.3
simulator on this Mac (see the Android and iOS rows of
[implementation-status.md](implementation-status.md)). This is what is left
to see on real phones, in the order it is easiest to do, with what should
happen. Note what happens instead, with the phone's model and system
version.

## Getting the app onto the phone

**Android** (Android 9 or later, a 64-bit ARM phone, which nearly every
phone sold since 2019 is):

- Quickest, for a trial: turn on the phone's developer options and USB
  debugging, connect it, run `apps/mobile/android/prepare.sh "$(mktemp -d)"`,
  then `./gradlew :app:installDebug` in `apps/mobile/android`. A debug build
  can be captured in screenshots only if built with `-Posm.screenshots=true`.
- As released: make a keystore once (`keytool -genkeypair -keystore
  release.jks -alias release -keyalg EC -groupname secp256r1 -validity 10000`)
  and keep it safe: an update must be signed with the same key. Then run
  `scripts/release-android.sh` with `OSM_ANDROID_KEYSTORE`,
  `OSM_ANDROID_KEYSTORE_PASSWORD`, `OSM_ANDROID_KEY_ALIAS`, and
  `OSM_ANDROID_KEY_PASSWORD` set, and install the APK from
  `dist/android/<commit>/` with `adb install`, or open it on the phone.

**iOS** (iOS 17 or later):

- An Apple developer team is needed to run the app on any iPhone. With the
  team's account signed in to Xcode, open `apps/mobile/ios` after running
  `apps/mobile/ios/prepare.sh "$(mktemp -d)"`, choose the team under Signing
  for the app and its AutoFill extension, connect the iPhone, and run.
  Xcode may first ask to install the iOS platform it lacks
  (`xcodebuild -downloadPlatform iOS`), which it also needs for the app icon.
- As released: `scripts/release-ios.sh` with `OSM_APPLE_TEAM` set makes an
  IPA for App Store Connect, which TestFlight then delivers to the phone.

## Pairing with the desktop app

1. Phone and computer on the same Wi-Fi network. In the desktop app, open
   Devices, choose Invite a device, and pick a phone.
2. Bring the invitation to the phone by a channel you control (it is good
   for one join and only together with the code comparison), and paste it in
   the app's join screen.
3. On iOS, allow the app to find devices on the local network when asked.
   Without it the phone cannot reach the computer.
4. Both screens show six digits: confirm on the computer only if they are
   the same. Set the phone's own password (at least 12 characters).
5. Expected: the items appear on the phone within a minute; the desktop's
   Devices panel lists the phone as a member that does not vote. An edit on
   the computer reaches the phone while the app is open (within a minute, or
   at once with Sync now).

## Writing on the phone

- Make a login on the phone (New, in the list). Within a minute,
  with the computer's app open, it appears there with its password.
- Edit it on the phone, leaving the password blank: on the computer the
  username changes and the password stays.
- Change the same item on the computer and on the phone while the phone's
  app is closed, then open it: both show the item as needing a decision,
  the phone offers no Edit, and choosing a version on the computer clears
  it on the phone.
- Delete it on the phone: it goes from the computer too.
- Open Recently deleted on the phone and restore it: it comes back on the computer, as it was.
- Change its password on the computer, then open its History on the phone and restore the version before: the computer shows the earlier password again.

## Leaving and coming back

- Switch to another app and back: the vault is locked.
- Lock the phone's screen with the app open, and unlock: the vault is
  locked.
- Leave the app for an hour, then open it: it is locked, and after unlocking
  it syncs again (the line under the list says when it last did).
- Restart the phone, then open the app: it opens locked, the vault intact.
- Copy a password, wait 30 seconds, and paste somewhere: nothing (or what
  was there before) is pasted.
- On Android, the app's preview in the recent-apps view and any screenshot
  are blank. On iOS, the app switcher shows a cover instead of the vault.

## Fingerprint and face

- At an unlock, tick "Unlock with a fingerprint next time" (Android) or
  "Unlock with Face ID / Touch ID next time" (iOS). Lock, then unlock with
  the finger or face alone.
- Enroll another finger or face in the phone's settings, then try again: the
  app should ask for the password once.

## Autofill

**Android:**

1. In the app's list, choose "Fill logins in other apps…" and pick Open
   Secret Manager as the autofill service.
2. In Chrome 135 or later, open Settings › Autofill services and choose
   "Autofill using another service" (Chrome then restarts). Firefox needs
   nothing more.
3. Open the login page of a site the vault has a login for (https, the same
   host it was saved for). Tap the username field: "Open Secret Manager ·
   unlock to fill" appears. Choose it, unlock, choose the login: both fields
   fill. A login saved with an unusual port is not offered (Android does not
   say a page's port); a login for the usual port is also offered on the same
   host's other ports.
4. In another app's login screen, the same entry appears; the first time the
   owner chooses a login for that app, after a warning, and it is offered
   there again afterwards.
5. On a site or app that asks for a code from an authenticator app after
   the password, tap the code field: the same entry appears, and the fill
   screen lists the logins with a one-time code; the chosen one's code
   fills the field. Note fields where nothing is offered (a field must say
   it takes a one-time code).

**iOS:**

1. In the app's list, choose "Fill logins in other apps…" and Turn On.
2. In Safari, open the login page of a site the vault has a login for and
   tap the username field, then the key in the keyboard's bar (or
   "Passwords"), then Open Secret Manager. Unlock (password or Face ID) and
   choose the login: both fields fill. The fill screen should list only the
   logins saved for that exact address.
3. In an app's login screen, the same; for an app that names no website the
   fill screen warns and lists every login.
4. Watch the unlock in the fill screen closely. In the simulator the
   extension used up to 118 MiB at an unlock (`scripts/measure-ios-memory.sh`),
   most of it the password's hashing, and iOS reportedly ends an AutoFill
   extension above about 120 MB. If the fill screen closes on its own as it
   unlocks, iOS likely ended it for its memory: note the phone's model and
   whether Face ID or the password was used.

## Saving from autofill

**Android:**

1. With Open Secret Manager as the autofill service, sign in to a site in
   Chrome (https) with an account the vault does not have, typing the
   username and password. After the page changes, Android asks "Save …
   to Open Secret Manager?": choose Save, unlock, and Save as a new login.
   The next time, the login is offered on that site.
2. Change that password on the site (or sign in with a new one): the save
   screen offers "Update the password of" the login, and the computer gets
   the new password within a minute.
3. The same in an app's sign-in: the new login is offered to that app
   afterwards, and to no other.
4. Note any app or site where no save is offered after signing in, and
   whether the app asked for the username and password on separate screens.

**iOS** (26.2 or later):

1. Sign in to a site in Safari, or to an app, with an account the vault
   does not have. iOS asks "Save Password?": choose Open Secret Manager,
   unlock, and Save as a new login.
2. Sign in again with a new password: the save screen offers to update the
   login.
3. Let Safari suggest a strong password on a sign-up page: note what iOS
   shows, and whether the password reaches the vault once the form is sent.

## Removing the phone

On the computer, remove the phone in the Devices panel. The next time the
phone's app syncs, it says the phone was removed from the vault, and what it
already held stays readable on it.
