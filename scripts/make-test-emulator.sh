#!/bin/sh
# Makes the Android emulator the phone tests run on, `osm-test`, in the
# folder ANDROID_AVD_HOME names, which keeps it out of the owner's own
# list: Android 16 with Google APIs on a Pixel 9 profile, a 6 GB data
# partition, a screen that never times out, Google Messages turned off
# (its "not responding" dialog took the focus from the tests), the PIN 1111,
# and a fingerprint enrolled through Settings, as a person would. It is
# left running; start it again later with
#
#   ANDROID_AVD_HOME=<folder> emulator -avd osm-test -no-window -no-audio \
#       -no-boot-anim -no-snapshot -gpu swiftshader_indirect
#
# and run the tests with OSM_DEVICE_PIN=1111 (scripts/test-mobile.sh).
# macOS deletes files under /tmp that were last read more than three days
# before, which takes an emulator kept there apart; make it again then.
#
#   ANDROID_AVD_HOME=<folder> scripts/make-test-emulator.sh
set -eu
: "${ANDROID_AVD_HOME:?name the folder for the test emulator in ANDROID_AVD_HOME}"
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
image="system-images;android-36;google_apis_playstore;arm64-v8a"
port=5580
pin=1111
mkdir -p "$ANDROID_AVD_HOME"
export ANDROID_AVD_HOME

adb() { "$sdk/platform-tools/adb" -s "emulator-$port" "$@"; }
say() { printf '%s\n' "$*"; }

# Waits up to $1 half-seconds for the command after it to succeed.
within() {
    tries=$1
    shift
    until "$@" >/dev/null 2>&1; do
        tries=$((tries - 1))
        [ "$tries" -gt 0 ] || return 1
        sleep 0.5
    done
}

# The centre of the first thing on the screen whose text is $1, ignoring
# case, as `x y`; nothing if there is none.
centre_of() {
    adb shell uiautomator dump /data/local/tmp/osm-ui.xml >/dev/null 2>&1 || return 0
    adb shell cat /data/local/tmp/osm-ui.xml | tr '<' '\n' \
        | grep -i "text=\"$1\"" | head -1 \
        | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p' \
        | awk '{ print int(($1 + $3) / 2), int(($2 + $4) / 2) }'
}

tap() {
    where=$(centre_of "$1")
    [ -n "$where" ] || { say "nothing on the screen says $1" >&2; return 1; }
    # shellcheck disable=SC2086
    adb shell input tap $where
}

# Whether the screen shows $1. A busy machine can make Settings stop
# answering for a while, and Android then asks whether to close it: wait.
shows() {
    if [ -n "$(centre_of "Close app")" ]; then
        tap "Wait"
        sleep 2
    fi
    [ -n "$(centre_of "$1")" ]
}

unlocked() { adb shell dumpsys trust | grep -q "deviceLocked=0"; }
locked() { adb shell dumpsys trust | grep -q "deviceLocked=1"; }

# Past the lock screen, with the PIN once there is one. Its PIN pad comes
# up after a swipe, or the Menu key; each was seen to fail now and then.
unlock() {
    for way in swipe menu swipe; do
        adb shell input keyevent KEYCODE_WAKEUP
        unlocked && return 0
        sleep 1
        if [ "$way" = swipe ]; then
            adb shell input swipe 540 2000 540 600 300
        else
            adb shell input keyevent KEYCODE_MENU
        fi
        sleep 2
        adb shell input text "$pin"
        adb shell input keyevent KEYCODE_ENTER
        within 20 unlocked && return 0
    done
    say "the lock screen did not open" >&2
    return 1
}


say "Making osm-test in $ANDROID_AVD_HOME"
"$sdk/cmdline-tools/latest/bin/sdkmanager" --install "$image" >/dev/null
echo no | "$sdk/cmdline-tools/latest/bin/avdmanager" create avd --force -n osm-test -k "$image" -d pixel_9 >/dev/null
config="$ANDROID_AVD_HOME/osm-test.avd/config.ini"
sed -i.bak -e 's/^disk.dataPartition.size=.*/disk.dataPartition.size=6G/' "$config" && rm -f "$config.bak"

say "Starting it"
"$sdk/emulator/emulator" -avd osm-test -port "$port" -no-window -no-audio -no-boot-anim -no-snapshot \
    -gpu swiftshader_indirect >"$ANDROID_AVD_HOME/osm-test.log" 2>&1 &
boot() { [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; }
within 1200 boot || { say "it did not start; see $ANDROID_AVD_HOME/osm-test.log" >&2; exit 1; }

say "Setting it up"
adb shell settings put system screen_off_timeout 2147483647
adb shell pm disable-user --user 0 com.google.android.apps.messaging >/dev/null
adb shell locksettings set-pin "$pin" >/dev/null

say "Enrolling a fingerprint"
# Locked for certain, then opened with the PIN: just after the PIN is set
# the device can still say it is open, and lock over Settings a moment on.
adb shell input keyevent KEYCODE_SLEEP
within 20 locked || { say "the screen did not lock" >&2; exit 1; }
unlock
adb shell am start -a android.settings.FINGERPRINT_ENROLL >/dev/null
within 60 shows "Re-enter your PIN" || { say "Settings did not ask for the PIN" >&2; exit 1; }
adb shell input text "$pin"
adb shell input keyevent KEYCODE_ENTER
# The introduction scrolls with More until it can be agreed to.
introduced() { shows "More" || shows "I agree"; }
within 60 introduced || { say "the introduction did not show" >&2; exit 1; }
for _ in 1 2 3 4 5; do
    if shows "I agree"; then break; fi
    tap "More"
    sleep 1
done
tap "I agree"
within 60 shows "Touch the sensor" || { say "Settings did not ask for a touch" >&2; exit 1; }
added=no
for _ in $(seq 1 30); do
    adb emu finger touch 1 >/dev/null
    sleep 1
    adb emu finger remove 1 >/dev/null
    sleep 1
    if shows "Fingerprint added"; then added=yes; break; fi
done
[ "$added" = yes ] || { say "the fingerprint was not enrolled" >&2; exit 1; }
tap "Done"
adb shell input keyevent KEYCODE_HOME
adb shell rm -f /data/local/tmp/osm-ui.xml
say "osm-test is ready and running, as emulator-$port, with PIN $pin and a fingerprint"
