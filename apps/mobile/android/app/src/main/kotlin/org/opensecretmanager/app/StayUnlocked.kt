package org.opensecretmanager.app

import android.app.KeyguardManager
import android.content.Context

/**
 * How long the vault stays unlocked once the app, or its fill or save
 * screen, has left the screen, so that the next field of another app is
 * filled from the system's list without unlocking again. The phone's screen
 * turning off leaves the app's screen too, and keeps the same time: the
 * phone's own lock screen guards the vault meanwhile. On a phone without
 * one, the screen turning off locks it at once. The owner chooses it in the
 * app; a minute unless changed.
 */
object StayUnlocked {
    private const val PREFERENCES = "settings"
    private const val KEY = "stay-unlocked-minutes"

    /** The choices, in minutes: 0 locks as soon as the app is left. */
    val CHOICES = listOf(0, 1, 5, 15, 60, 240)
    private const val DEFAULT = 1

    /** For tests: how long, in milliseconds, in place of the owner's choice. */
    @Volatile internal var millisForTests: Long? = null

    /** For tests: whether the phone has a lock screen, in place of what the phone says. */
    @Volatile internal var lockScreenForTests: Boolean? = null

    fun minutes(context: Context): Int =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getInt(KEY, DEFAULT).takeIf { it in CHOICES } ?: DEFAULT

    fun set(context: Context, minutes: Int) {
        require(minutes in CHOICES)
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit().putInt(KEY, minutes).apply()
    }

    fun millis(context: Context): Long = millisForTests ?: (minutes(context) * 60_000L)

    /**
     * Whether the screen turning off leaves the vault unlocked for the time
     * chosen: a time is chosen, and a PIN, pattern, or password locks the
     * phone itself.
     */
    fun throughScreenOff(context: Context): Boolean =
        millis(context) > 0 &&
            (lockScreenForTests ?: context.getSystemService(KeyguardManager::class.java).isDeviceSecure)
}
