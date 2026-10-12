package org.opensecretmanager.app

import android.content.Context

/**
 * How long the vault stays unlocked once the app, or its fill or save
 * screen, has left the screen, so that the next field of another app is
 * filled from the system's list without unlocking again. The phone's screen
 * turning off locks it at once whatever this is. The owner chooses it in the
 * app; a minute unless changed.
 */
object StayUnlocked {
    private const val PREFERENCES = "settings"
    private const val KEY = "stay-unlocked-minutes"

    /** The choices, in minutes: 0 locks as soon as the app is left. */
    val CHOICES = listOf(0, 1, 5, 15)
    private const val DEFAULT = 1

    /** For tests: how long, in milliseconds, in place of the owner's choice. */
    @Volatile internal var millisForTests: Long? = null

    fun minutes(context: Context): Int =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getInt(KEY, DEFAULT).takeIf { it in CHOICES } ?: DEFAULT

    fun set(context: Context, minutes: Int) {
        require(minutes in CHOICES)
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit().putInt(KEY, minutes).apply()
    }

    fun millis(context: Context): Long = millisForTests ?: (minutes(context) * 60_000L)
}
