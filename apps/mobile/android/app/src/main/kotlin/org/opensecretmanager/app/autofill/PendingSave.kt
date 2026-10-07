package org.opensecretmanager.app.autofill

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicInteger

/**
 * What a form submitted, between the system's save request and the save
 * screen, in this app's memory: not in the intent that opens the screen,
 * which the system keeps. Only the latest save is held. It goes when its
 * screen closes, or [KEPT_MILLIS] after it came.
 *
 * The system asks for a save only once the owner chose Save, and then
 * starts the save screen. Android 15 and later start it only while the
 * form's app is on the screen or has just left it, so a save whose screen
 * never opened is [waiting], and the app offers it when it is opened. A
 * start Android held back can still come when the form's app is opened
 * again, for a save the owner [settled] meanwhile.
 */
object PendingSave {
    class Save(val form: Form, val username: String, val password: String)

    /** A save whose screen never opened, and who sent it. */
    data class Waiting(val id: Int, val from: String)

    /** How long a save is kept: its password is in memory meanwhile. */
    const val KEPT_MILLIS = 10 * 60 * 1000L

    /** The time a save's age is read by; tests set it. */
    internal var clock: () -> Long = SystemClock::elapsedRealtime

    private class Entry(val id: Int, val save: Save, val from: String, val at: Long) {
        var opened = false
    }

    private val ids = AtomicInteger()
    private var latest: Entry? = null

    /** The saves saved or discarded, by ID only: no secret, so kept for as long as the process. */
    private val settledIds = mutableSetOf<Int>()
    private val handler by lazy { Handler(Looper.getMainLooper()) }

    /** Goes after its time even if nothing asks: the clock behind it stops while the phone sleeps, so asking checks too. */
    private val expire = Runnable { synchronized(this) { latest = null } }

    @Synchronized
    fun put(save: Save, from: String): Int {
        val id = ids.incrementAndGet()
        latest = Entry(id, save, from, clock())
        handler.removeCallbacks(expire)
        handler.postDelayed(expire, KEPT_MILLIS)
        return id
    }

    /** The save [id] names, for its screen, which has now opened. */
    @Synchronized
    fun open(id: Int): Save? {
        val entry = current()?.takeIf { it.id == id } ?: return null
        entry.opened = true
        return entry.save
    }

    /** The save whose screen never opened, if one is kept. */
    @Synchronized
    fun waiting(): Waiting? = current()?.takeIf { !it.opened }?.let { Waiting(it.id, it.from) }

    /** Saved or discarded: the save [id] names goes. */
    @Synchronized
    fun forget(id: Int) {
        if (latest?.id == id) latest = null
        settledIds += id
    }

    /** Whether the save [id] names was saved or discarded. */
    @Synchronized
    fun settled(id: Int): Boolean = id in settledIds

    /** Drops whatever is kept, as a new process starts: for tests, which share one. */
    @Synchronized
    internal fun forgetForTests() {
        latest = null
        settledIds.clear()
    }

    private fun current(): Entry? {
        val entry = latest ?: return null
        if (clock() - entry.at < KEPT_MILLIS) return entry
        latest = null
        return null
    }
}
