package org.opensecretmanager.app.autofill

import java.util.concurrent.atomic.AtomicInteger

/**
 * What a form submitted, between the system's save request and the save
 * screen, in this app's memory: not in the intent that opens the screen,
 * which the system keeps. Only the latest save is held; it goes when its
 * screen closes.
 */
object PendingSave {
    class Save(val form: Form, val username: String, val password: String)

    private val ids = AtomicInteger()
    private var latest: Pair<Int, Save>? = null

    @Synchronized
    fun put(save: Save): Int {
        val id = ids.incrementAndGet()
        latest = id to save
        return id
    }

    @Synchronized
    fun get(id: Int): Save? = latest?.takeIf { it.first == id }?.second

    @Synchronized
    fun forget(id: Int) {
        if (latest?.first == id) latest = null
    }
}
