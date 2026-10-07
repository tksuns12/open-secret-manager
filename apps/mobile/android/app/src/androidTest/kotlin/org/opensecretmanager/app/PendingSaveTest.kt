package org.opensecretmanager.app

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Form
import org.opensecretmanager.app.autofill.PendingSave

/**
 * What the app keeps of a save between the system's request and the save
 * screen: offered as waiting until its screen opens, and gone when the
 * screen closes, when it is discarded, or once its time is up.
 */
@RunWith(AndroidJUnit4::class)
class PendingSaveTest {
    private var now = 0L
    private val form = Form("org.example.app", null, null, null, null, null)

    @Before
    fun withAClockOfTheTest() {
        PendingSave.forgetForTests()
        now = 1_000_000L
        PendingSave.clock = { now }
    }

    @After
    fun putTheClockBack() {
        PendingSave.forgetForTests()
        PendingSave.clock = SystemClock::elapsedRealtime
    }

    @Test
    fun aSaveWaitsUntilItsScreenOpensAndGoesWhenTheScreenCloses() {
        val id = PendingSave.put(PendingSave.Save(form, "someone", "a password"), "Example")
        assertEquals(PendingSave.Waiting(id, "Example"), PendingSave.waiting())

        val save = PendingSave.open(id)
        assertEquals("a password", save?.password)
        // Opened, it is the screen's: no longer offered, still there for it.
        assertNull(PendingSave.waiting())
        assertNotNull(PendingSave.open(id))

        assertFalse(PendingSave.settled(id))
        PendingSave.forget(id)
        assertNull(PendingSave.open(id))
        // Its screen, started late by Android, can tell it was handled.
        assertTrue(PendingSave.settled(id))
        assertFalse(PendingSave.settled(id + 1))
    }

    @Test
    fun onlyTheLatestSaveIsKept() {
        val first = PendingSave.put(PendingSave.Save(form, "first", "first password"), "Example")
        val second = PendingSave.put(PendingSave.Save(form, "second", "second password"), "Example")
        assertNull(PendingSave.open(first))
        assertEquals(second, PendingSave.waiting()?.id)
        // Forgetting the older one leaves the newer.
        PendingSave.forget(first)
        assertEquals(second, PendingSave.waiting()?.id)
    }

    @Test
    fun aSaveIsDiscardedOrGoesOnceItsTimeIsUp() {
        val discarded = PendingSave.put(PendingSave.Save(form, "someone", "a password"), "Example")
        PendingSave.forget(discarded)
        assertNull(PendingSave.waiting())

        val kept = PendingSave.put(PendingSave.Save(form, "someone", "a password"), "Example")
        now += PendingSave.KEPT_MILLIS - 1
        assertEquals(kept, PendingSave.waiting()?.id)
        now += 1
        assertNull(PendingSave.waiting())
        assertNull(PendingSave.open(kept))
    }
}
