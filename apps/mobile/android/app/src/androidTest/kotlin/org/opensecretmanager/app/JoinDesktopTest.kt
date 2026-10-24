package org.opensecretmanager.app

import android.util.Log
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import androidx.work.ListenableWorker
import androidx.work.testing.TestListenableWorkerBuilder
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The app joins a desktop-side device running on the machine the emulator
 * runs on, through its screens and over the network, shows the vault it
 * receives, and sends back a login made on the phone: run by
 * scripts/test-mobile-join.sh, which passes the invitation, answers for the
 * owner on the desktop side once the two codes match, and then looks for
 * the phone's login there. Then the app leaves the screen, the desktop
 * writes a login, and the phone's background sync takes it in while the
 * vault stays locked: the script writes /data/local/tmp/osm-desktop-wrote
 * once the desktop has. Skipped without an invitation.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class JoinDesktopTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    /** Away from the screen, the vault locks at once. */
    @Before
    fun lockingAtOnce() {
        StayUnlocked.millisForTests = 0L
    }

    @After
    fun lockingAsChosen() {
        StayUnlocked.millisForTests = null
    }

    @Test
    fun joinsTheDesktopAndShowsItsVault() {
        val invitation = InstrumentationRegistry.getArguments().getString("invitation")
        assumeTrue(invitation != null)
        val session = joinTheDesktop(compose, invitation!!)

        // A login made on the phone goes the other way; the script then
        // looks for it on the desktop.
        val made = System.currentTimeMillis() / 1000
        compose.onNodeWithTag("new-item").performClick()
        compose.waitUntilAtLeastOneExists(hasTestTag("edit-title"), 10_000)
        compose.onNodeWithTag("edit-title").performTextInput("From the phone")
        compose.onNodeWithTag("edit-password").performTextReplacement("phone-made password")
        compose.onNodeWithTag("save").performClick()
        compose.waitUntil(60_000) { (session.state.value.sync?.lastSyncedAt?.toLong() ?: 0) >= made }
        Log.i("OSMJoin", "PHONE-MADE From the phone")

        // Away from the screen the vault locks and the phone stops taking
        // part; the desktop writes a login meanwhile.
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        UiDevice.getInstance(instrumentation).pressHome()
        val away = System.currentTimeMillis() / 1000
        eventually("the vault locks when the app leaves the screen") { session.state.value.screen == Screen.LOCKED }
        Log.i("OSMJoin", "PHONE-AWAY")
        eventually("the desktop writes a login") { shell("ls /data/local/tmp/osm-desktop-wrote").contains("osm-desktop-wrote") }

        // Android's background sync: it takes in what the desktop wrote, to
        // wait for the next unlock, and leaves the vault locked.
        val worker = TestListenableWorkerBuilder<BackgroundSync.Worker>(instrumentation.targetContext.applicationContext).build()
        val result = runBlocking { worker.doWork() }
        assertEquals(ListenableWorker.Result.success(), result)
        val sync = session.state.value.sync!!
        assertTrue("$sync", (sync.lastSyncedAt?.toLong() ?: 0) >= away)
        assertTrue("$sync", sync.pending > 0u)
        assertEquals(Screen.LOCKED, session.state.value.screen)
        Log.i("OSMJoin", "PHONE-SYNCED-AWAY")

        // Back on the screen (as from the launcher, the same window) and
        // unlocked, it shows the login.
        shell("am start -W -n org.opensecretmanager.app/.MainActivity --activity-reorder-to-front")
        compose.waitUntilAtLeastOneExists(hasTestTag("password"), 30_000)
        compose.onNodeWithTag("password").performTextInput("phone password, long enough")
        compose.onNodeWithTag("unlock").performClick()
        compose.waitUntilAtLeastOneExists(hasTestTag("item:Away"), 60_000)
        Log.i("OSMJoin", "PHONE-HAS Away")
    }
}
