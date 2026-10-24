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
 * The app reaches a desktop-side device through the relay the vault names,
 * once it can no longer reach it directly: run by
 * scripts/test-mobile-relay.sh. At home the phone joins and syncs; the
 * desktop then sets the relay (the script writes osm-relay-set), and the
 * phone takes it in with its next sync. The script then cuts every direct
 * path between the two and the desktop writes a login (osm-direct-cut):
 * the phone syncs it in through the relay and sends one back, and, away
 * from the screen and locked, its background sync takes in another one
 * (osm-desktop-wrote) the same way. Skipped without an invitation.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class RelayDesktopTest {
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

    private fun syncedSince(session: VaultSession, since: Long) =
        (session.state.value.sync?.lastSyncedAt?.toLong() ?: 0) >= since

    @Test
    fun syncsThroughTheRelayOnceTheDesktopCannotBeReached() {
        val invitation = InstrumentationRegistry.getArguments().getString("relayInvitation")
        assumeTrue(invitation != null)
        val session = joinTheDesktop(compose, invitation!!)

        // At home: the desktop sets the relay, and the next sync brings it.
        Log.i("OSMJoin", "PHONE-JOINED")
        waitForScript("osm-relay-set", "the desktop sets the relay")
        val home = System.currentTimeMillis() / 1000
        session.syncNow()
        eventually("the phone syncs at home") { syncedSince(session, home) }
        Log.i("OSMJoin", "PHONE-SYNCED-HOME")

        // Away: nothing reaches the desktop directly. Through the relay the
        // desktop's login comes in, and one made here goes out.
        waitForScript("osm-direct-cut", "every direct path is cut")
        eventually("the desktop's login comes through the relay") {
            session.syncNow()
            Thread.sleep(2_000)
            session.state.value.items.any { it.title == "Through the relay" }
        }
        compose.waitUntilAtLeastOneExists(hasTestTag("item:Through the relay"), 30_000)
        Log.i("OSMJoin", "PHONE-HAS Through the relay")
        val made = System.currentTimeMillis() / 1000
        compose.onNodeWithTag("new-item").performClick()
        compose.waitUntilAtLeastOneExists(hasTestTag("edit-title"), 10_000)
        compose.onNodeWithTag("edit-title").performTextInput("Sent through the relay")
        compose.onNodeWithTag("edit-password").performTextReplacement("relayed password")
        compose.onNodeWithTag("save").performClick()
        compose.waitUntil(60_000) { syncedSince(session, made) }
        Log.i("OSMJoin", "PHONE-MADE Sent through the relay")

        // Away from the screen and locked: the background sync, which goes
        // online only for it, reaches the desktop through the relay too.
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        UiDevice.getInstance(instrumentation).pressHome()
        val away = System.currentTimeMillis() / 1000
        eventually("the vault locks when the app leaves the screen") { session.state.value.screen == Screen.LOCKED }
        Log.i("OSMJoin", "PHONE-AWAY")
        waitForScript("osm-desktop-wrote", "the desktop writes a login")
        val worker = TestListenableWorkerBuilder<BackgroundSync.Worker>(instrumentation.targetContext.applicationContext).build()
        assertEquals(ListenableWorker.Result.success(), runBlocking { worker.doWork() })
        val sync = session.state.value.sync!!
        assertTrue("$sync", (sync.lastSyncedAt?.toLong() ?: 0) >= away)
        assertTrue("$sync", sync.pending > 0u)
        assertEquals(Screen.LOCKED, session.state.value.screen)
        Log.i("OSMJoin", "PHONE-SYNCED-AWAY")
        shell("am start -W -n org.opensecretmanager.app/.MainActivity --activity-reorder-to-front")
        compose.waitUntilAtLeastOneExists(hasTestTag("password"), 30_000)
        compose.onNodeWithTag("password").performTextInput("phone password, long enough")
        compose.onNodeWithTag("unlock").performClick()
        compose.waitUntilAtLeastOneExists(hasTestTag("item:Relayed while locked"), 60_000)
        Log.i("OSMJoin", "PHONE-HAS Relayed while locked")
    }
}
