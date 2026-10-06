package org.opensecretmanager.app

import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import android.view.WindowManager
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkManager
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The app's screens over the real shared code, on an emulator or a device:
 * a copy of the frozen format 7 vault is put where the app keeps its vault
 * before each test.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class AppTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val session = (instrumentation.targetContext.applicationContext as VaultApp).session

    private fun withTheFrozenVault() = session.reopenForTests { folder ->
        // Unlocking with a fingerprint is BiometricTest's; here, the password.
        BiometricUnlock(instrumentation.targetContext).disable()
        instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
            File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
        }
    }

    private fun withoutAVault() = session.reopenForTests { }

    private fun waitFor(tag: String) = compose.waitUntilAtLeastOneExists(hasTestTag(tag), 30_000)

    @Test
    fun aLockedVaultUnlocksListsCopiesAndLocksWhenTheAppIsLeft() {
        withTheFrozenVault()
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        compose.onNodeWithTag("item:Bank").performClick()
        waitFor("detail-username")
        compose.onNodeWithTag("detail-username").assertExists()
        compose.waitUntilAtLeastOneExists(hasText("account 42"), 10_000)

        // The password goes to the clipboard marked sensitive.
        compose.onNodeWithTag("copy-password").performClick()
        val clipboard = instrumentation.targetContext.getSystemService(ClipboardManager::class.java)
        compose.waitUntil(10_000) {
            instrumentation.runOnMainSync { }
            clipboard.primaryClip?.getItemAt(0)?.text?.toString() == "p@ss \"quoted\" \\ and 🔑"
        }
        val sensitive = if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
        assertTrue(clipboard.primaryClipDescription!!.extras!!.getBoolean(sensitive))

        // Leaving the app locks the vault.
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.waitUntil(10_000) { session.state.value.screen == Screen.LOCKED }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitFor("locked")
    }

    @Test
    fun recordsTakenOutOfTheFileAreSaidAfterUnlockingUntilConfirmed() {
        // The format 8 fixture with the first version of Mail taken out
        // (prepare.sh makes it).
        session.reopenForTests { folder ->
            BiometricUnlock(instrumentation.targetContext).disable()
            instrumentation.context.assets.open("sealed-taken-out-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("rows-changed")
        compose.onNodeWithTag("item:Mail").assertExists()
        compose.onNodeWithTag("rows-changed-ok").performClick()
        compose.waitUntil(10_000) { !session.state.value.rowsChanged }
        compose.onNodeWithTag("rows-changed").assertDoesNotExist()
        // Confirmed, it is not said again.
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.waitUntil(10_000) { session.state.value.screen == Screen.LOCKED }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        compose.onNodeWithTag("rows-changed").assertDoesNotExist()
    }

    @Test
    fun syncingWhileClosedIsScheduledUntilTurnedOff() {
        val context = instrumentation.targetContext
        BackgroundSync.set(context, true)
        val work = WorkManager.getInstance(context)
        fun scheduled() = work.getWorkInfosForUniqueWork("background-sync").get().any { !it.state.isFinished }
        assertTrue(scheduled())

        withTheFrozenVault()
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        compose.onNodeWithTag("background-sync").assertIsOn().performClick()
        compose.waitUntil(10_000) { !scheduled() }
        assertFalse(BackgroundSync.enabled(context))
        compose.onNodeWithTag("background-sync").assertIsOff().performClick()
        compose.waitUntil(10_000) { scheduled() }
        assertTrue(BackgroundSync.enabled(context))
    }

    @Test
    fun aWrongPasswordIsRefused() {
        withTheFrozenVault()
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput("not the password")
        compose.onNodeWithTag("unlock").performClick()
        compose.waitUntilAtLeastOneExists(hasText("That password was rejected"), 30_000)
        assertEquals(Screen.LOCKED, session.state.value.screen)
    }

    @Test
    fun withoutAVaultItOffersToJoinAndRefusesWhatIsNoInvitation() {
        withoutAVault()
        waitFor("invitation")
        compose.onNodeWithTag("invitation").performTextInput("not an invitation")
        compose.onNodeWithTag("join-continue").performClick()
        compose.waitUntilAtLeastOneExists(hasText("That is not an invitation", substring = true), 30_000)
        assertEquals(Screen.NO_VAULT, session.state.value.screen)
    }

    @Test
    fun theVaultIsKeptOutOfScreenshots() {
        // Except in the build made for reviewing the screens.
        assumeFalse(BuildConfig.ALLOW_SCREENSHOTS)
        withTheFrozenVault()
        waitFor("locked")
        val flags = compose.activity.window.attributes.flags
        assertNotEquals(0, flags and WindowManager.LayoutParams.FLAG_SECURE)
    }
}
