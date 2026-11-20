package org.opensecretmanager.app

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Unlocking with a fingerprint, on an emulator with one enrolled, while
 * scripts/test-mobile.sh touches its sensor: asked for at once when the app
 * comes back, never after the owner's own Lock. Skipped where no strong
 * biometric is enrolled.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class BiometricTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val session = (context.applicationContext as VaultApp).session

    private fun waitFor(tag: String) = compose.waitUntilAtLeastOneExists(hasTestTag(tag), 60_000)

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
    fun aFingerprintUnlocksOnceThePasswordWasKeptForIt() {
        val biometric = BiometricUnlock(context)
        assumeTrue(biometric.available)
        biometric.disable()
        session.reopenForTests { folder ->
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
        // The password unlocks; the fingerprint then keeps it for next time.
        waitFor("remember-biometric")
        compose.onNodeWithTag("remember-biometric").performClick()
        compose.onNodeWithTag("password").performTextInput("fixture password, not a secret")
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        compose.waitUntil(60_000) { biometric.enabled }

        // Locked by the owner, nothing is asked: the sensor touched for
        // longer than between two touches, the vault is still locked. Then
        // a fingerprint alone unlocks.
        compose.onNodeWithTag("lock").performClick()
        waitFor("unlock-biometric")
        Thread.sleep(5_000)
        assertEquals(Screen.LOCKED, session.state.value.screen)
        compose.onNodeWithTag("unlock-biometric").performClick()
        waitFor("item:Bank")
        assertTrue(biometric.enabled)

        // Left, the vault locks; back, the fingerprint is asked for at once,
        // and it unlocks with no tap.
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.waitUntil(10_000) { session.state.value.screen == Screen.LOCKED }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(60_000) { session.state.value.screen == Screen.UNLOCKED }
        waitFor("item:Bank")

        // The password changed, the one kept for the fingerprint is gone,
        // and the next unlock offers to keep the new one.
        compose.onNodeWithTag("settings").performClick()
        compose.onNodeWithTag("change-password").performClick()
        waitFor("current-password")
        compose.onNodeWithTag("current-password").performTextInput("fixture password, not a secret")
        compose.onNodeWithTag("new-password").performTextInput("a new password for this phone")
        compose.onNodeWithTag("new-password-again").performTextInput("a new password for this phone")
        compose.onNodeWithTag("save-password").performClick()
        waitFor("recently-deleted")
        compose.onNodeWithTag("back").performClick()
        waitFor("item:Bank")
        compose.waitUntil(30_000) { !biometric.enabled }
        compose.onNodeWithTag("lock").performClick()
        waitFor("remember-biometric")
        biometric.disable()
    }
}
