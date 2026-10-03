package org.opensecretmanager.app

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Unlocking with a fingerprint, on an emulator with one enrolled, while
 * scripts/test-mobile.sh touches its sensor. Skipped where no strong
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

        // Locked, a fingerprint alone unlocks.
        compose.onNodeWithTag("lock").performClick()
        waitFor("unlock-biometric")
        compose.onNodeWithTag("unlock-biometric").performClick()
        waitFor("item:Bank")
        assertTrue(biometric.enabled)
        biometric.disable()
    }
}
