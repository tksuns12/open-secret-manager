package org.opensecretmanager.app

import android.util.Log
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The app joins a desktop-side device running on the machine the emulator
 * runs on, through its screens and over the network, and shows the vault it
 * receives: run by scripts/test-mobile-join.sh, which passes the invitation
 * and answers for the owner on the desktop side once the two codes match.
 * Skipped without an invitation.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class JoinDesktopTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun joinsTheDesktopAndShowsItsVault() {
        val invitation = InstrumentationRegistry.getArguments().getString("invitation")
        assumeTrue(invitation != null)
        val session = (InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VaultApp).session
        session.reopenForTests { }
        compose.waitUntilAtLeastOneExists(hasTestTag("invitation"), 30_000)
        compose.onNodeWithTag("invitation").performTextInput(invitation!!)
        compose.onNodeWithTag("join-continue").performClick()
        compose.waitUntilAtLeastOneExists(hasTestTag("join-code"), 60_000)
        val code = compose.onNodeWithTag("join-code").fetchSemanticsNode()
            .config[SemanticsProperties.Text].joinToString("")
        // The script reads this and compares it with the desktop's.
        Log.i("OSMJoin", "PHONE-CODE $code")
        compose.onNodeWithTag("new-password").performTextInput("phone password, long enough")
        compose.onNodeWithTag("new-password-again").performTextInput("phone password, long enough")
        compose.onNodeWithTag("join-finish").performClick()
        // Joined, unlocked, and the desktop's item arrives as it syncs.
        compose.waitUntilAtLeastOneExists(hasTestTag("item:Mail"), 120_000)
        Log.i("OSMJoin", "PHONE-HAS Mail")
    }
}
