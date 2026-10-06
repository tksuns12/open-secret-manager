package org.opensecretmanager.app

import android.content.ClipboardManager
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * An item's history and the items deleted, through the app's screens over
 * the real shared code, on a copy of the frozen format 7 vault: Mail was
 * edited twice, and a note was deleted.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class HistoryTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val session = (instrumentation.targetContext.applicationContext as VaultApp).session

    private fun waitFor(tag: String) = compose.waitUntilAtLeastOneExists(hasTestTag(tag), 30_000)

    private fun text(tag: String) =
        compose.onNodeWithTag(tag).fetchSemanticsNode().config[SemanticsProperties.Text].joinToString("")

    private fun unlocked() {
        session.reopenForTests { folder ->
            BiometricUnlock(instrumentation.targetContext).disable()
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
    }

    private fun openHistory(title: String) {
        compose.onNodeWithTag("item:$title").performClick()
        waitFor("history")
        compose.onNodeWithTag("history").performScrollTo().performClick()
        waitFor("version-0")
    }

    @Test
    fun anEarlierVersionComesBackAsTheNewest() {
        unlocked()
        openHistory("Mail")
        // Newest first, each saying what it changed.
        assertEquals("Changed password, notes", text("said-0"))
        assertEquals("Changed password", text("said-1"))
        assertEquals("Made the item", text("said-2"))
        compose.onAllNodesWithTag("restore-0").assertCountEquals(0)

        // Keep leaves it; Restore brings back the first password.
        compose.onNodeWithTag("restore-2").performClick()
        compose.onNodeWithTag("keep").performClick()
        compose.onNodeWithTag("restore-2").performClick()
        compose.onNodeWithTag("confirm-restore").performClick()
        waitFor("copy-password")
        compose.onNodeWithTag("copy-password").performClick()
        val clipboard = instrumentation.targetContext.getSystemService(ClipboardManager::class.java)
        compose.waitUntil(10_000) {
            instrumentation.runOnMainSync { }
            clipboard.primaryClip?.getItemAt(0)?.text?.toString() == "first password"
        }
        compose.onNodeWithTag("history").performScrollTo().performClick()
        waitFor("version-3")
        assertEquals("Changed password, notes", text("said-0"))
    }

    @Test
    fun aDeletedNoteComesBackAsItWas() {
        unlocked()
        compose.onNodeWithTag("recently-deleted").performClick()
        waitFor("deleted:A note that was deleted")
        compose.onNodeWithTag("restore:A note that was deleted").performClick()
        waitFor("detail-notes")
        assertEquals("gone", text("detail-notes"))
        compose.onNodeWithTag("back").performClick()
        waitFor("item:A note that was deleted")
        compose.onNodeWithTag("recently-deleted").performClick()
        waitFor("deleted-hint")
        assertEquals("Nothing has been deleted.", text("deleted-hint"))
    }

    @Test
    fun anItemInConflictIsRestoredOnAComputer() {
        unlocked()
        openHistory("Shared, as this device has it")
        waitFor("restore-elsewhere")
        compose.onAllNodesWithTag("restore-1").assertCountEquals(0)
        compose.onAllNodesWithTag("restore-2").assertCountEquals(0)
    }
}
