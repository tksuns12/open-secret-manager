package org.opensecretmanager.app

import android.content.ClipboardManager
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.vault.Device

/**
 * Writing on the phone through the app's screens, over the real shared code,
 * on a copy of the frozen format 7 vault: new items, edits, deletions, and
 * what is left to a computer.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class EditTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val session = (instrumentation.targetContext.applicationContext as VaultApp).session
    private val folder = File(instrumentation.targetContext.filesDir, VaultApp.DEVICE_FOLDER)

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

    private fun save() {
        compose.onNodeWithTag("save").performClick()
    }

    /** Copies the open item's password and waits for the pasteboard to hold `expected`. */
    private fun assertCopiedPassword(expected: String) {
        compose.onNodeWithTag("copy-password").performClick()
        val clipboard = instrumentation.targetContext.getSystemService(ClipboardManager::class.java)
        compose.waitUntil(10_000) {
            instrumentation.runOnMainSync { }
            clipboard.primaryClip?.getItemAt(0)?.text?.toString() == expected
        }
    }

    @Test
    fun aLoginIsCreatedEditedAndDeleted() {
        unlocked()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        compose.onNodeWithTag("save").assertIsNotEnabled()
        compose.onNodeWithTag("edit-title").performTextInput("Forum")
        compose.onNodeWithTag("edit-username").performTextInput("me@forum.example.test")
        compose.onNodeWithTag("edit-url").performTextInput("https://forum.example.test")
        compose.onNodeWithTag("edit-password").performTextInput("forum password")
        save()
        // The new item opens.
        waitFor("detail-username")
        assertEquals("me@forum.example.test", text("detail-username"))
        assertCopiedPassword("forum password")

        // An edit keeps the password it does not change.
        compose.onNodeWithTag("edit").performClick()
        waitFor("edit-username")
        compose.onNodeWithTag("edit-username").performTextClearance()
        compose.onNodeWithTag("edit-username").performTextInput("someone else")
        save()
        compose.waitUntil(15_000) { runCatching { text("detail-username") }.getOrNull() == "someone else" }
        assertCopiedPassword("forum password")

        // Deleting asks first.
        compose.onNodeWithTag("delete").performClick()
        compose.onNodeWithTag("keep").performClick()
        compose.onNodeWithTag("detail-username").assertExists()
        compose.onNodeWithTag("delete").performClick()
        compose.onNodeWithTag("confirm-delete").performClick()
        waitFor("item:Bank")
        compose.onAllNodesWithTag("item:Forum").assertCountEquals(0)
    }

    @Test
    fun aGeneratedPasswordIsSavedAndASecureNoteHasOnlyItsText() {
        unlocked()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        compose.onNodeWithTag("edit-title").performTextInput("Router")
        compose.onNodeWithTag("generate").performClick()
        val generated = compose.onNodeWithTag("edit-password").fetchSemanticsNode()
            .config[SemanticsProperties.EditableText].text
        assertEquals(20, generated.length)
        save()
        waitFor("copy-password")
        assertCopiedPassword(generated)

        compose.onNodeWithTag("back").performClick()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        compose.onNodeWithTag("kind-note").performClick()
        compose.onAllNodesWithTag("edit-username").assertCountEquals(0)
        compose.onAllNodesWithTag("edit-password").assertCountEquals(0)
        compose.onNodeWithTag("edit-title").performTextInput("Recovery codes")
        compose.onNodeWithTag("edit-notes").performScrollTo().performTextInput("first code\nsecond code")
        save()
        waitFor("detail-notes")
        assertEquals("first code\nsecond code", text("detail-notes"))
        compose.onAllNodesWithTag("copy-password").assertCountEquals(0)
    }

    @Test
    fun anItemInConflictIsLeftToAComputer() {
        unlocked()
        compose.onNodeWithTag("item:Shared, as this device has it").performClick()
        waitFor("back")
        compose.onAllNodesWithTag("edit").assertCountEquals(0)
        compose.onAllNodesWithTag("delete").assertCountEquals(0)
    }

    @Test
    fun aSaveOfAnItemThatChangedMeanwhileShowsItAsItIsNow() {
        unlocked()
        compose.onNodeWithTag("item:Bank").performClick()
        waitFor("edit")
        compose.onNodeWithTag("edit").performClick()
        waitFor("edit-username")

        // Meanwhile the item changes: here through a second device object on
        // the same folder, as a sync would change it.
        Device.open(folder.path).use { other ->
            other.unlock(password)
            val bank = other.item("fixture-bank")
            other.updateItem(
                "fixture-bank",
                bank.revision,
                org.opensecretmanager.vault.ItemDraft(
                    title = "Bank", kind = bank.kind, username = "changed elsewhere", url = bank.url,
                    notes = bank.notes, favorite = bank.favorite, password = null, oneTimeCodeSecret = null,
                ),
            )
        }

        compose.onNodeWithTag("edit-username").performTextClearance()
        compose.onNodeWithTag("edit-username").performTextInput("changed here")
        save()
        compose.waitUntilAtLeastOneExists(hasText("This item changed since you opened it", substring = true), 15_000)
        waitFor("detail-username")
        assertEquals("changed elsewhere", text("detail-username"))
    }
}
