package org.opensecretmanager.app

import android.content.ClipboardManager
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.vault.AndroidKeystore
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

    /** What a field of the editor holds. */
    private fun value(tag: String) =
        compose.onNodeWithTag(tag).fetchSemanticsNode().config[SemanticsProperties.EditableText].text

    private fun unlocked() {
        Generator.forget(instrumentation.targetContext)
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
        // It comes with a password made for it, which typing replaces.
        compose.onNodeWithTag("password-made", useUnmergedTree = true).assertExists()
        compose.onNodeWithTag("edit-password").performTextReplacement("forum password")
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
    fun aCardIsMadeAndEditedByItsOwnFieldsKeepingWhatWasLeftBlank() {
        unlocked()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        compose.onNodeWithTag("kind-card").performClick()
        // A card asks for a card's fields, not a login's.
        compose.onAllNodesWithTag("edit-username").assertCountEquals(0)
        compose.onNodeWithTag("edit-title").performTextInput("Travel card")
        compose.onNodeWithTag("edit-cardholder").performTextInput("Alex Northstar")
        compose.onNodeWithTag("edit-number").performTextInput("5555 5555 5555 4440")
        waitFor("number-check")
        compose.onNodeWithTag("edit-number").performTextClearance()
        compose.onNodeWithTag("edit-number").performTextInput("5555 5555 5555 4444")
        compose.waitUntil(5_000) { compose.onAllNodesWithTag("number-check").fetchSemanticsNodes().isEmpty() }
        assertEquals("Mastercard", value("edit-brand"))
        compose.onNodeWithTag("edit-expiry-month").performTextInput("11")
        compose.onNodeWithTag("edit-expiry-year").performTextInput("2030")
        compose.onNodeWithTag("edit-security-code").performScrollTo().performTextInput("987")
        save()
        waitFor("card-number")
        assertEquals("•••• 4444", text("card-number"))
        assertEquals("11 / 2030", text("card-expiry"))
        assertEquals("Alex Northstar", text("card-cardholder"))
        compose.onAllNodesWithText("5555", substring = true).assertCountEquals(0)

        // An edit that leaves the number and code blank keeps them.
        compose.onNodeWithTag("edit").performClick()
        waitFor("edit-cardholder")
        assertEquals("", value("edit-number"))
        compose.onNodeWithTag("edit-cardholder").performTextClearance()
        compose.onNodeWithTag("edit-cardholder").performTextInput("A. Northstar")
        save()
        compose.waitUntil(15_000) { runCatching { text("card-cardholder") }.getOrNull() == "A. Northstar" }
        assertEquals("•••• 4444", text("card-number"))
        compose.onNodeWithTag("card-code").assertExists()
        compose.onNodeWithTag("back").performClick()
        waitFor("search")
        compose.onNodeWithTag("search").performTextInput("Travel")
        waitFor("item:Travel card")
        compose.onAllNodesWithText("Mastercard •••• 4444").assertCountEquals(1)
    }

    @Test
    fun aGeneratedPasswordIsSavedAndASecureNoteHasOnlyItsText() {
        unlocked()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        compose.onNodeWithTag("edit-title").performTextInput("Router")
        // A new login comes with a password made for it, shown.
        val made = value("edit-password")
        assertTrue(made, Regex("[^lIO01]{20}").matches(made))
        compose.onNodeWithTag("password-made", useUnmergedTree = true).assertExists()
        compose.onNodeWithTag("generate").performClick()
        val generated = value("edit-password")
        assertEquals(20, generated.length)
        assertNotEquals(made, generated)
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

    /**
     * The generator's options, opened under the password, make the password
     * again at each change, and are kept for the next new item; Clear
     * leaves none.
     */
    @Test
    fun theGeneratorsChoiceIsMadeUnderThePasswordAndKept() {
        unlocked()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        compose.onNodeWithTag("generator-open").performClick()
        waitFor("generator-options")
        for (kind in listOf("A–Z", "a–z", "!@#$")) compose.onNodeWithTag("generator-kind:$kind").performScrollTo().performClick()
        // The last kind cannot be turned off.
        compose.onNodeWithTag("generator-kind:0–9").assertIsNotEnabled()
        compose.waitUntil(5_000) { Regex("[0-9]{20}").matches(value("edit-password")) }
        compose.onNodeWithTag("generator-length").performScrollTo().performSemanticsAction(SemanticsActions.SetProgress) { it(8f) }
        compose.waitUntil(5_000) { Regex("[0-9]{8}").matches(value("edit-password")) }
        assertEquals("Length 8", text("generator-length-shown"))

        // Kept: the next new item's password is made with it.
        compose.onNodeWithTag("cancel-edit").performClick()
        compose.onNodeWithTag("new-item").performClick()
        waitFor("edit-title")
        assertTrue(Regex("[0-9]{8}").matches(value("edit-password")))
        compose.onNodeWithTag("clear-password").performClick()
        assertEquals("", value("edit-password"))
        compose.onAllNodesWithTag("password-made", useUnmergedTree = true).assertCountEquals(0)
        compose.onNodeWithTag("edit-title").performTextInput("No password")
        save()
        waitFor("edit")
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
    fun aSaveOfAnItemThatChangedMeanwhileKeepsWhatWasTypedOnTopOfIt() {
        unlocked()
        compose.onNodeWithTag("item:Bank").performClick()
        waitFor("edit")
        compose.onNodeWithTag("edit").performClick()
        waitFor("edit-username")

        // Meanwhile another device changes the item's notes: here through a
        // second device object on the same folder, as a sync would.
        Device.open(folder.path, AndroidKeystore).use { other ->
            other.unlock(password)
            val bank = other.item("fixture-bank")
            other.updateItem(
                "fixture-bank",
                bank.revision,
                org.opensecretmanager.vault.ItemDraft(
                    title = "Bank", kind = bank.kind, username = bank.username, url = bank.url,
                    notes = "changed elsewhere", favorite = bank.favorite, password = null, oneTimeCodeSecret = null, card = null,
                ),
            )
        }

        compose.onNodeWithTag("edit-username").performTextClearance()
        compose.onNodeWithTag("edit-username").performTextInput("changed here")
        save()
        // Refused, the edit stays open: what was typed is kept, on top of the
        // item as it is now, and what changed elsewhere is named.
        waitFor("changed-elsewhere")
        compose.onNode(
            hasText("It changed its notes.", substring = true) and hasAnyAncestor(hasTestTag("changed-elsewhere")),
            useUnmergedTree = true,
        ).assertExists()
        assertEquals("changed here", value("edit-username"))
        assertEquals("changed elsewhere", value("edit-notes"))

        // Saved again, both changes stand.
        save()
        waitFor("detail-username")
        assertEquals("changed here", text("detail-username"))
        assertEquals("changed elsewhere", text("detail-notes"))
    }
}
