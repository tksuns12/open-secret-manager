package org.opensecretmanager.app

import android.Manifest
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.os.Build
import android.view.WindowManager
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.lifecycle.Lifecycle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import androidx.work.WorkManager
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
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

    /** Away from the screen, the vault locks at once, unless a test says otherwise. */
    @Before
    fun lockingAtOnce() {
        StayUnlocked.millisForTests = 0L
    }

    @After
    fun lockingAsChosen() {
        StayUnlocked.millisForTests = null
    }

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
    fun theVaultStaysUnlockedAfterTheAppIsLeftForTheTimeChosen() {
        withTheFrozenVault()
        StayUnlocked.millisForTests = null
        val context = instrumentation.targetContext
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")

        // A minute: left and back within it, the vault is still unlocked.
        compose.onNodeWithTag("stay-unlocked").performClick()
        waitFor("stay-unlocked:1")
        compose.onNodeWithTag("stay-unlocked:1").performClick()
        assertEquals(1, StayUnlocked.minutes(context))
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        Thread.sleep(3_000)
        assertEquals(Screen.UNLOCKED, session.state.value.screen)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitFor("item:Bank")

        // At once: leaving locks it.
        compose.onNodeWithTag("stay-unlocked").performClick()
        waitFor("stay-unlocked:0")
        compose.onNodeWithTag("stay-unlocked:0").performClick()
        assertEquals(0, StayUnlocked.minutes(context))
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.waitUntil(10_000) { session.state.value.screen == Screen.LOCKED }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitFor("locked")
        StayUnlocked.set(context, 1)
    }

    @Test
    fun thePasswordChangesGivenTheCurrentOne() {
        withTheFrozenVault()
        val new = "a new password for this phone"
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        compose.onNodeWithTag("change-password").performClick()
        waitFor("current-password")

        // Too short, then not the same twice: not offered.
        compose.onNodeWithTag("new-password").performTextInput("eleven char")
        compose.onNodeWithTag("password-problem").assertTextEquals("Use at least 12 characters")
        compose.onNodeWithTag("save-password").assertIsNotEnabled()
        compose.onNodeWithTag("new-password").performTextClearance()
        compose.onNodeWithTag("new-password").performTextInput(new)
        compose.onNodeWithTag("new-password-again").performTextInput("$new!")
        compose.onNodeWithTag("password-problem").assertTextEquals("The two passwords differ")
        compose.onNodeWithTag("new-password-again").performTextClearance()
        compose.onNodeWithTag("new-password-again").performTextInput(new)

        // A wrong current password changes nothing.
        compose.onNodeWithTag("current-password").performTextInput("not the password")
        compose.onNodeWithTag("save-password").performClick()
        compose.waitUntilAtLeastOneExists(hasText("That is not this phone's current password · nothing was changed"), 30_000)
        compose.onNodeWithTag("current-password").performTextClearance()
        compose.onNodeWithTag("current-password").performTextInput(password)
        compose.onNodeWithTag("save-password").performClick()
        waitFor("item:Bank")

        // From the next unlock on, only the new one opens the vault.
        compose.onNodeWithTag("lock").performClick()
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        compose.waitUntilAtLeastOneExists(hasText("That password was rejected"), 30_000)
        compose.onNodeWithTag("password").performTextInput(new)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
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
    fun anItemsOtherFieldsAreNamedAndCopiedButNotShown() {
        // The format 8 fixture with a card and an identity added (prepare.sh
        // makes it).
        session.reopenForTests { folder ->
            BiometricUnlock(instrumentation.targetContext).disable()
            instrumentation.context.assets.open("cards-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
        waitFor("locked")
        compose.onNodeWithTag("password").performTextInput(password)
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        val clipboard = instrumentation.targetContext.getSystemService(ClipboardManager::class.java)
        val sensitive = if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
        fun open(title: String) {
            compose.onNodeWithTag("search").performTextClearance()
            compose.onNodeWithTag("search").performTextInput(title)
            waitFor("item:$title")
            compose.onNodeWithTag("item:$title").performClick()
        }
        fun copies(name: String, value: String) {
            compose.onNodeWithTag("field:$name").assertTextEquals("••••••••")
            compose.onNodeWithTag("copy-field:$name").performScrollTo().performClick()
            compose.waitUntil(10_000) {
                instrumentation.runOnMainSync { }
                clipboard.primaryClip?.getItemAt(0)?.text?.toString() == value
            }
            assertTrue(clipboard.primaryClipDescription!!.extras!!.getBoolean(sensitive))
            compose.waitUntilAtLeastOneExists(hasText("$name copied · cleared in 30 seconds"), 10_000)
            // Gone before the next tap, which it could cover.
            compose.waitUntil(15_000) { session.state.value.notice == null }
        }

        // A card: every field by name, none shown, each copied as a secret.
        open("Visa")
        waitFor("copy-field:Number")
        for (name in listOf("Cardholder name", "Expiry month", "Expiry year", "Number", "Security code")) {
            compose.onNodeWithTag("field:$name").assertExists()
        }
        compose.onAllNodesWithText("4111111111111111", substring = true).assertCountEquals(0)
        compose.onNodeWithTag("edit-elsewhere").assertExists()
        compose.onNodeWithTag("edit").assertDoesNotExist()
        copies("Security code", "123")
        copies("Number", "4111111111111111")
        compose.onNodeWithTag("back").performClick()

        // An identity, likewise.
        waitFor("search")
        open("Passport")
        waitFor("copy-field:Passport number")
        compose.onAllNodesWithText("X1234567", substring = true).assertCountEquals(0)
        copies("Passport number", "X1234567")
        compose.onNodeWithTag("back").performClick()

        // A login's own extra fields, beside what it had.
        waitFor("search")
        open("Bank")
        waitFor("copy-field:PIN")
        compose.onNodeWithTag("copy-password").assertExists()
        compose.onNodeWithTag("field:Branch").assertExists()
        copies("PIN", "0000")
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
    fun theCameraIsAskedForOnlyToScanAnInvitationAndWithoutItPastingIsLeft() {
        val app = instrumentation.targetContext
        // As Gradle installs the app for a run: the camera not yet allowed.
        assumeTrue(app.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED)
        withoutAVault()
        waitFor("join-scan")
        compose.onNodeWithTag("join-scan").performClick()
        val device = UiDevice.getInstance(instrumentation)
        val deny = By.res("com.android.permissioncontroller", "permission_deny_button")
        val asked = device.wait(Until.findObject(deny), 15_000) ?: error("Android did not ask for the camera")
        asked.click()
        compose.waitUntilAtLeastOneExists(hasText("Without the camera, paste the invitation instead"), 15_000)
        compose.onNodeWithTag("invitation").assertExists()

        instrumentation.uiAutomation.grantRuntimePermission(app.packageName, Manifest.permission.CAMERA)
        compose.onNodeWithTag("join-scan").performClick()
        waitFor("scan-preview")
        compose.onNodeWithText("Point the camera at the QR code on your computer.").assertExists()
        // The emulator's camera starts, and the screen stays until Cancel.
        Thread.sleep(3_000)
        compose.onNodeWithTag("scan-cancel").assertExists()
        assertEquals(0, compose.onAllNodesWithText("The camera could not be started", substring = true).fetchSemanticsNodes().size)
        compose.onNodeWithTag("scan-cancel").performClick()
        waitFor("join-scan")
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
