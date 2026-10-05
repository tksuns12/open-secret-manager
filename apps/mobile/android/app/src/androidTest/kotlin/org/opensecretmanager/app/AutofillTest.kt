package org.opensecretmanager.app

import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import android.view.KeyEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.vault.Device
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind

/**
 * Filling another app's forms through the system's autofill, end to end:
 * the app's service is made the phone's autofill service, a stand-in app
 * (the `loginfixture` module) shows a login form, and the test chooses
 * "unlock to fill" in it, unlocks the fill screen, and picks a login, as
 * the owner would. A copy of the frozen format 7 vault is the vault.
 *
 * In a build made with `-Posm.screenshots=true` and run with the
 * instrumentation argument `screens=true`, it also captures the screens it
 * passes through for a person to look at (see [ScreensForReview]).
 */
@RunWith(AndroidJUnit4::class)
class AutofillTest {
    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val session = (context.applicationContext as VaultApp).session
    private val device = UiDevice.getInstance(instrumentation)
    private var previousService: String? = null

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    @Before
    fun withTheServiceAndTheFrozenVault() {
        // Not this app's own service, which a run stopped before it put the
        // setting back would have left.
        previousService = shell("settings get secure autofill_service").trim()
            .takeIf { it.isNotEmpty() && it != "null" && !it.startsWith("${context.packageName}/") }
        shell("settings put secure autofill_service ${context.packageName}/.autofill.VaultAutofillService")
        context.getSharedPreferences("app-logins", 0).edit().clear().commit()
        Requester.trustedForTests.clear()
        session.reopenForTests { folder ->
            BiometricUnlock(context).disable()
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
    }

    @After
    fun putTheServiceBack() {
        Requester.trustedForTests.clear()
        shell("am force-stop $FIXTURE")
        shell(previousService?.let { "settings put secure autofill_service $it" } ?: "settings delete secure autofill_service")
    }

    private fun find(selector: BySelector, timeout: Long = 15_000): UiObject2 =
        device.wait(Until.findObject(selector), timeout) ?: throw AssertionError("nothing matches $selector")

    private val capturing =
        BuildConfig.ALLOW_SCREENSHOTS && InstrumentationRegistry.getArguments().getString("screens") == "true"

    private fun capture(name: String) {
        if (!capturing) return
        device.waitForIdle()
        Thread.sleep(500)
        val folder = context.getExternalFilesDir("screens")!!
        instrumentation.uiAutomation.takeScreenshot()
            .compress(Bitmap.CompressFormat.PNG, 100, File(folder, "fill-$name.png").outputStream())
    }

    private fun mine(tag: String) = By.res(tag).pkg(context.packageName)

    /**
     * Opens a form of the stand-in app (with [extras] for `am start`), chooses
     * "unlock to fill" in it, and unlocks.
     */
    private fun askToFill(activity: String, origin: String? = null, name: String? = null, field: String = "username", extras: String = "") {
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.$activity" + (origin?.let { " --es origin $it" } ?: "") + extras)
        val field = if (origin == null) {
            find(By.res(FIXTURE, field))
        } else {
            find(By.clazz("android.widget.EditText").pkg(FIXTURE), 30_000)
        }
        field.click()
        val offer = find(By.text("Open Secret Manager · unlock to fill"))
        name?.let { capture("$it-offer") }
        offer.click()
        find(mine("password"))
        name?.let { capture("$it-locked") }
        find(mine("password")).text = password
        find(mine("unlock")).click()
        find(mine("asker"))
    }

    private fun assertFilled(expected: String) {
        val filled = find(By.res(FIXTURE, "filled"))
        assertTrue(
            "filled: ${filled.text}",
            filled.wait(Until.textEquals(expected), 15_000) == true,
        )
    }

    /** The fill screen gone, the vault locks again. */
    private fun assertLockedAgain() {
        val deadline = System.currentTimeMillis() + 15_000
        while (session.state.value.screen != Screen.LOCKED && System.currentTimeMillis() < deadline) Thread.sleep(100)
        assertEquals(Screen.LOCKED, session.state.value.screen)
    }

    @Test
    fun anAppIsOfferedOnlyTheLoginsTheOwnerChoseForIt() {
        askToFill("NativeLoginActivity", name = "app")
        // Nothing chosen for this app yet: the owner chooses one, warned.
        assertNull(device.findObject(mine("fill:Bank")))
        find(mine("choose-another"))
        capture("app-nothing-chosen")
        find(mine("choose-another")).click()
        find(mine("warning"))
        capture("app-choose")
        find(mine("fill:Bank")).click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        assertLockedAgain()

        // The next time, the login chosen for it is offered, and only that.
        askToFill("NativeLoginActivity")
        find(mine("fill:Bank"))
        assertNull(device.findObject(mine("fill:Mail")))
        capture("app-chosen")
        find(mine("fill:Bank")).click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        capture("app-filled")
        assertLockedAgain()
    }

    @Test
    fun aTrustedBrowsersPageIsOfferedTheLoginsSavedForItsOrigin() {
        Requester.trustedForTests += FIXTURE
        askToFill("WebLoginActivity", "https://mail.example.test", name = "web")
        find(mine("fill:Mail"))
        capture("web-logins")
        assertNull(device.findObject(mine("fill:Bank")))
        assertNull(device.findObject(mine("choose-another")))
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertLockedAgain()

        // Bank is saved for port 8443. A phone's browser reports the host
        // only, which is port 443: nothing is offered.
        askToFill("WebLoginActivity", "https://bank.example.test")
        find(mine("no-logins"))
        capture("web-none")
        assertNull(device.findObject(mine("choose-another")))
        find(mine("cancel")).click()
        assertFilled("|")
        assertLockedAgain()
    }

    @Test
    fun aPageInAnAppThatIsNotATrustedBrowserIsTheAppsAndItsClaimsOnly() {
        askToFill("WebLoginActivity", "https://mail.example.test")
        find(mine("claimed"))
        capture("untrusted-page")
        assertNull(device.findObject(mine("fill:Mail")))
        find(mine("choose-another")).click()
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertLockedAgain()

        // Chosen for the page this app says is mail.example.test: on a page
        // it says is another site, nothing chosen is offered.
        askToFill("WebLoginActivity", "https://other.example.test")
        find(mine("choose-another"))
        assertNull(device.findObject(mine("fill:Mail")))
        find(mine("cancel")).click()
        assertLockedAgain()
    }

    /**
     * Types [text] as keys into the page's focused field: one key, which
     * closes the offer to fill under the field, and then the rest. While the
     * offer shows, the system passes keys through it, and loses or reorders
     * some (a space even chooses it); the on-screen keyboard's typing does
     * not go that way.
     */
    private fun typeKeys(text: String) {
        shell("input text ${text.take(1)}")
        Thread.sleep(1_500)
        shell("input text ${text.drop(1)}")
    }

    /**
     * Opens a form of the stand-in app, types [username] and [password] into
     * it, and signs in; then chooses Save in the system's offer, and unlocks
     * the save screen. On a page, they are typed as keys, since a web view
     * reports only what was typed: letters, digits, and dashes only.
     */
    private fun submitAndSave(activity: String, origin: String?, username: String, password: String, name: String? = null) {
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.$activity" + (origin?.let { " --es origin $it" } ?: ""))
        // A tap first: the system asks this app about a form when a field
        // takes the focus, and only then offers to save it. Not on the
        // password field, which the offer to fill may cover by then.
        if (origin == null) {
            find(By.res(FIXTURE, "username")).click()
            find(By.res(FIXTURE, "username")).text = username
            find(By.res(FIXTURE, "password")).text = password
            find(By.res(FIXTURE, "sign_in")).click()
        } else {
            // Keys typed can still be lost on the way, so the form is typed
            // again, afresh, until the page shows it got them all.
            for (attempt in 1..3) {
                if (attempt > 1) shell("am start -W -S -n $FIXTURE/.$activity --es origin $origin")
                find(By.clazz("android.widget.EditText").pkg(FIXTURE), 30_000).click()
                Thread.sleep(1_500)
                typeKeys(username)
                device.pressKeyCode(KeyEvent.KEYCODE_TAB)
                Thread.sleep(1_500)
                typeKeys(password)
                if (find(By.res(FIXTURE, "filled")).wait(Until.textEquals("$username|$password"), 5_000) == true) break
                check(attempt < 3) { "the page never got all the keys typed" }
            }
            // The page's one button is its Sign in, uncovered now that the
            // offer to fill is closed. The web view may redo its tree, so
            // the button is found again until the tap reaches it.
            for (attempt in 1..3) {
                try {
                    find(By.clazz("android.widget.Button").pkg(FIXTURE)).click()
                    break
                } catch (stale: StaleObjectException) {
                    if (attempt == 3) throw stale
                }
            }
        }
        val save = find(By.res("android", "autofill_save_yes"))
        name?.let { capture("$it-save-offer") }
        save.click()
        find(mine("password"))
        find(mine("password")).text = this.password
        find(mine("unlock")).click()
        find(mine("asker"))
    }

    @Test
    fun anAppsNewLoginIsSavedForItAndItsNextPasswordIntoThatLogin() {
        submitAndSave("NativeLoginActivity", null, "new account", "new password", name = "app")
        // Nothing chosen for this app: only a new login, for this app.
        find(mine("save-new"))
        assertNull(device.findObject(mine("update:Bank")))
        assertEquals("Login fixture", find(mine("save-title")).text)
        capture("save-app-new")
        find(mine("save-new")).click()
        assertLockedAgain()
        askToFill("NativeLoginActivity")
        find(mine("fill:Login fixture")).click()
        assertFilled("new account|new password")
        assertLockedAgain()

        // The next password for that account goes into that login.
        submitAndSave("NativeLoginActivity", null, "new account", "newer password")
        find(mine("update:Login fixture")).click()
        assertLockedAgain()
        askToFill("NativeLoginActivity")
        find(mine("fill:Login fixture")).click()
        assertFilled("new account|newer password")
        assertLockedAgain()
    }

    @Test
    fun aTrustedBrowsersPageSavesIntoTheLoginsForItsOriginOnly() {
        Requester.trustedForTests += FIXTURE
        // A page with no login for it: a new login, for its origin.
        submitAndSave("WebLoginActivity", "https://new.example.test", "someone", "first-password", name = "web")
        find(mine("save-new"))
        assertNull(device.findObject(mine("update:Mail")))
        assertEquals("new.example.test", find(mine("save-title")).text)
        capture("save-web-new")
        find(mine("save-new")).click()
        assertLockedAgain()
        askToFill("WebLoginActivity", "https://new.example.test")
        find(mine("fill:new.example.test")).click()
        assertFilled("someone|first-password")
        assertLockedAgain()

        // What the vault has already is not saved again.
        submitAndSave("WebLoginActivity", "https://new.example.test", "someone", "first-password")
        find(mine("already-saved"))
        find(mine("done")).click()
        assertLockedAgain()

        // A new password for that account goes into its login.
        submitAndSave("WebLoginActivity", "https://new.example.test", "someone", "second-password")
        find(mine("update:new.example.test"))
        capture("save-web-update")
        find(mine("update:new.example.test")).click()
        assertLockedAgain()
        askToFill("WebLoginActivity", "https://new.example.test")
        find(mine("fill:new.example.test")).click()
        assertFilled("someone|second-password")
        assertLockedAgain()
    }

    /** The code of RFC 6238 for a base32 [secret] at [unixTime], as the shared code makes it. */
    private fun totp(secret: String, unixTime: Long): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val key = ByteArrayOutputStream()
        var buffer = 0
        var bits = 0
        for (char in secret) {
            buffer = (buffer shl 5) or alphabet.indexOf(char)
            bits += 5
            if (bits >= 8) {
                bits -= 8
                key.write((buffer shr bits) and 0xff)
            }
        }
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA1"))
        val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(unixTime / 30).array())
        val offset = hash.last().toInt() and 0x0f
        val value = ((hash[offset].toInt() and 0x7f) shl 24) or ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or (hash[offset + 3].toInt() and 0xff)
        return "%06d".format(value % 1_000_000)
    }

    /** The stand-in shows the current code of [secret] (or the one before, as the step may just have turned). */
    private fun assertFilledWithCodeOf(secret: String) {
        val filled = find(By.res(FIXTURE, "filled"))
        assertTrue("filled: ${filled.text}", filled.wait(Until.textMatches("[0-9]{6}"), 15_000) == true)
        val now = System.currentTimeMillis() / 1000
        assertTrue("filled: ${filled.text}", filled.text in setOf(totp(secret, now), totp(secret, now - 30)))
    }

    @Test
    fun anAppsCodeFieldIsFilledWithTheCurrentCodeOfTheLoginChosenForIt() {
        askToFill("CodeActivity", field = "code", name = "code")
        find(mine("choose-another")).click()
        find(mine("warning"))
        // Only the logins that have a code: Bank, not Mail.
        find(mine("fill:Bank"))
        assertNull(device.findObject(mine("fill:Mail")))
        capture("code-choose")
        find(mine("fill:Bank")).click()
        assertFilledWithCodeOf(BANK_CODE_SECRET)
        assertLockedAgain()

        // Chosen for this app, it is offered there again.
        askToFill("CodeActivity", field = "code")
        find(mine("fill:Bank")).click()
        assertFilledWithCodeOf(BANK_CODE_SECRET)
        assertLockedAgain()
    }

    @Test
    fun aTrustedBrowsersCodeFieldIsFilledFromTheLoginsForItsOrigin() {
        // A login with a code for an origin without a port, which a page on
        // Android can be offered.
        session.reopenForTests { folder ->
            BiometricUnlock(context).disable()
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
            Device.open(folder.path).use { other ->
                other.unlock(password)
                other.createItem(
                    ItemDraft(
                        title = "Codes", kind = ItemKind.LOGIN, username = "code user",
                        url = "https://codes.example.test", notes = "", favorite = false, password = "x",
                        oneTimeCodeSecret = BANK_CODE_SECRET,
                    ),
                )
            }
        }
        Requester.trustedForTests += FIXTURE
        askToFill("WebLoginActivity", "https://codes.example.test", name = "web-code", extras = " --es page code")
        find(mine("fill:Codes"))
        capture("web-code-logins")
        find(mine("fill:Codes")).click()
        assertFilledWithCodeOf(BANK_CODE_SECRET)
        assertLockedAgain()

        // Mail is for its page but has no code: nothing is offered.
        askToFill("WebLoginActivity", "https://mail.example.test", extras = " --es page code")
        find(mine("no-logins"))
        assertNull(device.findObject(mine("fill:Mail")))
        find(mine("cancel")).click()
        assertLockedAgain()
    }

    private companion object {
        const val FIXTURE = "org.opensecretmanager.loginfixture"

        /** Bank's one-time code secret in the frozen vault (`crates/vault-core/examples/make_fixture.rs`). */
        const val BANK_CODE_SECRET = "JBSWY3DPEHPK3PXP"
    }
}
