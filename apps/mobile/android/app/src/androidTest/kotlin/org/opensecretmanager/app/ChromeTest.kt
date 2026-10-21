package org.opensecretmanager.app

import android.net.Uri
import android.os.ParcelFileDescriptor
import android.util.Log
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
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.vault.AndroidKeystore
import org.opensecretmanager.vault.Device
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind

/**
 * Filling and saving in real Chrome, not a stand-in: run by
 * scripts/test-mobile-chrome.sh, which serves a test site over HTTPS on this
 * computer, has Chrome reach it by name and trust it, and passes its address
 * as the instrumentation argument `chromeSite`; the site logs what its forms
 * send, which the script compares with what this test logs. Chrome must use
 * this app for autofill ("Autofill using another service"), which only its
 * own settings screen can choose. Skipped without the argument.
 *
 * With the argument `browser` naming another package, Chromium's for one,
 * that browser is driven instead. It is not on the list of browsers the
 * app trusts to say which page it shows, so this test trusts it.
 */
@RunWith(AndroidJUnit4::class)
class ChromeTest {
    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val session = (context.applicationContext as VaultApp).session
    private val device = UiDevice.getInstance(instrumentation)
    private val site: String? = InstrumentationRegistry.getArguments().getString("chromeSite")
    private val browser: String = InstrumentationRegistry.getArguments().getString("browser") ?: CHROME
    private var previousService: String? = null
    private val keyboard = Keyboard(::shell)

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    /** The origin a login for the site is saved for: Android reports a page's host, not its port. */
    private val origin get() = "https://${Uri.parse(site).host}"

    @Before
    fun withTheServiceAndALoginForTheSite() {
        assumeTrue("no chromeSite argument", site != null)
        // A keyboard that leaves the entries to the system's list.
        keyboard.use("PlainKeyboard")
        previousService = shell("settings get secure autofill_service").trim()
            .takeIf { it.isNotEmpty() && it != "null" && !it.startsWith("${context.packageName}/") }
        shell("settings put secure autofill_service ${context.packageName}/.autofill.VaultAutofillService")
        if (browser != CHROME) Requester.trustedForTests += browser
        // Each fill and save is checked to lock the vault again at once.
        StayUnlocked.millisForTests = 0L
        session.reopenForTests { folder ->
            BiometricUnlock(context).disable()
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
            Device.open(folder.path, AndroidKeystore).use { vault ->
                vault.unlock(password)
                vault.createItem(
                    ItemDraft(
                        title = "Test site", kind = ItemKind.LOGIN, username = "site-user",
                        url = origin, notes = "", favorite = false, password = "site-pass-1",
                        oneTimeCodeSecret = CODE_SECRET,
                        card = null,
                    ),
                )
            }
        }
    }

    @After
    fun putTheServiceBack() {
        StayUnlocked.millisForTests = null
        keyboard.putBack()
        if (site == null) return
        Requester.trustedForTests.clear()
        shell(previousService?.let { "settings put secure autofill_service $it" } ?: "settings delete secure autofill_service")
    }

    private fun find(selector: BySelector, timeout: Long = 30_000): UiObject2 =
        device.wait(Until.findObject(selector), timeout) ?: throw AssertionError("nothing matches $selector")

    private fun mine(tag: String) = By.res(tag).pkg(context.packageName)

    private fun inChrome(selector: BySelector) = selector.pkg(browser)

    /** The page's text fields, in order: not Chrome's address bar, which is one too. */
    private fun fields(): List<UiObject2> {
        val field = inChrome(By.clazz("android.widget.EditText").hasAncestor(By.clazz("android.webkit.WebView")))
        find(field)
        return device.findObjects(field)
    }

    /** Opens the page and waits until it shows [text]. */
    private fun open(path: String, text: String) {
        device.wakeUp()
        // A new address each time, so that Chrome loads the page afresh.
        shell("am start -W -a android.intent.action.VIEW -d $site$path?at=${System.nanoTime()} $browser")
        find(inChrome(By.text(text).hasAncestor(By.clazz("android.webkit.WebView"))), 60_000)
    }

    /** Taps the field, chooses "unlock to fill" under it, unlocks, and picks the login. */
    private fun fillFrom(field: UiObject2, login: String) {
        field.click()
        find(By.text(OFFER), 60_000).click()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        find(mine("fill:$login"), 60_000).click()
    }

    /** Taps the page's button, found again until the tap reaches it: the page may redo its tree. */
    private fun press(label: String) {
        for (attempt in 1..3) {
            try {
                find(inChrome(By.clazz("android.widget.Button").text(label))).click()
                return
            } catch (stale: StaleObjectException) {
                if (attempt == 3) throw stale
            }
        }
    }

    private fun assertLockedAgain() {
        val deadline = System.currentTimeMillis() + 30_000
        while (session.state.value.screen != Screen.LOCKED && System.currentTimeMillis() < deadline) Thread.sleep(100)
        assertEquals(Screen.LOCKED, session.state.value.screen)
    }

    // What a form sent is checked on the site, which logs it: after a form
    // is sent, Chrome's accessibility tree can show the page before it for
    // a while, so the test waits instead of reading the next page.
    @Test
    fun aLoginAndThenItsCodeFillIntoChrome() {
        open("/login", "Email or username")
        fillFrom(fields()[0], "Test site")
        find(inChrome(By.text("site-user")), 30_000)
        assertLockedAgain()
        press("Sign in")
        Thread.sleep(5_000)
        Log.i("OSMChrome", "CHROME-SIGNED-IN")

        open("/code", "Verify")
        val now = System.currentTimeMillis() / 1000
        fillFrom(fields()[0], "Test site")
        val codes = setOf(totp(CODE_SECRET, now), totp(CODE_SECRET, now + 30), totp(CODE_SECRET, now - 30))
        val deadline = System.currentTimeMillis() + 30_000
        var filled = ""
        while (filled !in codes && System.currentTimeMillis() < deadline) {
            filled = fields().firstOrNull()?.text.orEmpty()
            Thread.sleep(300)
        }
        assertTrue("filled: $filled, expected one of $codes", filled in codes)
        assertLockedAgain()
        press("Verify")
        Thread.sleep(5_000)
        Log.i("OSMChrome", "CHROME-CODE $filled")
    }

    @Test
    fun aLoginTypedIntoChromeIsSavedForTheSite() {
        // Typed as keys, since a page reports only what was typed. Typed
        // again, afresh, until the page shows the username whole; the site
        // checks the password.
        for (attempt in 1..3) {
            open("/login", "Email or username")
            typeInto(fields()[0], "new-user")
            typeInto(fields()[1], "new-pass-1")
            if (device.wait(Until.hasObject(inChrome(By.text("new-user").hasAncestor(By.clazz("android.webkit.WebView")))), 5_000) == true) break
            check(attempt < 3) { "the page never got all the keys typed" }
        }
        press("Sign in")
        // The offer slides up: tapped while it moves, the tap can land
        // beside it, which closes it.
        find(By.res("android", "autofill_save_yes"), 60_000)
        Thread.sleep(2_000)
        find(By.res("android", "autofill_save_yes")).click()
        find(mine("password")).text = password
        find(mine("unlock")).click()
        assertEquals(Uri.parse(site).host, find(mine("save-title")).text)
        find(mine("save-new")).click()
        assertLockedAgain()
        Log.i("OSMChrome", "CHROME-SAVED")

        // Offered on the site from now on, beside the login it had.
        open("/login", "Email or username")
        fields()[0].click()
        find(By.text(OFFER), 60_000).click()
        find(mine("password")).text = password
        find(mine("unlock")).click()
        find(mine("fill:${Uri.parse(site).host}"), 60_000)
        find(mine("fill:Test site"))
        find(mine("cancel")).click()
        assertLockedAgain()
    }

    @Test
    fun aSignInOnTwoPagesIsSavedWithTheUsernameOfTheFirst() {
        // The username on one page; the next asks for the password only,
        // and the save takes the username from the page before.
        open("/signin", "Email or username")
        typeInto(fields()[0], "two-page-user")
        press("Next")
        find(inChrome(By.textContains("Signing in as two-page-user")), 60_000)
        typeInto(fields()[0], "two-page-pass-1")
        press("Sign in")
        find(By.res("android", "autofill_save_yes"), 60_000)
        Thread.sleep(2_000)
        find(By.res("android", "autofill_save_yes")).click()
        find(mine("password")).text = password
        find(mine("unlock")).click()
        assertEquals(Uri.parse(site).host, find(mine("save-title")).text)
        assertEquals("two-page-user", find(mine("save-username")).text)
        find(mine("save-new")).click()
        assertLockedAgain()
        Log.i("OSMChrome", "CHROME-TWO-PAGES-SAVED")
    }

    /**
     * Types [text] into the field as keys. While the offer to fill shows
     * under the field, keys pass through it and some are lost or reordered;
     * the first key closes it, so the rest wait until it is gone.
     */
    private fun typeInto(field: UiObject2, text: String) {
        field.click()
        device.wait(Until.hasObject(By.text(OFFER)), 30_000)
        shell("input text ${text.take(1)}")
        device.wait(Until.gone(By.text(OFFER)), 30_000)
        Thread.sleep(500)
        shell("input text ${text.drop(1)}")
    }

    /** RFC 6238 with SHA-1, 30-second steps, 6 digits. */
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
        val number = ((hash[offset].toInt() and 0x7f) shl 24) or ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or (hash[offset + 3].toInt() and 0xff)
        return (number % 1_000_000).toString().padStart(6, '0')
    }

    private companion object {
        const val CHROME = "com.android.chrome"
        const val OFFER = "Open Secret Manager · unlock to fill"

        /** The test vector's secret, as the frozen vault's Bank has it. */
        const val CODE_SECRET = "JBSWY3DPEHPK3PXP"
    }
}
