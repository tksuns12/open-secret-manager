package org.opensecretmanager.app

import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Requester

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

    /** Opens a form of the stand-in app, chooses "unlock to fill" in it, and unlocks. */
    private fun askToFill(activity: String, origin: String? = null, name: String? = null) {
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.$activity" + (origin?.let { " --es origin $it" } ?: ""))
        val field = if (origin == null) {
            find(By.res(FIXTURE, "username"))
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

    private companion object {
        const val FIXTURE = "org.opensecretmanager.loginfixture"
    }
}
