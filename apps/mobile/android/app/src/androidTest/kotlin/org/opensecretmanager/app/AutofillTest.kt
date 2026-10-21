package org.opensecretmanager.app

import android.app.KeyguardManager
import android.app.UiAutomation
import android.graphics.Bitmap
import android.os.Build
import android.os.PowerManager
import android.os.ParcelFileDescriptor
import android.view.KeyEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.Configurator
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
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Form
import org.opensecretmanager.app.autofill.OtherFieldService
import org.opensecretmanager.app.autofill.PendingSave
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.vault.AndroidKeystore
import org.opensecretmanager.vault.Device
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind

/**
 * Filling another app's forms through the system's autofill, end to end:
 * the app's service is made the phone's autofill service, a stand-in app
 * (the `loginfixture` module) shows a login form, and the test chooses
 * "unlock to fill" in it, unlocks the fill screen, and picks a login, as
 * the owner would. A copy of the frozen format 7 vault is the vault. The
 * vault locks as soon as the app is left, unless a test says otherwise.
 * The keyboard is the stand-in's plain one, which leaves the entries to the
 * system's list under the field, unless a test says otherwise ([Keyboard]).
 *
 * In a build made with `-Posm.screenshots=true` and run with the
 * instrumentation argument `screens=true`, it also captures the screens it
 * passes through for a person to look at (see [ScreensForReview]).
 *
 * When a wait fails, the test leaves what the screen showed, the window
 * tree, and why in [FAILURES] on the device, which `scripts/test-mobile.sh`
 * brings back (in any build; the app's own screens show black unless
 * screenshots are allowed).
 *
 * The test's own connection to Android's accessibility leaves accessibility
 * services running, which it would otherwise turn off while it lasts: a
 * test turns on the app's own ([OtherFieldService]) as the owner would.
 */
@RunWith(AndroidJUnit4::class)
class AutofillTest {
    init {
        Configurator.getInstance().uiAutomationFlags = UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES
    }

    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val session = (context.applicationContext as VaultApp).session
    private val device = UiDevice.getInstance(instrumentation)
    private var previousService: String? = null
    private val animationScales = listOf("window_animation_scale", "transition_animation_scale", "animator_duration_scale")
    private var previousScales = emptyList<String>()
    private val keyboard = Keyboard(::shell)
    private var previousAccessibility: Pair<String, String>? = null

    @get:Rule
    val test = TestName()

    /** The same connection as the [device]'s: another set of flags would replace it. */
    private val automation: UiAutomation
        get() = instrumentation.getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES)

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(automation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    @Before
    fun withTheServiceAndTheFrozenVault() {
        // Not this app's own service, which a run stopped before it put the
        // setting back would have left.
        previousService = shell("settings get secure autofill_service").trim()
            .takeIf { it.isNotEmpty() && it != "null" && !it.startsWith("${context.packageName}/") }
        shell("settings put secure autofill_service ${context.packageName}/.autofill.VaultAutofillService")
        // Without animations, an offer sliding up is where it is found
        // when it is tapped.
        previousScales = animationScales.map { shell("settings get global $it").trim() }
        animationScales.forEach { shell("settings put global $it 0") }
        keyboard.use("PlainKeyboard")
        context.getSharedPreferences("app-logins", 0).edit().clear().commit()
        Requester.trustedForTests.clear()
        forgetLinks()
        PendingSave.forgetForTests()
        StayUnlocked.millisForTests = 0L
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
        forgetLinks()
        PendingSave.forgetForTests()
        StayUnlocked.millisForTests = null
        shell("am force-stop $FIXTURE")
        turnOffOtherField()
        keyboard.putBack()
        shell(previousService?.let { "settings put secure autofill_service $it" } ?: "settings delete secure autofill_service")
        animationScales.zip(previousScales).forEach { (name, scale) ->
            shell(if (scale.isEmpty() || scale == "null") "settings delete global $name" else "settings put global $name $scale")
        }
        // The other tests' connection, as before.
        Configurator.getInstance().uiAutomationFlags = 0
    }

    /**
     * No site says the stand-in app is its own, and the owner set it to open
     * no site's links: the stand-in declares the links of `example.test`,
     * which a test approves as if the site had named it.
     */
    private fun forgetLinks() {
        shell("pm set-app-links --package $FIXTURE 0 all")
        shell("pm set-app-links-user-selection --user cur --package $FIXTURE false all")
    }

    /** Turns on [OtherFieldService], as the owner would in Android's accessibility settings, until the test ends. */
    private fun turnOnOtherField() {
        if (previousAccessibility == null) {
            previousAccessibility = shell("settings get secure enabled_accessibility_services").trim() to
                shell("settings get secure accessibility_enabled").trim()
        }
        shell("settings put secure enabled_accessibility_services ${context.packageName}/${OtherFieldService::class.java.name}")
        shell("settings put secure accessibility_enabled 1")
        waitUntil("the accessibility service to start") { OtherFieldService.connectedForTests }
    }

    private fun turnOffOtherField() {
        val (services, enabled) = previousAccessibility ?: return
        fun putBack(name: String, value: String) =
            shell(if (value.isEmpty() || value == "null") "settings delete secure $name" else "settings put secure $name $value")
        putBack("enabled_accessibility_services", services)
        putBack("accessibility_enabled", enabled)
        previousAccessibility = null
    }

    /** Fails with [message], leaving what the screen shows, its window tree, and the message in [FAILURES]. */
    private fun fail(message: String): Nothing {
        val folder = context.getExternalFilesDir("failures")!!
        val name = "${test.methodName}-${System.currentTimeMillis()}"
        runCatching {
            File(folder, "$name.png").outputStream().use { output ->
                automation.takeScreenshot()?.compress(Bitmap.CompressFormat.PNG, 100, output)
            }
        }
        runCatching { File(folder, "$name.xml").outputStream().use { device.dumpWindowHierarchy(it) } }
        File(folder, "$name.txt").writeText("$message\n")
        // Out of the app's own folders, which go when the run uninstalls it.
        shell("mkdir -p $FAILURES")
        shell("cp ${folder.path}/$name.png ${folder.path}/$name.xml ${folder.path}/$name.txt $FAILURES/")
        throw AssertionError(message)
    }

    private fun find(selector: BySelector, timeout: Long = 15_000): UiObject2 =
        device.wait(Until.findObject(selector), timeout) ?: fail("nothing matches $selector")

    private val capturing =
        BuildConfig.ALLOW_SCREENSHOTS && InstrumentationRegistry.getArguments().getString("screens") == "true"

    private fun capture(name: String) {
        if (!capturing) return
        device.waitForIdle()
        Thread.sleep(500)
        val folder = context.getExternalFilesDir("screens")!!
        automation.takeScreenshot()
            .compress(Bitmap.CompressFormat.PNG, 100, File(folder, "fill-$name.png").outputStream())
    }

    private fun mine(tag: String) = By.res(tag).pkg(context.packageName)

    /**
     * Opens a form of the stand-in app (with [extras] for `am start`), chooses
     * "unlock to fill" in it, and unlocks.
     */
    private fun askToFill(activity: String, origin: String? = null, name: String? = null, field: String = "username", extras: String = "") {
        val offer = openAndFind(OFFER, activity, origin, field, extras)
        name?.let { capture("$it-offer") }
        offer.click()
        // The fill screen's first start can take long on an emulator.
        find(mine("password"), 60_000)
        name?.let { capture("$it-locked") }
        find(mine("password")).text = password
        find(mine("unlock")).click()
        find(mine("asker"))
    }

    /**
     * Opens a form of the stand-in app (with [extras] for `am start`), taps
     * its field, and finds [entry] in the list the system shows under it.
     */
    private fun openAndFind(entry: BySelector, activity: String, origin: String? = null, field: String = "username", extras: String = ""): UiObject2 {
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.$activity" + (origin?.let { " --es origin $it" } ?: "") + extras)
        val form = if (origin == null) By.res(FIXTURE, field) else By.clazz("android.widget.EditText").pkg(FIXTURE)
        find(form, 30_000).click()
        // The system asks the service when the field takes the focus, and
        // on a busy emulator its offer was seen to take over 15 seconds, or
        // not to come; a field tapped again asks again.
        return device.wait(Until.findObject(entry), 30_000) ?: run {
            find(form).click()
            find(entry, 30_000)
        }
    }

    private fun assertFilled(expected: String) {
        val filled = find(By.res(FIXTURE, "filled"))
        if (filled.wait(Until.textEquals(expected), 15_000) != true) fail("filled: ${filled.text}")
    }

    /** The fill screen gone, the vault locks again. */
    private fun assertLockedAgain() {
        val deadline = System.currentTimeMillis() + 15_000
        while (session.state.value.screen != Screen.LOCKED && System.currentTimeMillis() < deadline) Thread.sleep(100)
        if (session.state.value.screen != Screen.LOCKED) fail("not locked again: ${session.state.value.screen}")
    }

    /** The fill screen gone a few seconds since, the vault is still unlocked. */
    private fun assertStillUnlocked() {
        Thread.sleep(3_000)
        if (session.state.value.screen != Screen.UNLOCKED) fail("locked: ${session.state.value.screen}")
    }

    @Test
    fun whileUnlockedAPagesLoginsAreInTheSystemsListAndFillAtOnce() {
        StayUnlocked.millisForTests = 60_000L
        Requester.trustedForTests += FIXTURE
        askToFill("WebLoginActivity", "https://mail.example.test")
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertStillUnlocked()

        // The next time, the list under the field names the login, and
        // choosing it fills the form, with no screen of this app's.
        val mail = openAndFind(By.text("Mail"), "WebLoginActivity", "https://mail.example.test")
        find(By.text("owner@example.test"))
        capture("web-unlocked-list")
        assertNull(device.findObject(By.text("Bank")))
        assertNull(device.findObject(OFFER))
        mail.click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertNull(device.findObject(mine("asker")))
        assertStillUnlocked()

        // A page with no login for it is told so, and offered the fill screen only.
        openAndFind(By.text("Open Secret Manager · no login for this site"), "WebLoginActivity", "https://bank.example.test")
        assertNull(device.findObject(By.text("Mail")))
    }

    @Test
    fun whileUnlockedAnAppIsListedTheLoginsChosenForItUntilTheTimeRunsOut() {
        StayUnlocked.millisForTests = 60_000L
        askToFill("NativeLoginActivity")
        find(mine("choose-another")).click()
        find(mine("fill:Bank")).click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        assertStillUnlocked()

        val bank = openAndFind(By.text("Bank"), "NativeLoginActivity")
        find(By.text("account 42"))
        find(By.text("Open Secret Manager…"))
        capture("app-unlocked-list")
        assertNull(device.findObject(By.text("Mail")))
        // Left unlocked for two seconds after this fill only.
        StayUnlocked.millisForTests = 2_000L
        bank.click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        assertLockedAgain()
        openAndFind(OFFER, "NativeLoginActivity")
        assertNull(device.findObject(By.text("Bank")))
    }

    /** [text] in the strip keyboard's strip. */
    private fun inStrip(text: String) = By.text(text).hasAncestor(By.desc(Keyboard.STRIP))

    /**
     * Whether the keyboard is up, and the system's list under the field is
     * not: on the owner's Galaxy phone, that list took the keyboard away.
     */
    private fun assertTheKeyboardIsUpAndNoListIs() {
        if ("mInputShown=true" !in shell("dumpsys input_method")) fail("the keyboard is down")
        if ("Autofill UI" in shell("dumpsys window windows")) fail("the system's list shows")
    }

    @Test
    fun aKeyboardThatAsksForTheEntriesInItsStripGetsThemThereAndStaysUp() {
        keyboard.use("StripKeyboard")
        StayUnlocked.millisForTests = 60_000L
        val unlock = openAndFind(inStrip("Unlock to fill"), "NativeLoginActivity")
        assertTheKeyboardIsUpAndNoListIs()
        capture("strip-locked")
        unlock.click()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        find(mine("choose-another")).click()
        find(mine("fill:Bank")).click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        assertStillUnlocked()

        // Unlocked, the strip names the login chosen for the app, which
        // fills the form with no screen of this app's.
        val bank = openAndFind(inStrip("Bank"), "NativeLoginActivity")
        find(inStrip("account 42"))
        find(inStrip("Open Secret Manager…"))
        assertNull(device.findObject(By.text("Mail")))
        assertTheKeyboardIsUpAndNoListIs()
        capture("strip-unlocked")
        bank.click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        assertNull(device.findObject(mine("asker")))
    }

    @Test
    fun turningTheScreenOffLocksAtOnce() {
        // The screen is unlocked again with the device's PIN, if it has one.
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        val pin = InstrumentationRegistry.getArguments().getString("pin")
        assumeTrue("the device has a PIN, and the run was not given it", !keyguard.isDeviceSecure || pin != null)
        StayUnlocked.millisForTests = 60_000L
        Requester.trustedForTests += FIXTURE
        askToFill("WebLoginActivity", "https://mail.example.test")
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertStillUnlocked()
        val power = context.getSystemService(PowerManager::class.java)
        device.sleep()
        assertLockedAgain()
        // Woken too soon after, the screen stayed off and locked.
        waitUntil("the screen turns off") { !power.isInteractive }
        Thread.sleep(1_000)
        for (attempt in 1..3) {
            device.wakeUp()
            waitUntil("the screen turns on") { power.isInteractive }
            Thread.sleep(1_000)
            if (pin != null) {
                shell("input keyevent KEYCODE_MENU")
                Thread.sleep(1_000)
                shell("input text $pin")
                shell("input keyevent KEYCODE_ENTER")
            }
            shell("wm dismiss-keyguard")
            val deadline = System.currentTimeMillis() + 10_000
            while (keyguard.isKeyguardLocked && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!keyguard.isKeyguardLocked) break
            if (attempt == 3) fail("the screen stayed locked")
        }
        openAndFind(OFFER, "WebLoginActivity", "https://mail.example.test")
    }

    private fun waitUntil(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 15_000
        while (!condition() && System.currentTimeMillis() < deadline) Thread.sleep(100)
        if (!condition()) fail("waited for $what")
    }

    @Test
    fun aPageWhoseOutermostViewNamesAnEmptyDomainIsKnownByItsFields() {
        Requester.trustedForTests += FIXTURE
        askToFill("NestedDomainLoginActivity")
        assertEquals("For shop.example.test", find(mine("asker")).text)
        find(mine("no-logins"))
        find(mine("cancel")).click()
        assertLockedAgain()

        submitAndSave("NestedDomainLoginActivity", null, "shopper", "shop password")
        assertEquals("shop.example.test", find(mine("save-title")).text)
        find(mine("save-new")).click()
        assertLockedAgain()
        Device.open(context.filesDir.resolve(VaultApp.DEVICE_FOLDER).path, AndroidKeystore).use { vault ->
            vault.unlock(password)
            assertTrue(vault.items().any { it.title == "shop.example.test" && it.url == "https://shop.example.test" })
        }
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
        // Every login is listed, and a search narrows them, as in the app.
        find(mine("fill:Mail"))
        find(mine("fill-search")).text = "BAN"
        device.wait(Until.gone(mine("fill:Mail")), 5_000)
        assertNull(device.findObject(mine("fill:Mail")))
        find(mine("fill:Bank")).click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        // The fill screen let the app be seen beneath it, which only paused
        // it: its fields never went out of the system's sight.
        assertEquals("0", find(By.res(FIXTURE, "stopped")).text)
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
    fun anAppASiteNamesAsItsOwnIsSuggestedTheLoginsSavedForThatSite() {
        assumeTrue("app links are verified for each site from Android 12 on", Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        // The owner set the app to open the site's links: that is not the
        // site saying the app is its own, and nothing is suggested.
        shell("pm set-app-links-user-selection --user cur --package $FIXTURE true example.test")
        askToFill("NativeLoginActivity")
        find(mine("choose-another"))
        assertNull(device.findObject(mine("linked")))
        assertNull(device.findObject(mine("fill:Mail")))
        find(mine("cancel")).click()
        assertLockedAgain()

        // Verified for example.test, as Android does once the site names
        // the app: Mail, saved for mail.example.test, is suggested. Bank,
        // saved for a port of its own on a host under it, is not.
        shell("pm set-app-links --package $FIXTURE 2 example.test")
        askToFill("NativeLoginActivity", name = "linked")
        find(mine("linked"))
        capture("app-linked")
        assertNull(device.findObject(mine("fill:Bank")))
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertLockedAgain()

        // Chosen, it is the app's, offered with the site no longer saying so.
        forgetLinks()
        askToFill("NativeLoginActivity")
        find(mine("fill:Mail"))
        assertNull(device.findObject(mine("linked")))
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertLockedAgain()
    }

    @Test
    fun anIdFieldThatSaysNothingToAutofillIsKnownByItsName() {
        // Named "user_id" and "아이디…", with a field for a company code
        // between it and the password: it is offered the fill, and gets the
        // username; the company code is left alone.
        askToFill("NamedLoginActivity", field = "user_id")
        find(mine("choose-another")).click()
        find(mine("fill:Bank")).click()
        assertFilled("account 42||p@ss \"quoted\" \\ and 🔑")
        assertLockedAgain()

        // Typed as a password shown as typed: it is the ID, and the field
        // that hides what is typed is the password.
        askToFill("NamedLoginActivity", field = "login_id", extras = " --es form shown")
        find(mine("fill:Bank")).click()
        assertFilled("account 42|p@ss \"quoted\" \\ and 🔑")
        assertLockedAgain()
    }

    @Test
    fun aPageThatReportsItsFieldsOneAtATimeIsFilledFieldByField() {
        // The ID and the password each in a form of their own, as in the web
        // view of an app the owner signs in to: the system is told only of
        // the field that has the focus. The ID is offered the fill, and,
        // unless the owner turned on filling both fields together, gets the
        // username alone.
        StayUnlocked.millisForTests = 60_000L
        askToFill("WebLoginActivity", "https://mail.example.test", extras = " --es page split")
        find(mine("choose-another")).click()
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|")
        assertStillUnlocked()

        // The password then, from the list under it, with the login chosen
        // for the page.
        val fields = device.wait(Until.findObjects(By.clazz("android.widget.EditText").pkg(FIXTURE)), 15_000)
        if (fields == null || fields.size < 2) fail("the page's two fields: ${fields?.size}")
        fields[1].click()
        val mail = device.wait(Until.findObject(By.text("Mail")), 30_000) ?: run {
            fields[1].click()
            find(By.text("Mail"), 30_000)
        }
        mail.click()
        assertFilled("owner@example.test|third password, with ünïcödé")
    }

    /** The split page's two fields, the ID and the password, once the page has both. */
    private fun splitPageFields(): List<UiObject2> {
        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline) {
            val fields = device.findObjects(By.clazz("android.widget.EditText").pkg(FIXTURE))
            if (fields.size >= 2) return fields
            Thread.sleep(200)
        }
        fail("the page's two fields")
    }

    @Test
    fun withBothFieldsFilledTogetherALoginChosenForEitherFieldFillsTheOtherToo() {
        // The owner turned it on: a login chosen for the ID fills the
        // password too, into the page's own field.
        turnOnOtherField()
        askToFill("WebLoginActivity", "https://mail.example.test", extras = " --es page split")
        find(mine("choose-another")).click()
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertLockedAgain()

        // Chosen for the password, it fills the ID too.
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.WebLoginActivity --es origin https://mail.example.test --es page split")
        val fields = splitPageFields()
        fields[1].click()
        val offer = device.wait(Until.findObject(OFFER), 30_000) ?: run {
            fields[1].click()
            find(OFFER, 30_000)
        }
        offer.click()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|third password, with ünïcödé")
        assertLockedAgain()
    }

    @Test
    fun aBrowsersPageThatReportsItsFieldsOneAtATimeGetsOnlyTheFieldThatAsked() {
        // A browser's next page can be another site's: the password is not
        // put into the page's own field, the browser trusted or not.
        turnOnOtherField()
        Requester.trustedForTests += FIXTURE
        askToFill("WebLoginActivity", "https://mail.example.test", extras = " --es page split")
        find(mine("fill:Mail")).click()
        assertFilled("owner@example.test|")
        Thread.sleep(6_000)
        assertEquals("owner@example.test|", find(By.res(FIXTURE, "filled")).text)
        assertLockedAgain()

        // Not trusted, but opening a link to any site.
        Requester.trustedForTests.clear()
        try {
            askToFill("WebLoginActivity", "https://mail.example.test", extras = " --es page split --ez asBrowser true")
            find(mine("choose-another")).click()
            find(mine("fill:Mail")).click()
            assertFilled("owner@example.test|")
            Thread.sleep(6_000)
            assertEquals("owner@example.test|", find(By.res(FIXTURE, "filled")).text)
            assertLockedAgain()
        } finally {
            shell("am start -W -S -n $FIXTURE/.WebLoginActivity --ez asBrowser false")
        }
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
     * Types [text] as keys into the page's focused field, and says whether
     * the page then reports what [shows] makes of it. While the offer to
     * fill shows under the field, the system passes keys through it, and
     * loses or reorders some (a space even chooses it); the on-screen
     * keyboard's typing does not go that way. One key closes the offer, so
     * it is typed once the offer shows, and the rest once the page has it
     * and the offer is gone: on a slow emulator the offer can take seconds
     * to come.
     */
    private fun typeKeys(text: String, shows: (String) -> String): Boolean {
        val filled = find(By.res(FIXTURE, "filled"))
        device.wait(Until.hasObject(OFFER), 15_000)
        shell("input text ${text.take(1)}")
        if (filled.wait(Until.textEquals(shows(text.take(1))), 5_000) != true) return false
        device.wait(Until.gone(OFFER), 15_000)
        shell("input text ${text.drop(1)}")
        return filled.wait(Until.textEquals(shows(text)), 5_000) == true
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
                if (typeKeys(username) { "$it|" } &&
                    device.pressKeyCode(KeyEvent.KEYCODE_TAB) &&
                    typeKeys(password) { "$username|$it" }
                ) {
                    break
                }
                if (attempt == 3) fail("the page never got all the keys typed")
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
        // With animations off, the offer does not slide up: a tap while it
        // moved could land beside it, which closes it.
        find(By.res("android", "autofill_save_yes"))
        name?.let { capture("$it-save-offer") }
        find(By.res("android", "autofill_save_yes")).click()
        find(mine("password"), 60_000)
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
    fun aSaveAndroidDidNotOpenIsOfferedWhenTheAppIsOpened() {
        // The stand-in closes on signing in, and Save is tapped well after:
        // Android does not start the save screen (`BAL_BLOCK` in its log).
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.NativeLoginActivity --es after close")
        find(By.res(FIXTURE, "username")).click()
        find(By.res(FIXTURE, "username")).text = "late account"
        find(By.res(FIXTURE, "password")).text = "late password"
        find(By.res(FIXTURE, "sign_in")).click()
        val left = System.currentTimeMillis()
        find(By.res("android", "autofill_save_yes"), 30_000)
        // Past the few seconds Android still allows it after the app left.
        Thread.sleep(maxOf(0L, left + 25_000 - System.currentTimeMillis()))
        device.wakeUp()
        find(By.res("android", "autofill_save_yes")).click()
        if (device.wait(Until.hasObject(mine("password")), 10_000) == true) fail("Android opened the save screen after all")

        // Opened, the app offers it, named as the save screen names it.
        shell("am start -W -n ${context.packageName}/.MainActivity")
        find(mine("waiting-save"), 30_000)
        find(By.text("A login from Login fixture is waiting to be saved"))
        capture("waiting-save")
        find(mine("waiting-save-open")).click()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        find(mine("asker"))
        find(mine("save-new")).click()
        // Saved, from the app's own screen: the app is in front, unlocked,
        // and offers it no more.
        if (device.wait(Until.gone(mine("waiting-save")), 15_000) != true) fail("the save is still offered")
        val deadline = System.currentTimeMillis() + 15_000
        while (session.state.value.items.none { it.title == "Login fixture" } && System.currentTimeMillis() < deadline) Thread.sleep(100)
        assertTrue(session.state.value.items.any { it.title == "Login fixture" && it.username == "late account" })
        assertNull(PendingSave.waiting())

        // Android held its start back, and makes it once the stand-in is
        // opened again: the save screen sees the save was handled, and
        // closes at once.
        shell("am start -W -n $FIXTURE/.NativeLoginActivity")
        if (device.wait(Until.hasObject(mine("password")), 15_000) == true) fail("a save screen opened for a save already made")

        askToFill("NativeLoginActivity")
        find(mine("fill:Login fixture")).click()
        assertFilled("late account|late password")
        assertLockedAgain()
    }

    @Test
    fun aSignInOnTwoScreensIsSavedWithTheUsernameOfTheFirst() {
        // The account on one screen, the password on the next.
        device.wakeUp()
        shell("am start -W -S -n $FIXTURE/.TwoStepUsernameActivity")
        find(By.res(FIXTURE, "username")).click()
        find(By.res(FIXTURE, "username")).text = "two step user"
        find(By.res(FIXTURE, "next")).click()
        find(By.res(FIXTURE, "password"), 30_000).click()
        find(By.res(FIXTURE, "password")).text = "two step password"
        if (find(By.res(FIXTURE, "filled")).wait(Until.textEquals("two step user|two step password"), 15_000) != true) {
            fail("the second screen did not get what was typed")
        }
        find(By.res(FIXTURE, "sign_in")).click()
        // The system offers to save both, from both screens.
        find(By.res("android", "autofill_save_yes"), 30_000)
        find(By.textContains("username and password"))
        capture("two-step-save-offer")
        find(By.res("android", "autofill_save_yes")).click()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        find(mine("asker"))
        assertEquals("two step user", find(mine("save-username")).text)
        find(mine("save-new")).click()
        assertLockedAgain()
        Device.open(context.filesDir.resolve(VaultApp.DEVICE_FOLDER).path, AndroidKeystore).use { vault ->
            vault.unlock(password)
            assertTrue(vault.items().any { it.title == "Login fixture" && it.username == "two step user" })
        }
    }

    @Test
    fun aWaitingSaveCanBeDiscarded() {
        val form = Form(FIXTURE, null, null, null, null, null)
        PendingSave.put(PendingSave.Save(form, "someone", "a password"), "Login fixture")
        shell("am start -W -n ${context.packageName}/.MainActivity")
        find(mine("waiting-save-discard"), 30_000).click()
        if (device.wait(Until.gone(mine("waiting-save")), 15_000) != true) fail("the save is still offered")
        assertNull(PendingSave.waiting())
        // Not offered again when the app comes back.
        shell("am start -W -n ${context.packageName}/.MainActivity")
        device.waitForIdle()
        assertNull(device.findObject(mine("waiting-save")))
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
        if (filled.wait(Until.textMatches("[0-9]{6}"), 15_000) != true) fail("filled: ${filled.text}")
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
            Device.open(folder.path, AndroidKeystore).use { other ->
                other.unlock(password)
                other.createItem(
                    ItemDraft(
                        title = "Codes", kind = ItemKind.LOGIN, username = "code user",
                        url = "https://codes.example.test", notes = "", favorite = false, password = "x",
                        oneTimeCodeSecret = BANK_CODE_SECRET,
                        card = null,
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

        /** The service's offer under a field, to unlock and fill it. */
        val OFFER: BySelector = By.text("Open Secret Manager · unlock to fill")

        /** Where a failed wait leaves what it saw, on the device. */
        const val FAILURES = "/data/local/tmp/osm-failures"

        /** Bank's one-time code secret in the frozen vault (`crates/vault-core/examples/make_fixture.rs`). */
        const val BANK_CODE_SECRET = "JBSWY3DPEHPK3PXP"
    }
}
