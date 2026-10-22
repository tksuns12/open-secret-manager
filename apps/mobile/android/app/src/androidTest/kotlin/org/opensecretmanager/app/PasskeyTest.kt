package org.opensecretmanager.app

import android.app.UiAutomation
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.junit.runner.RunWith
import org.opensecretmanager.vault.PasskeyCaller

/**
 * Passkeys through Android's Credential Manager, end to end: the app's
 * provider is made the phone's, a stand-in app (`loginfixture`'s
 * PasskeyClientActivity) asks for a passkey for example.test as a site's own
 * app would, and the test goes through the system's sheet and this app's
 * screen as the owner would. What the stand-in receives is checked as a
 * site's server would check it, with `java.security`. A copy of the frozen
 * format 7 vault is the vault. The phone's check of the owner is a
 * fingerprint, which the run touches throughout (see
 * `scripts/test-mobile.sh`).
 */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 34)
class PasskeyTest {
    private val password = "fixture password, not a secret"
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val session = (context.applicationContext as VaultApp).session
    private val device = UiDevice.getInstance(instrumentation)
    private var previous = emptyList<Pair<String, String>>()

    @get:Rule
    val test = TestName()

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    @Before
    fun withTheProviderAndTheFrozenVault() {
        val service = "${context.packageName}/${context.packageName}.passkey.PasskeyProviderService"
        previous = listOf("credential_service", "credential_service_primary").map { it to shell("settings get secure $it").trim() }
        previous.forEach { (name, _) -> shell("settings put secure $name $service") }
        context.getSharedPreferences("passkey-apps", 0).edit().clear().commit()
        shell("pm set-app-links --package $FIXTURE 0 all")
        // The vault stays unlocked after this app's screens go, so that a
        // sign-in is offered the passkeys.
        StayUnlocked.millisForTests = 300_000L
        session.reopenForTests { folder ->
            BiometricUnlock(context).disable()
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
        waitUntil("the vault to open") { session.state.value.screen == Screen.LOCKED }
    }

    @After
    fun putTheProviderBack() {
        closeSheet()
        StayUnlocked.millisForTests = null
        shell("am force-stop $FIXTURE")
        shell("pm set-app-links --package $FIXTURE 0 all")
        previous.forEach { (name, value) ->
            shell(if (value.isEmpty() || value == "null") "settings delete secure $name" else "settings put secure $name $value")
        }
    }

    private fun waitUntil(what: String, timeout: Long = 15_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeout
        while (!condition()) {
            if (System.currentTimeMillis() > deadline) fail("waited for $what")
            Thread.sleep(100)
        }
    }

    /** Fails with [message], leaving what the screen showed and its window tree beside the autofill tests' (`scripts/test-mobile.sh` brings them back). */
    private fun fail(message: String): Nothing {
        val folder = context.getExternalFilesDir("failures")!!
        val name = "${test.methodName}-${System.currentTimeMillis()}"
        runCatching {
            File(folder, "$name.png").outputStream().use { instrumentation.uiAutomation.takeScreenshot()?.compress(Bitmap.CompressFormat.PNG, 100, it) }
        }
        runCatching { File(folder, "$name.xml").outputStream().use { device.dumpWindowHierarchy(it) } }
        File(folder, "$name.txt").writeText("$message\n")
        shell("mkdir -p $FAILURES")
        shell("cp ${folder.path}/$name.png ${folder.path}/$name.xml ${folder.path}/$name.txt $FAILURES/")
        throw AssertionError(message)
    }

    private fun find(selector: BySelector, timeout: Long = 20_000): UiObject2 =
        device.wait(Until.findObject(selector), timeout) ?: fail("nothing matches $selector")

    private fun mine(tag: String) = By.res(tag).pkg(context.packageName)

    /** The stand-in asks: `create` or `sign-in`, with [extras] for `am start`. Gives the challenge it sent. */
    private fun ask(action: String, extras: String = ""): String {
        device.wakeUp()
        closeSheet()
        val challenge = base64(ByteArray(32).also(java.security.SecureRandom()::nextBytes))
        shell("am start -W -S -n $FIXTURE/.PasskeyClientActivity --es challenge $challenge $extras")
        find(By.desc(action).pkg(FIXTURE)).click()
        return challenge
    }

    /** A sheet a test left, which would cover the stand-in. */
    private fun closeSheet() {
        repeat(3) {
            if (!device.hasObject(By.pkg(SHEET))) return
            device.pressBack()
            device.waitForIdle()
        }
    }

    /** In the system's sheet, the button that goes on with this app's entry. */
    private fun goOn() {
        find(By.text("Open Secret Manager").pkg(SHEET), 30_000)
        find(By.text("Continue").pkg(SHEET)).click()
    }

    /** What the stand-in received: the response, or its error. */
    private fun received(): String {
        val result = find(By.desc("result").pkg(FIXTURE), 60_000)
        if (!result.wait(Until.textMatches(".+"), 60_000)) fail("the stand-in received nothing")
        return result.text
    }

    private fun response(): JSONObject = received().let { if (it.startsWith("ERROR")) fail(it) else JSONObject(it) }

    private fun unbase64(text: String): ByteArray = Base64.decode(text, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun base64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /** The stand-in's origin, as WebAuthn gives an app one: the SHA-256 of its signing certificate. */
    private val fixtureOrigin: String by lazy {
        val signing = context.packageManager.getPackageInfo(FIXTURE, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo!!
        "android:apk-key-hash:" + base64(sha256(signing.apkContentsSigners[0].toByteArray()))
    }

    /** Checks a response's client data, as a site would, and gives it. */
    private fun clientData(response: JSONObject, type: String, challenge: String): ByteArray {
        val bytes = unbase64(response.getJSONObject("response").getString("clientDataJSON"))
        val data = JSONObject(String(bytes))
        assertEquals(type, data.getString("type"))
        assertEquals(challenge, data.getString("challenge"))
        assertEquals(fixtureOrigin, data.getString("origin"))
        return bytes
    }

    /** Checks a registration as a site would: its site, flags, and key. Gives the public key. */
    private fun registered(response: JSONObject, challenge: String, verified: Boolean): java.security.PublicKey {
        clientData(response, "webauthn.create", challenge)
        val inner = response.getJSONObject("response")
        val data = unbase64(inner.getString("authenticatorData"))
        assertArrayEquals(sha256("example.test".toByteArray()), data.copyOfRange(0, 32))
        // Present, backup eligible and backed up, attested; verified as said.
        assertEquals(if (verified) 0x5d else 0x59, data[32].toInt() and 0xff)
        assertEquals(-7, inner.getInt("publicKeyAlgorithm"))
        assertTrue(response.getJSONObject("clientExtensionResults").getJSONObject("credProps").getBoolean("rk"))
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(unbase64(inner.getString("publicKey"))))
    }

    /** Checks a sign-in as a site would: its site, flags, signature, and account. */
    private fun signedIn(response: JSONObject, challenge: String, key: java.security.PublicKey, verified: Boolean) {
        val client = clientData(response, "webauthn.get", challenge)
        val inner = response.getJSONObject("response")
        val data = unbase64(inner.getString("authenticatorData"))
        assertArrayEquals(sha256("example.test".toByteArray()), data.copyOfRange(0, 32))
        assertEquals(if (verified) 0x1d else 0x19, data[32].toInt() and 0xff)
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(key)
            update(data + sha256(client))
        }
        assertTrue("the signature is the passkey's", signature.verify(unbase64(inner.getString("signature"))))
        assertEquals("AQIDBA", inner.getString("userHandle"))
    }

    /** The passkeys on the vault's logins, by title. */
    private fun passkeyLogins(): Map<String, UInt> =
        session.state.value.items.filter { it.passkeys > 0u }.associate { it.title to it.passkeys }

    @Test
    fun anAppsPasskeyIsMadeAfterAWarningAndSignsInAsASiteWouldCheck() {
        val made = ask("create")
        goOn()
        // Locked: unlocked here, which verifies the owner.
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        // The app is not a browser, and no site named it as its own.
        assertTrue(find(mine("app-warning")).children.joinToString { it.text ?: "" }.contains("Login fixture is an app, not a browser"))
        assertEquals("Android has not verified that example.test names this app as its own.", find(mine("linked")).text)
        assertEquals("For example.test", find(mine("passkey-site")).text)
        find(mine("save-new"))
        find(mine("save-passkey")).click()
        val key = registered(response(), made, verified = true)
        waitUntil("the new login") { passkeyLogins() == mapOf("example.test" to 1u) }

        // Signed in with, from the unlocked vault, after the phone's check;
        // the app was allowed when it saved.
        val asked = ask("sign-in")
        find(By.text("fixture-user").pkg(SHEET), 30_000)
        goOn()
        signedIn(response(), asked, key, verified = true)

        // Locked between the list and the choice: unlocked on the screen,
        // which verifies the owner, then signed in.
        val late = ask("sign-in")
        find(By.text("fixture-user").pkg(SHEET), 30_000)
        runBlocking { session.lock().join() }
        goOn()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        signedIn(response(), late, key, verified = true)
    }

    @Test
    fun whileLockedTheListOffersAnUnlockAndAnAppIsAskedAboutOnceForASite() {
        // A passkey for the stand-in, made as a computer's import would.
        val certificate = sha256(
            context.packageManager.getPackageInfo(FIXTURE, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo!!.apkContentsSigners[0].toByteArray(),
        )
        runBlocking { session.unlock(password).join() }
        val registration = AtomicReference<String>()
        val options = JSONObject()
            .put("rp", JSONObject().put("id", "example.test").put("name", "Example"))
            .put("user", JSONObject().put("id", "AQIDBA").put("name", "fixture-user").put("displayName", "Fixture User"))
            .put("challenge", base64(ByteArray(32) { 7 }))
            .put("pubKeyCredParams", org.json.JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
        session.forPasskey({ it.createPasskey(options.toString(), PasskeyCaller.App(certificate), true, null) }) { registration.set(it.getOrThrow()) }
        waitUntil("the passkey") { registration.get() != null }
        val key = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(unbase64(JSONObject(registration.get()).getJSONObject("response").getString("publicKey"))),
        )
        runBlocking { session.lock().join() }
        // Android verified that the site names the stand-in as its own.
        shell("pm set-app-links --package $FIXTURE 2 example.test")

        // Locked, the list offers only an unlock, which says nothing of the vault.
        val asked = ask("sign-in")
        find(By.text(context.getString(R.string.passkey_unlock)).pkg(SHEET), 30_000).click()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        // Then the passkey, in the same list.
        find(By.text("fixture-user").pkg(SHEET), 30_000)
        goOn()
        // The first time this app asks for the site's passkeys: a warning.
        assertEquals("Android verified that example.test names this app as its own.", find(mine("linked"), 30_000).text)
        find(mine("allow-passkey")).click()
        signedIn(response(), asked, key, verified = true)

        // The second time, none: the phone's check alone.
        val again = ask("sign-in")
        find(By.text("fixture-user").pkg(SHEET), 30_000)
        goOn()
        signedIn(response(), again, key, verified = true)
    }

    @Test
    fun anAppsOwnClientDataHashIsIgnoredAndAnExcludedPasskeyIsNotMadeAgain() {
        // A hash of the app's own: ignored, and its client data made here.
        val made = ask("create", "--ez hash true --es verification discouraged")
        goOn()
        find(mine("password"), 60_000).text = password
        find(mine("unlock")).click()
        find(mine("save-passkey")).click()
        val registration = response()
        val key = registered(registration, made, verified = true)
        val id = registration.getString("id")

        // The site has it: another is not made, and the site is told once
        // the owner chose to save.
        ask("create", "--es exclude $id")
        goOn()
        find(mine("save-passkey"), 30_000).click()
        val refused = received()
        assertTrue(refused, refused.startsWith("ERROR ") && "INVALID_STATE_ERROR" in refused)
        assertEquals(mapOf("example.test" to 1u), passkeyLogins())

        // A sign-in that does not want the owner verified: no check, and
        // not flagged; signed over the client data made here, not the hash
        // the app sent.
        val asked = ask("sign-in", "--ez hash true --es verification discouraged --es allow $id")
        find(By.text("fixture-user").pkg(SHEET), 30_000)
        goOn()
        signedIn(response(), asked, key, verified = false)

        // A site no passkey may be for: this app offers no place to save
        // one, and leaves the request to others.
        ask("create", "--es rp github.io")
        find(By.pkg(SHEET), 30_000)
        device.waitForIdle()
        assertTrue("offered for github.io", !device.hasObject(By.text("Open Secret Manager").pkg(SHEET)))
    }

    private companion object {
        const val FIXTURE = "org.opensecretmanager.loginfixture"
        /** The system's sheet for Credential Manager, on an image with Google Play. */
        const val SHEET = "com.google.android.gms"
        /** Where failures are left for `scripts/test-mobile.sh`, as the autofill tests leave theirs. */
        const val FAILURES = "/data/local/tmp/osm-failures"
    }
}
