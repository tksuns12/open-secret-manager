package org.opensecretmanager.vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The phone interface through its generated Kotlin bindings, on a copy of
 * the frozen format 7 vault: the same checks as
 * crates/mobile/tests/frozen_vault.rs, on an emulator or a device.
 */
@RunWith(AndroidJUnit4::class)
class DeviceTest {
    private val password = "fixture password, not a secret"

    private fun copyOfTheFrozenVault(): File {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val folder = File(instrumentation.targetContext.filesDir, "device-${System.nanoTime()}")
        folder.mkdirs()
        instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
            File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
        }
        return folder
    }

    private inline fun <reified E : MobileException> fails(call: () -> Unit) {
        try {
            call()
        } catch (error: MobileException) {
            assertTrue("expected ${E::class.simpleName}, got $error", error is E)
            return
        }
        fail("expected ${E::class.simpleName}, but the call succeeded")
    }

    @Test
    fun theFrozenVaultReadsThroughTheBindings() {
        val folder = copyOfTheFrozenVault()
        val device = Device.open(folder.path)
        try {
            assertEquals(DeviceState.LOCKED, device.state())
            fails<MobileException.Locked> { device.items() }
            fails<MobileException.InvalidCredentials> { device.unlock("not the password") }
            device.unlock(password)
            assertEquals(DeviceState.UNLOCKED, device.state())

            val items = device.items()
            val titles = items.map { it.title }
            assertTrue("$titles", "Bank" in titles && "Mail" in titles)
            assertTrue("a conflict is shown as one", items.any { it.conflict })

            val bank = device.item("fixture-bank")
            assertEquals("Bank", bank.title)
            assertEquals(ItemKind.LOGIN, bank.kind)
            assertEquals("account 42", bank.username)
            assertTrue(bank.hasPassword && bank.hasOneTimeCode && bank.favorite)
            assertEquals("line one\nline two", bank.notes)
            assertEquals("p@ss \"quoted\" \\ and 🔑", device.password("fixture-bank"))
            val code = device.oneTimeCode("fixture-bank")
            assertTrue(code, code.length == 6 && code.all { it.isDigit() })
            assertEquals("third password, with ünïcödé", device.password("fixture-mail"))
            fails<MobileException.NoOneTimeCode> { device.oneTimeCode("fixture-mail") }
            fails<MobileException.NotFound> { device.item("no such item") }

            // A copy of a vault is not a device of its vault's devices.
            fails<MobileException.Network> { device.goOnline() }
            assertEquals(SyncState.OFFLINE, device.syncStatus().state)
            device.lock()
            fails<MobileException.Locked> { device.password("fixture-bank") }
        } finally {
            device.close()
            folder.deleteRecursively()
        }
    }
}
