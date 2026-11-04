package org.opensecretmanager.vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
        val device = Device.open(folder.path, AndroidKeystore)
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
            assertEquals(listOf("Branch", "PIN"), bank.fields)
            assertEquals("0000", device.field("fixture-bank", "PIN"))
            fails<MobileException.NoSuchField> { device.field("fixture-bank", "pin") }
            assertEquals("p@ss \"quoted\" \\ and 🔑", device.password("fixture-bank"))
            val code = device.oneTimeCode("fixture-bank")
            assertTrue(code, code.length == 6 && code.all { it.isDigit() })
            assertEquals("third password, with ünïcödé", device.password("fixture-mail"))
            fails<MobileException.NoOneTimeCode> { device.oneTimeCode("fixture-mail") }
            fails<MobileException.NotFound> { device.item("no such item") }

            // What fills a form: a page gets only the logins for its origin,
            // an app only a login the owner chose for it, which it keeps.
            val mailPage = Requester.Page(listOf("https://mail.example.test"))
            assertEquals(listOf("Mail"), device.offer(mailPage, Asks.LOGIN).logins.map { it.title })
            fails<MobileException.InvalidOrigin> { device.offer(Requester.Page(listOf("http://mail.example.test")), Asks.LOGIN) }
            val filled = device.fill(mailPage, "fixture-mail", Asks.LOGIN)
            assertEquals("owner@example.test", filled.credentials?.username)
            assertEquals("third password, with ünïcödé", filled.credentials?.password)
            assertNull(filled.oneTimeCode)
            fails<MobileException.NotForThisPage> { device.fill(mailPage, "fixture-bank", Asks.LOGIN) }
            val app = Requester.App("org.example.app:AB12", listOf("example.test"))
            fails<MobileException.NotChosen> { device.fill(app, "fixture-bank", Asks.LOGIN) }
            assertEquals("account 42", device.fillChosen(app, "fixture-bank", Asks.LOGIN).credentials?.username)
            assertEquals(listOf("Bank"), device.offer(app, Asks.LOGIN).logins.map { it.title })
            device.importAppChoices(mapOf("org.example.other:CD34" to listOf("fixture-mail")))
            assertEquals(listOf("Mail"), device.offer(Requester.App("org.example.other:CD34", emptyList()), Asks.LOGIN).logins.map { it.title })
            assertTrue(device.offer(Requester.Unnamed, Asks.LOGIN).logins.isEmpty())

            // An item's history, and a deleted note, come back.
            val history = device.history("fixture-mail")
            assertEquals(listOf("password", "notes"), history[0].changed)
            device.restore("fixture-mail", history[2].revision, listOf(history[0].revision))
            assertEquals("first password", device.password("fixture-mail"))
            val note = device.deletedItems().first { it.title == "A note that was deleted" }
            device.restore(note.id, note.last, note.heads)
            assertEquals("gone", device.item(note.id).notes)

            // A one-time code goes only where its login would.
            assertEquals(listOf("Bank"), device.loginsToChoose(Asks.ONE_TIME_CODE).map { it.title })
            val bankPage = Requester.Page(listOf("https://bank.example.test:8443"))
            assertEquals(6, device.fill(bankPage, "fixture-bank", Asks.ONE_TIME_CODE).oneTimeCode?.length)
            fails<MobileException.NotForThisPage> { device.fill(Requester.Page(listOf("https://bank.example.test")), "fixture-bank", Asks.ONE_TIME_CODE) }
            fails<MobileException.NoOneTimeCode> { device.fill(mailPage, "fixture-mail", Asks.ONE_TIME_CODE) }

            // The owner's edits cross the other way, unicode and all.
            val draft = ItemDraft(
                title = "Forum", kind = ItemKind.LOGIN, username = "me", url = "https://forum.example.test",
                notes = "", favorite = false, password = "新しい 🔑 \"pass\"", oneTimeCodeSecret = null, card = null,
            )
            val created = device.createItem(draft)
            assertEquals("新しい 🔑 \"pass\"", device.password(created))
            val read = device.item(created)
            val renamed = draft.copy(username = "someone else", password = null)
            device.updateItem(created, read.revision, renamed)
            assertEquals("someone else", device.item(created).username)
            assertEquals("新しい 🔑 \"pass\"", device.password(created))
            fails<MobileException.ChangedElsewhere> { device.updateItem(created, read.revision, renamed) }
            fails<MobileException.NotEditableHere> { device.createItem(draft.copy(kind = ItemKind.IDENTITY)) }
            // What a form submitted goes into a login the form could fill, as its password only.
            val forum = Requester.Page(listOf("https://forum.example.test"))
            val candidates = device.saveCandidatesFor(forum, "someone else", "新しい 🔑 \"pass\"")
            assertEquals(listOf(true), candidates.map { it.hasThisPassword })
            assertTrue(device.saveCandidatesFor(forum, "another", "x").isEmpty())
            fails<MobileException.NotForThisForm> { device.updateSaved(mailPage, created, candidates[0].revision, "someone else", "x") }
            device.updateSaved(forum, created, candidates[0].revision, "someone else", "次の 🔑")
            assertEquals("次の 🔑", device.password(created))
            assertEquals("someone else", device.item(created).username)
            device.deleteItem(created, device.item(created).revision)
            fails<MobileException.NotFound> { device.item(created) }
            val saved = device.saveNew(forum, "Forum again", "me", "x")
            assertEquals("https://forum.example.test", device.item(saved).url)
            device.deleteItem(saved, device.item(saved).revision)
            assertEquals(24, generatePassword(defaultPasswordOptions().copy(length = 24u)).length)

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

    @Test
    fun thePasswordChangesThroughTheBindings() {
        val folder = copyOfTheFrozenVault()
        val device = Device.open(folder.path, AndroidKeystore)
        val new = "a new password for this phone"
        try {
            fails<MobileException.Locked> { device.changePassword(password, new) }
            device.unlock(password)
            fails<MobileException.InvalidCredentials> { device.changePassword("not the password", new) }
            fails<MobileException.PasswordTooShort> { device.changePassword(password, "eleven char") }
            device.changePassword(password, new)
            device.lock()
            fails<MobileException.InvalidCredentials> { device.unlock(password) }
            device.unlock(new)
            assertEquals(DeviceState.UNLOCKED, device.state())
        } finally {
            device.close()
            folder.deleteRecursively()
        }
    }

    private inline fun <reified E : KeystoreFailure> keystoreFails(call: () -> Unit) {
        try {
            call()
        } catch (error: KeystoreFailure) {
            assertTrue("expected ${E::class.simpleName}, got $error", error is E)
            return
        }
        fail("expected ${E::class.simpleName}, but the call succeeded")
    }

    @Test
    fun theAndroidKeystoreSealsAKeyAndOpensOnlyWhatItSealed() {
        val key = "a key that identifies no device".toByteArray()
        val before = AndroidKeystore.count()
        val sealed = AndroidKeystore.seal(key)
        assertEquals(before + 1, AndroidKeystore.count())
        assertTrue(sealed.toList().windowed(key.size).none { it == key.toList() })
        assertTrue(AndroidKeystore.unseal(sealed).contentEquals(key))

        val altered = sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        keystoreFails<KeystoreFailure.Lost> { AndroidKeystore.unseal(altered) }
        val renamed = sealed.copyOf().also { it[1] = (it[1] + 1).toByte() }
        keystoreFails<KeystoreFailure.Lost> { AndroidKeystore.unseal(renamed) }
        keystoreFails<KeystoreFailure.Lost> { AndroidKeystore.unseal(byteArrayOf(1, 2, 3)) }

        AndroidKeystore.forgetEverything()
        keystoreFails<KeystoreFailure.Lost> { AndroidKeystore.unseal(sealed) }
    }

    @Test
    fun aNetworkKeyAnEarlierBuildKeptUnsealedIsSealedByTheAndroidKeystore() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val folder = copyOfTheFrozenVault()
        val peers = File(folder, "peers.sqlite3")
        instrumentation.context.assets.open("peers-1.sqlite3").use { input ->
            peers.outputStream().use { output -> input.copyTo(output) }
        }
        val before = peers.readBytes()
        try {
            AndroidKeystore.forgetEverything()
            // Opening the device seals the key it found unsealed; that the
            // key is then gone from the file is checked in the shared code
            // (crates/vault-peer, the frozen peer stores).
            Device.open(folder.path, AndroidKeystore).close()
            assertEquals(1, AndroidKeystore.count())
            assertTrue(!before.contentEquals(peers.readBytes()))
            // Opened again, the sealed key is opened, not sealed again.
            Device.open(folder.path, AndroidKeystore).close()
            assertEquals(1, AndroidKeystore.count())
        } finally {
            AndroidKeystore.forgetEverything()
            folder.deleteRecursively()
        }
    }
}
