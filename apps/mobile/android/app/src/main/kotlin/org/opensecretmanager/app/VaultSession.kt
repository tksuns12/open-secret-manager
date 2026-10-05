package org.opensecretmanager.app

import android.content.Context
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.opensecretmanager.vault.Device
import org.opensecretmanager.vault.DeviceState
import org.opensecretmanager.vault.FillCredentials
import org.opensecretmanager.vault.ItemDetail
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemSummary
import org.opensecretmanager.vault.MobileException
import org.opensecretmanager.vault.SaveCandidate
import org.opensecretmanager.vault.SyncStatus

/** What the app shows. */
enum class Screen { OPENING, NO_VAULT, JOINING, LOCKED, UNLOCKED, REMOVED, UNREADABLE }

data class UiState(
    val screen: Screen = Screen.OPENING,
    val items: List<ItemSummary> = emptyList(),
    val detail: ItemDetail? = null,
    val sync: SyncStatus? = null,
    /** The code to compare with the inviting device's, while joining. */
    val joinCode: String? = null,
    /** What is under way, while something takes a while. */
    val busy: String? = null,
    /** The outcome of the last thing the owner did, to show once. */
    val notice: String? = null,
    val unreadable: String? = null,
    /** An item being written, while the editor is open. */
    val editor: Editor? = null,
)

/** A new item when [detail] is null, otherwise that item as it was read. */
data class Editor(val detail: ItemDetail?)

/**
 * The device of the vault, as the screens use it. Every call to it runs off
 * the main thread, one at a time; the screens follow [state].
 */
class VaultSession(private val context: Context, private val folder: File) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val calls = Mutex()
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state
    private var device: Device? = null
    private var foreground: Job? = null

    init {
        openDevice()
    }

    private fun openDevice() = run(null) {
        device = Device.open(folder.path)
        refresh()
    }

    /** Closes the device and opens its folder again: for tests, which put a vault there first. */
    internal fun reopenForTests(prepare: (File) -> Unit) = runBlocking {
        calls.withLock {
            device?.let {
                it.goOffline()
                it.close()
            }
            device = null
            _state.value = UiState()
            folder.deleteRecursively()
            folder.mkdirs()
            prepare(folder)
        }
        openDevice().join()
    }

    /** Runs [work] off the main thread, showing [busy] meanwhile, and any failure. */
    private fun run(busy: String?, work: suspend () -> Unit): Job =
        scope.launch {
            calls.withLock {
                if (busy != null) _state.update { it.copy(busy = busy, notice = null) }
                try {
                    work()
                } catch (error: MobileException) {
                    if (error is MobileException.UnreadableVault) {
                        _state.update { it.copy(screen = Screen.UNREADABLE, unreadable = error.reason) }
                    } else {
                        _state.update { it.copy(notice = describe(error)) }
                    }
                    runCatching { refresh() }
                } catch (error: Exception) {
                    _state.update { it.copy(notice = "Something went wrong on this phone · ${error.message}") }
                    runCatching { refresh() }
                } finally {
                    if (busy != null) _state.update { it.copy(busy = null) }
                }
            }
        }

    /** Reads where the device stands, and what an unlocked vault holds. */
    private fun refresh() {
        val device = device ?: return
        val screen = when (device.state()) {
            DeviceState.NO_VAULT -> Screen.NO_VAULT
            DeviceState.JOINING -> Screen.JOINING
            DeviceState.LOCKED -> Screen.LOCKED
            DeviceState.UNLOCKED -> Screen.UNLOCKED
            DeviceState.REMOVED -> Screen.REMOVED
        }
        val items = if (screen == Screen.UNLOCKED) device.items().sortedBy { it.title.lowercase() } else emptyList()
        _state.update { current ->
            current.copy(
                screen = screen,
                items = items,
                // A detail stays open only while its item does.
                detail = current.detail?.takeIf { detail -> screen == Screen.UNLOCKED && items.any { it.id == detail.id } },
                sync = device.syncStatus(),
                joinCode = current.joinCode.takeIf { screen == Screen.JOINING },
                editor = current.editor.takeIf { screen == Screen.UNLOCKED },
            )
        }
    }

    /** Unlocks with [password]; then, on the main thread, [onUnlocked]. */
    fun unlock(password: String, onUnlocked: (() -> Unit)? = null) = run("Unlocking…") {
        device?.unlock(password)
        device?.let { runCatching { it.goOnline() } }
        refresh()
        if (onUnlocked != null) withContext(Dispatchers.Main) { onUnlocked() }
    }

    fun lock() = run(null) {
        device?.lock()
        _state.update { it.copy(detail = null, editor = null) }
        refresh()
    }

    fun joinStart(invitation: String) = run("Reaching the inviting device…") {
        val code = device!!.joinStart(invitation.trim())
        _state.update { it.copy(joinCode = code) }
        refresh()
    }

    fun joinFinish(password: String) = run("Waiting for your other devices to add this phone…") {
        device!!.joinFinish(password)
        _state.update { it.copy(joinCode = null, notice = "Joined · the vault arrives as it syncs") }
        refresh()
    }

    fun cancelJoin() = run(null) {
        device?.cancelJoin()
        _state.update { it.copy(joinCode = null) }
        refresh()
    }

    fun syncNow() = run("Syncing…") {
        device?.syncNow()
        refresh()
    }

    fun open(id: String) = run(null) {
        val detail = device!!.item(id)
        _state.update { it.copy(detail = detail) }
    }

    fun close() {
        _state.update { it.copy(detail = null) }
    }

    fun startNew() {
        _state.update { it.copy(editor = Editor(null)) }
    }

    fun startEdit(detail: ItemDetail) {
        _state.update { it.copy(editor = Editor(detail)) }
    }

    fun closeEditor() {
        _state.update { it.copy(editor = null) }
    }

    /** Saves the editor's draft: a new item, or an edit of the item as it was read. */
    fun save(draft: ItemDraft) = run("Saving…") {
        val device = device!!
        val editing = _state.value.editor?.detail
        try {
            val id = if (editing == null) {
                device.createItem(draft)
            } else {
                device.updateItem(editing.id, editing.revision, draft)
                editing.id
            }
            val saved = device.item(id)
            _state.update {
                it.copy(editor = null, detail = saved, notice = if (editing == null) "Item created" else "Changes saved")
            }
        } catch (error: MobileException.ChangedElsewhere) {
            // What was read is out of date: show the item as it is now.
            val current = editing?.let { runCatching { device.item(it.id) }.getOrNull() }
            _state.update { it.copy(editor = null, detail = current, notice = describe(error)) }
        }
        refresh()
    }

    /** Deletes the item as it was read, on every device. */
    fun delete(detail: ItemDetail) = run(null) {
        device!!.deleteItem(detail.id, detail.revision)
        _state.update { it.copy(detail = null, notice = "Item deleted") }
        refresh()
    }

    /** A new password from the shared generator. */
    fun generatePassword(): String = org.opensecretmanager.vault.generatePassword(20u)

    fun copyUsername(detail: ItemDetail) {
        SecretClipboard.copy(context, "Username", detail.username, secret = false)
        _state.update { it.copy(notice = "Username copied") }
    }

    fun copyPassword(id: String) = run(null) {
        SecretClipboard.copy(context, "Password", device!!.password(id), secret = true)
        _state.update { it.copy(notice = "Password copied · cleared in 30 seconds") }
    }

    fun copyOneTimeCode(id: String) = run(null) {
        SecretClipboard.copy(context, "One-time code", device!!.oneTimeCode(id), secret = true)
        _state.update { it.copy(notice = "Code copied · cleared in 30 seconds") }
    }

    /** The logins saved for [origin]'s pages; then, on the main thread, [done]. */
    fun loginsForWeb(origin: String, done: (List<ItemSummary>) -> Unit) = run(null) {
        val logins = device!!.loginsForWeb(origin).sortedBy { it.title.lowercase() }
        withContext(Dispatchers.Main) { done(logins) }
    }

    /** Of [logins], those with a one-time code, in their order; then, on the main thread, [done]. */
    fun withOneTimeCodes(logins: List<ItemSummary>, done: (List<ItemSummary>) -> Unit) = run(null) {
        val found = device!!.withOneTimeCodes(logins.map { it.id })
        withContext(Dispatchers.Main) { done(found) }
    }

    /**
     * What fills a form from a login: its username and password if [login],
     * and its current one-time code if [code]. Into a page of [origin], which
     * the login must be saved for, or, without an origin, into an app the
     * owner chose the login for. A form that asks for the password too is
     * filled without a code when the login has none. Then, on the main
     * thread, [done].
     */
    fun fill(id: String, origin: String?, login: Boolean, code: Boolean, done: (FillCredentials?, String?) -> Unit) = run(null) {
        val device = device!!
        val credentials = when {
            !login -> null
            origin != null -> device.fillForWeb(id, origin)
            else -> device.fillForApp(id)
        }
        val oneTimeCode = if (!code) {
            null
        } else {
            try {
                if (origin != null) device.oneTimeCodeForWeb(id, origin) else device.oneTimeCode(id)
            } catch (error: MobileException.NoOneTimeCode) {
                if (login) null else throw error
            }
        }
        withContext(Dispatchers.Main) { done(credentials, oneTimeCode) }
    }

    /**
     * For saving what a form submitted: the logins it could go into, among
     * those saved for [origin]'s pages or, without an origin, those in
     * [chosen] (the logins the owner chose for an app). Then, on the main
     * thread, [done].
     */
    fun saveCandidates(
        origin: String?,
        chosen: Set<String>,
        username: String,
        password: String,
        done: (List<SaveCandidate>) -> Unit,
    ) = run(null) {
        val device = device!!
        val ids = if (origin != null) device.loginsForWeb(origin).map { it.id } else chosen.toList()
        val candidates = device.saveCandidates(ids, username, password).sortedBy { it.title.lowercase() }
        withContext(Dispatchers.Main) { done(candidates) }
    }

    /** Saves a new login from [draft]; then, on the main thread, [done] with its ID. */
    fun saveNew(draft: ItemDraft, done: (String) -> Unit) = run("Saving…") {
        val id = device!!.createItem(draft)
        withContext(Dispatchers.Main) { done(id) }
    }

    /**
     * Changes the password of the login [candidate] as it was read; then, on
     * the main thread, [done] with whether it did. A login that changed
     * since is left alone.
     */
    fun updatePassword(candidate: SaveCandidate, password: String, done: (Boolean) -> Unit) = run("Saving…") {
        val saved = try {
            device!!.updatePassword(candidate.id, candidate.revision, password)
            true
        } catch (error: MobileException.ChangedElsewhere) {
            _state.update { it.copy(notice = "That login changed since this screen read it · choose again") }
            false
        }
        withContext(Dispatchers.Main) { done(saved) }
    }

    fun notify(text: String) {
        _state.update { it.copy(notice = text) }
    }

    fun dismissNotice() {
        _state.update { it.copy(notice = null) }
    }

    /** The app came to the front: take part again, and keep the list current. */
    fun onForeground() {
        run(null) {
            device?.let { device ->
                if (device.state() == DeviceState.LOCKED || device.state() == DeviceState.UNLOCKED) {
                    runCatching { device.goOnline() }
                }
            }
            refresh()
        }
        foreground?.cancel()
        foreground = scope.launch {
            while (isActive) {
                delay(5_000)
                calls.withLock { runCatching { refresh() } }
            }
        }
    }

    /**
     * The app left the screen: lock the vault and stop taking part. A join
     * under way is left alone, since the owner compares the codes on the
     * other device's screen.
     */
    fun onBackground() {
        foreground?.cancel()
        foreground = null
        run(null) {
            val device = device ?: return@run
            if (device.state() == DeviceState.JOINING) return@run
            device.lock()
            device.goOffline()
            _state.update { it.copy(detail = null, editor = null) }
            refresh()
        }
    }

    private fun describe(error: MobileException): String = when (error) {
        is MobileException.Locked -> "The vault is locked"
        is MobileException.InvalidCredentials -> "That password was rejected"
        is MobileException.NotFound -> "That item is no longer in the vault"
        is MobileException.NoVault -> "This phone has no vault yet"
        is MobileException.VaultExists -> "This phone already has a vault"
        is MobileException.UnreadableVault -> "The vault on this phone cannot be opened"
        is MobileException.NotJoining -> "Start again with an invitation"
        is MobileException.PasswordTooShort -> "Use at least ${error.minimum} characters"
        is MobileException.NotConfirmed -> "The other device did not confirm · nothing was changed"
        is MobileException.EnrollmentTimeout -> "Your other devices did not add this phone in time · cancel on the computer and try again"
        is MobileException.Removed -> "This phone was removed from the vault"
        is MobileException.InvalidInvitation -> "That is not an invitation · copy it again from your computer"
        is MobileException.NoOneTimeCode -> "This item has no one-time code"
        is MobileException.InvalidOrigin -> "Logins are filled only into https pages"
        is MobileException.NotForThisPage -> "That login is not saved for this page"
        is MobileException.NotALogin -> "Only a login can be filled"
        is MobileException.InvalidItem -> error.reason
        is MobileException.ChangedElsewhere -> "This item changed since you opened it · open it again"
        is MobileException.InConflict -> "Two devices changed this item at once · choose a version on your computer"
        is MobileException.NotEditableHere -> "Identities and cards are edited on your computer"
        is MobileException.Network -> "Could not reach your other devices · ${error.reason}"
        is MobileException.Storage -> "Something went wrong on this phone · ${error.reason}"
    }
}
