package org.opensecretmanager.app

import android.content.Context
import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
import kotlinx.coroutines.withTimeoutOrNull
import org.opensecretmanager.vault.DeletedEntry
import org.opensecretmanager.vault.AndroidKeystore
import org.opensecretmanager.vault.Device
import org.opensecretmanager.vault.DeviceState
import org.opensecretmanager.vault.FillCredentials
import org.opensecretmanager.vault.HistoryEntry
import org.opensecretmanager.vault.ItemDetail
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind
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
    /** An item's versions, while its history is open. */
    val history: History? = null,
    /** The items deleted, while that list is open. */
    val deleted: List<DeletedEntry>? = null,
    /** The last unlock found records taken out of the vault's file. */
    val rowsChanged: Boolean = false,
)

/** The versions of [detail], newest first. */
data class History(val detail: ItemDetail, val versions: List<HistoryEntry>)

/** A new item when [detail] is null, otherwise that item as it was read. */
/**
 * An item being made (`detail` null) or edited. After a save met a change
 * made elsewhere, [draft] holds what the owner typed put on top of the item
 * as it is now, and [changedElsewhere] names what the other device changed.
 */
data class Editor(val detail: ItemDetail?, val draft: ItemDraft? = null, val changedElsewhere: List<String> = emptyList())

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
    /** The app is on the screen, where it takes part and syncs anyway. */
    @Volatile private var inFront = false
    /**
     * While the vault stays unlocked after the app left the screen: when it
     * locks, by [SystemClock.elapsedRealtime]. Written under [calls].
     */
    @Volatile private var lockAt: Long? = null
    /** Locks the vault once the time it stays unlocked for has run out. */
    private var lockLater: Job? = null

    init {
        openDevice()
    }

    private fun openDevice() = run(null) {
        device = Device.open(folder.path, AndroidKeystore)
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
                history = current.history.takeIf { screen == Screen.UNLOCKED },
                deleted = current.deleted.takeIf { screen == Screen.UNLOCKED },
                rowsChanged = screen == Screen.UNLOCKED && device.rowsChanged(),
            )
        }
    }

    /** The owner has seen that records were taken out of the vault's file. */
    fun confirmRowsChanged() = run(null) {
        device?.confirmRowsChanged()
        refresh()
    }

    /** Unlocks with [password]; then, on the main thread, [onUnlocked]. */
    fun unlock(password: String, onUnlocked: (() -> Unit)? = null) = run("Unlocking…") {
        device?.unlock(password)
        device?.let { runCatching { it.goOnline() } }
        refresh()
        if (onUnlocked != null) withContext(Dispatchers.Main) { onUnlocked() }
    }

    fun lock(): Job {
        lockLater?.cancel()
        return run(null) {
            lockAt = null
            device?.let(::lockVault)
            refresh()
        }
    }

    /** Locks the vault, and lets go of what the screens held of it. Under [calls]. */
    private fun lockVault(device: Device) {
        device.lock()
        _state.update { it.copy(detail = null, editor = null, history = null, deleted = null) }
    }

    /** Locks an unlocked vault: not one being joined. Under [calls]. */
    private fun lockIfUnlocked(device: Device) {
        if (device.state() == DeviceState.UNLOCKED) lockVault(device)
    }

    /**
     * Locks the vault if the time it stays unlocked for after the app left
     * has run out: [lockLater] may not have run, as its clock stops while
     * the phone sleeps. Under [calls].
     */
    private fun lockIfDue() {
        val at = lockAt ?: return
        if (SystemClock.elapsedRealtime() < at) return
        lockAt = null
        device?.let(::lockIfUnlocked)
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
            // What was read is out of date. What the owner typed is kept, put
            // on top of the item as it is now, for the owner to look at and
            // save again; failing that, the item is shown as it is now. The
            // item is read before the edit is moved, so a change between the
            // two is refused again rather than undone.
            val rebased = editing?.let { read ->
                runCatching {
                    val current = device.item(read.id)
                    val edit = device.rebaseEdit(read.id, read.revision, draft)
                    Editor(current, edit.draft, edit.changedElsewhere)
                }.getOrNull()
            }
            if (rebased != null) {
                _state.update { it.copy(editor = rebased, notice = "Changed on another device meanwhile · your changes are kept") }
            } else {
                val current = editing?.let { runCatching { device.item(it.id) }.getOrNull() }
                _state.update { it.copy(editor = null, detail = current, notice = describe(error)) }
            }
        }
        refresh()
    }

    /** Deletes the item as it was read, on every device. */
    fun delete(detail: ItemDetail) = run(null) {
        device!!.deleteItem(detail.id, detail.revision)
        _state.update { it.copy(detail = null, notice = "Item deleted") }
        refresh()
    }

    fun openHistory(detail: ItemDetail) = run(null) {
        val versions = device!!.history(detail.id)
        _state.update { it.copy(history = History(detail, versions)) }
    }

    fun closeHistory() {
        _state.update { it.copy(history = null) }
    }

    /**
     * Brings back what [version] held, as the newest version, following the
     * current versions the history showed. If the item changed since, the
     * history is read again.
     */
    fun restoreVersion(version: HistoryEntry) = run("Restoring…") {
        val device = device!!
        val history = _state.value.history ?: return@run
        val heads = history.versions.filter { it.current }.map { it.revision }
        try {
            device.restore(history.detail.id, version.revision, heads)
            val now = device.item(history.detail.id)
            _state.update { it.copy(history = null, detail = now, notice = "Version restored") }
        } catch (error: MobileException.ChangedElsewhere) {
            val versions = device.history(history.detail.id)
            _state.update { it.copy(history = history.copy(versions = versions), notice = describe(error)) }
        }
        refresh()
    }

    fun openDeleted() = run(null) {
        val deleted = device!!.deletedItems()
        _state.update { it.copy(deleted = deleted) }
    }

    fun closeDeleted() {
        _state.update { it.copy(deleted = null) }
    }

    /** Brings back a deleted item as it was before it was deleted. */
    fun restoreDeleted(entry: DeletedEntry) = run("Restoring…") {
        val device = device!!
        device.restore(entry.id, entry.last, entry.heads)
        val now = device.item(entry.id)
        _state.update { it.copy(deleted = null, detail = now, notice = "${entry.title} restored") }
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

    /** Copies the value of one of the item's other fields, as a secret. */
    fun copyField(id: String, name: String) = run(null) {
        SecretClipboard.copy(context, name, device!!.field(id, name), secret = true)
        _state.update { it.copy(notice = "$name copied · cleared in 30 seconds") }
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
        val (credentials, oneTimeCode) = filling(device!!, id, origin, login, code)
        withContext(Dispatchers.Main) { done(credentials, oneTimeCode) }
    }

    private fun filling(device: Device, id: String, origin: String?, login: Boolean, code: Boolean): Pair<FillCredentials?, String?> {
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
        return credentials to oneTimeCode
    }

    /**
     * For the system's list under another app's field, while the vault is
     * unlocked: the logins a fill would offer, which are those saved for
     * [origin]'s pages or, without an origin, those in [chosen] (the logins
     * the owner chose for an app), and of them only those with a one-time
     * code if [codeOnly]. Null while the vault is locked, or if it does not
     * answer within a moment, since the system waits only so long for an
     * answer. Nothing is shown meanwhile. Then, on the main thread, [done].
     */
    fun offered(origin: String?, chosen: Set<String>, codeOnly: Boolean, done: (List<ItemSummary>?) -> Unit) {
        scope.launch {
            val found = withTimeoutOrNull(OFFER_MILLIS) {
                calls.withLock {
                    runCatching {
                        lockIfDue()
                        val device = device?.takeIf { it.state() == DeviceState.UNLOCKED } ?: return@runCatching null
                        val logins = if (origin != null) {
                            device.loginsForWeb(origin)
                        } else {
                            device.items().filter { it.kind == ItemKind.LOGIN && it.id in chosen }
                        }.sortedBy { it.title.lowercase() }
                        if (codeOnly) device.withOneTimeCodes(logins.map { it.id }) else logins
                    }.getOrNull()
                }
            }
            withContext(Dispatchers.Main) { done(found) }
        }
    }

    /**
     * As [fill], for a login the owner chose in the system's list while the
     * vault was unlocked: [done] with what fills the form, or with null if
     * the vault is locked by now or the login does not fill this form, for
     * the fill screen to take over. Nothing is shown meanwhile.
     */
    fun fillChosen(id: String, origin: String?, login: Boolean, code: Boolean, done: (Pair<FillCredentials?, String?>?) -> Unit) {
        scope.launch {
            val filled = calls.withLock {
                runCatching {
                    lockIfDue()
                    val device = device?.takeIf { it.state() == DeviceState.UNLOCKED } ?: return@runCatching null
                    filling(device, id, origin, login, code)
                }.getOrNull()
            }
            withContext(Dispatchers.Main) { done(filled) }
        }
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
        inFront = true
        lockLater?.cancel()
        lockLater = null
        run(null) {
            lockIfDue()
            lockAt = null
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
     * The app left the screen: stop taking part, and lock the vault, at once
     * or after the time the owner chose ([StayUnlocked]), so that another
     * app's next field is filled from the system's list without unlocking
     * again. A join under way is left alone, since the owner compares the
     * codes on the other device's screen.
     */
    fun onBackground() {
        inFront = false
        foreground?.cancel()
        foreground = null
        val stay = StayUnlocked.millis(context)
        lockLater?.cancel()
        lockLater = if (stay > 0) {
            scope.launch {
                delay(stay)
                run(null) {
                    if (inFront) return@run
                    lockAt = null
                    device?.let(::lockIfUnlocked)
                    refresh()
                }
            }
        } else {
            null
        }
        run(null) {
            val device = device ?: return@run
            if (device.state() == DeviceState.JOINING) return@run
            if (stay > 0 && device.state() == DeviceState.UNLOCKED) {
                lockAt = SystemClock.elapsedRealtime() + stay
            } else {
                lockAt = null
                lockVault(device)
            }
            device.goOffline()
            refresh()
        }
    }

    /** The phone's screen turned off: lock at once, whatever the time the vault would stay unlocked for. */
    fun onScreenOff() {
        lockLater?.cancel()
        lockLater = null
        run(null) {
            lockAt = null
            device?.let(::lockIfUnlocked)
            refresh()
        }
    }

    /**
     * A sync while the app is closed: takes part just long enough to sync,
     * and never unlocks; what arrives waits for the next unlock. Nothing
     * while the app is on the screen, which syncs anyway, or without a
     * vault this phone belongs to.
     */
    fun syncInBackground() = run(null) {
        val device = device ?: return@run
        if (inFront) return@run
        val state = device.state()
        if (state != DeviceState.LOCKED && state != DeviceState.UNLOCKED) return@run
        runCatching { device.syncInBackground() }
        refresh()
    }

    private companion object {
        /** How long the system's list waits for [offered]: the system gives an answer some 5 seconds. */
        const val OFFER_MILLIS = 3_000L
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
        is MobileException.NoSuchField -> "This item no longer has that field · open it again"
        is MobileException.InvalidOrigin -> "Logins are filled only into https pages"
        is MobileException.NotForThisPage -> "That login is not saved for this page"
        is MobileException.NotALogin -> "Only a login can be filled"
        is MobileException.InvalidItem -> error.reason
        is MobileException.ChangedElsewhere -> "This item changed since you opened it · open it again"
        is MobileException.InConflict -> "Two devices changed this item at once · choose a version on your computer"
        is MobileException.NotEditableHere -> "Identities and cards are edited on your computer"
        is MobileException.Network -> "Could not reach your other devices · ${error.reason}"
        is MobileException.Storage -> "Something went wrong on this phone · ${error.reason}"
        is MobileException.KeystoreUnavailable -> "This phone's keystore did not answer · try again"
        is MobileException.KeystoreLost -> "This phone no longer holds its network key · remove it on your computer and join again"
    }
}

/**
 * The session's state as a screen reads it, collected on the main thread,
 * where screens are drawn: the session changes it from its own threads.
 * Collected in the screen's own context instead, a test's screen was once
 * redrawn on the thread that changed it, which Android refuses, and the
 * app then crashed when the screen closed.
 */
@Composable
fun VaultSession.screenState(): State<UiState> =
    state.collectAsStateWithLifecycle(context = Dispatchers.Main.immediate)
