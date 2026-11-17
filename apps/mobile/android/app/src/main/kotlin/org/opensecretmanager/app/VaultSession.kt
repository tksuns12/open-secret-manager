package org.opensecretmanager.app

import android.content.Context
import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.completeWith
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
import org.opensecretmanager.app.autofill.EarlierAppLogins
import org.opensecretmanager.vault.Asks
import org.opensecretmanager.vault.CardFill
import org.opensecretmanager.vault.DeletedEntry
import org.opensecretmanager.vault.AndroidKeystore
import org.opensecretmanager.vault.Device
import org.opensecretmanager.vault.DeviceState
import org.opensecretmanager.vault.Filled
import org.opensecretmanager.vault.HistoryEntry
import org.opensecretmanager.vault.ItemDetail
import org.opensecretmanager.vault.PasskeyCaller
import org.opensecretmanager.vault.PasskeyDetail
import org.opensecretmanager.vault.PasskeySignIn
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemSummary
import org.opensecretmanager.vault.MobileException
import org.opensecretmanager.vault.Offer
import org.opensecretmanager.vault.Requester
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
    /** The screen that changes this phone's password is open. */
    val passwordChange: Boolean = false,
    /**
     * How many times the vault was locked since the app started: what the
     * screens keep of it, a search for one, is let go of at each, even one
     * that came and went while the app was not on the screen.
     */
    val locks: Int = 0,
)

/** The versions of [detail], newest first. */
data class History(val detail: ItemDetail, val versions: List<HistoryEntry>)

/**
 * An item being made (`detail` null) or edited. After a save met a change
 * made elsewhere, [draft] holds what the owner typed put on top of the item
 * as it is now, and [changedElsewhere] names what the other device changed.
 * A new item comes with a password made for it, [generated], kept here so
 * that the screen made again, as when the phone turns, shows the same.
 */
data class Editor(
    val detail: ItemDetail?,
    val draft: ItemDraft? = null,
    val changedElsewhere: List<String> = emptyList(),
    val generated: String? = null,
)

/**
 * The device of the vault, as the screens use it. Every call to it runs off
 * the main thread, one at a time ([calls]), but for two kinds: going online
 * and offline and syncing, which wait on the network and take their own
 * turn ([online]), and what the system's list under another app's field
 * reads, which waits for neither ([offer]). The screens follow [state].
 */
class VaultSession(private val context: Context, private val folder: File) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val calls = Mutex()
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state
    @Volatile private var device: Device? = null
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
    /**
     * Whether the next locked vault shown asks for a fingerprint at once:
     * when the app starts or comes back, or a fill, save, or passkey screen
     * opens ([askAtOnceNext]); not after the owner's own Lock. The first
     * unlock screen shown takes it ([takeAskAtOnce]).
     */
    private val askAtOnce = AtomicBoolean(true)

    /**
     * Whether the vault is unlocked, as [refresh] last read it, and cleared
     * as it locks: what the system's list goes by ([offer]), which does not
     * wait for [calls].
     */
    @Volatile private var unlockedNow = false

    /**
     * How many locks asked for at once ([lock], [onScreenOff],
     * [onBackground]) have not run yet: while any has not, the system's list
     * names nothing, as if it had.
     */
    private val locksAsked = AtomicInteger()

    /**
     * Going online and offline, and syncs, one at a time and in the order
     * asked for ([online]). They wait on the network, for seconds at times,
     * so they are not among [calls]: an unlock or a fill does not wait for
     * them.
     */
    private val network = Channel<suspend () -> Unit>(Channel.UNLIMITED)

    /** The device was opened, or failed to be: [network]'s work waits for it. */
    private val opened = CompletableDeferred<Unit>()

    init {
        openDevice()
        scope.launch {
            opened.await()
            for (work in network) runCatching { work() }
        }
    }

    private fun openDevice() = run(null) {
        try {
            val opened = Device.open(folder.path, AndroidKeystore)
            device = opened
            // The logins an earlier build kept as chosen for each app, which
            // the device keeps from now on; tried again at the next open if
            // it fails.
            runCatching { EarlierAppLogins.moveInto(context, opened) }
            refresh()
        } finally {
            opened.complete(Unit)
        }
    }

    /**
     * Closes the device and opens its folder again: for tests, which put a
     * vault there first. In [network]'s turn, so that nothing goes online or
     * offline on a device as it closes.
     */
    internal fun reopenForTests(prepare: (File) -> Unit) = runBlocking {
        val reopened = CompletableDeferred<Unit>()
        network.send {
            reopened.completeWith(
                runCatching {
                    calls.withLock {
                        device?.let {
                            it.goOffline()
                            it.close()
                        }
                        device = null
                        unlockedNow = false
                        _state.value = UiState()
                        folder.deleteRecursively()
                        folder.mkdirs()
                        prepare(folder)
                    }
                    openDevice().join()
                },
            )
        }
        reopened.await()
    }

    /**
     * Holds [calls] until the function returned is called, or a minute has
     * passed, as a long call would: for tests.
     */
    internal fun holdCallsForTests(): () -> Unit {
        val release = CompletableDeferred<Unit>()
        run(null) { withTimeoutOrNull(60_000) { release.await() } }
        return { release.complete(Unit) }
    }

    /** As [holdCallsForTests], for [network]'s turn, as a slow going online would hold it. */
    internal fun holdNetworkForTests(): () -> Unit {
        val release = CompletableDeferred<Unit>()
        network.trySend { withTimeoutOrNull(60_000) { release.await() } }
        return { release.complete(Unit) }
    }

    /** Runs [work] off the main thread, showing [busy] meanwhile, and any failure. */
    private fun run(busy: String?, work: suspend () -> Unit): Job =
        scope.launch {
            calls.withLock {
                if (busy != null) _state.update { it.copy(busy = busy, notice = null) }
                try {
                    work()
                } catch (error: Exception) {
                    report(error)
                    runCatching { refresh() }
                } finally {
                    if (busy != null) _state.update { it.copy(busy = null) }
                }
            }
        }

    /**
     * Runs [work] with the device in [network]'s turn, after what was asked
     * for there before, showing [busy] meanwhile, and any failure; then reads
     * where the device stands, among [calls]. Nothing without a device.
     */
    private fun online(busy: String? = null, work: suspend (Device) -> Unit): Job {
        val finished = CompletableDeferred<Unit>()
        network.trySend {
            try {
                device?.let { device ->
                    if (busy != null) _state.update { it.copy(busy = busy, notice = null) }
                    try {
                        work(device)
                    } catch (error: Exception) {
                        report(error)
                    } finally {
                        if (busy != null) _state.update { it.copy(busy = null) }
                    }
                    calls.withLock { runCatching { refresh() } }
                }
            } finally {
                finished.complete(Unit)
            }
        }
        return finished
    }

    /** Shows what went wrong: an unreadable vault as a screen of its own, anything else once. */
    private fun report(error: Exception) {
        when (error) {
            is MobileException.UnreadableVault -> _state.update { it.copy(screen = Screen.UNREADABLE, unreadable = error.reason) }
            is MobileException -> _state.update { it.copy(notice = describe(error)) }
            else -> _state.update { it.copy(notice = "Something went wrong on this phone · ${error.message}") }
        }
    }

    /** Reads where the device stands, and what an unlocked vault holds. */
    private fun refresh() {
        lockIfDue()
        val device = device ?: return
        val screen = when (device.state()) {
            DeviceState.NO_VAULT -> Screen.NO_VAULT
            DeviceState.JOINING -> Screen.JOINING
            DeviceState.LOCKED -> Screen.LOCKED
            DeviceState.UNLOCKED -> Screen.UNLOCKED
            DeviceState.REMOVED -> Screen.REMOVED
        }
        unlockedNow = screen == Screen.UNLOCKED
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
                passwordChange = current.passwordChange && screen == Screen.UNLOCKED,
                rowsChanged = screen == Screen.UNLOCKED && device.rowsChanged(),
            )
        }
    }

    /** The owner has seen that records were taken out of the vault's file. */
    fun confirmRowsChanged() = run(null) {
        device?.confirmRowsChanged()
        refresh()
    }

    /**
     * Unlocks with [password]; then, on the main thread, [onUnlocked]. It
     * takes part again if it had stopped, in [network]'s turn.
     */
    fun unlock(password: String, onUnlocked: (() -> Unit)? = null) = run("Unlocking…") {
        device?.unlock(password)
        refresh()
        online { runCatching { it.goOnline() } }
        if (onUnlocked != null) withContext(Dispatchers.Main) { onUnlocked() }
    }

    /** The owner's own Lock, which asks for no fingerprint until the app leaves the screen. */
    fun lock(): Job {
        askAtOnce.set(false)
        locksAsked.incrementAndGet()
        lockLater?.cancel()
        return run(null) {
            try {
                lockAt = null
                device?.let(::lockVault)
                refresh()
            } finally {
                locksAsked.decrementAndGet()
            }
        }
    }

    /** A fill, save, or passkey screen opened: its unlock asks for a fingerprint at once. */
    fun askAtOnceNext() = askAtOnce.set(true)

    /**
     * Whether the unlock screen now shown asks for a fingerprint at once;
     * the one shown after it does not, unless the app left the screen or
     * another request opened meanwhile.
     */
    fun takeAskAtOnce(): Boolean = askAtOnce.getAndSet(false)

    /** Locks the vault, and lets go of what the screens held of it. Under [calls]. */
    private fun lockVault(device: Device) {
        device.lock()
        unlockedNow = false
        _state.update { it.copy(detail = null, editor = null, history = null, deleted = null, passwordChange = false, locks = it.locks + 1) }
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
        if (!lockDue()) return
        lockAt = null
        device?.let(::lockIfUnlocked)
    }

    /** Whether the time the vault stays unlocked for after the app left has run out. */
    private fun lockDue(): Boolean = lockAt?.let { SystemClock.elapsedRealtime() >= it } == true

    /**
     * Shows the vault locked at once if that time has run out, ahead of the
     * lock itself, which waits for its turn among the [calls]: the app's
     * screen, coming back, then shows nothing of the vault meanwhile. On the
     * main thread.
     */
    private fun showLockedIfDue() {
        if (!lockDue()) return
        _state.update {
            it.copy(
                screen = Screen.LOCKED, items = emptyList(), detail = null, editor = null, history = null,
                deleted = null, passwordChange = false, rowsChanged = false,
            )
        }
    }

    // A join reaches other devices, in [network]'s turn: going offline there
    // can then see a join under way, and leave it alone.

    fun joinStart(invitation: String) = online("Reaching the inviting device…") { device ->
        val code = device.joinStart(invitation.trim())
        _state.update { it.copy(joinCode = code) }
    }

    fun joinFinish(password: String) = online("Waiting for your other devices to add this phone…") { device ->
        device.joinFinish(password)
        _state.update { it.copy(joinCode = null, notice = "Joined · the vault arrives as it syncs") }
    }

    fun cancelJoin() = online { device ->
        device.cancelJoin()
        _state.update { it.copy(joinCode = null) }
    }

    fun syncNow(): Job = online("Syncing…") { it.syncNow() }

    fun open(id: String) = run(null) {
        val detail = device!!.item(id)
        _state.update { it.copy(detail = detail) }
    }

    fun close() {
        _state.update { it.copy(detail = null) }
    }

    fun startNew() {
        _state.update { it.copy(editor = Editor(null, generated = runCatching { generatePassword() }.getOrNull())) }
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

    /** Removes [passkey] of the login [detail] shows, on every device, and shows the login as it is then. */
    fun removePasskey(detail: ItemDetail, passkey: PasskeyDetail) = run(null) {
        val device = device!!
        device.removePasskey(detail.id, detail.revision, passkey.credentialId)
        _state.update { it.copy(detail = device.item(detail.id), notice = "Passkey removed") }
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

    fun openPasswordChange() {
        _state.update { it.copy(passwordChange = true) }
    }

    fun closePasswordChange() {
        _state.update { it.copy(passwordChange = false) }
    }

    /**
     * Makes [new] this phone's password from now on, given [current]. The
     * password kept for unlocking with a fingerprint is the old one, so that
     * is turned off, to be turned on again at an unlock. A wrong current
     * password changes nothing, and the screen stays open.
     */
    fun changePassword(current: String, new: String) = run("Changing the password…") {
        try {
            device!!.changePassword(current, new)
        } catch (error: MobileException.InvalidCredentials) {
            _state.update { it.copy(notice = "That is not this phone's current password · nothing was changed") }
            return@run
        }
        val biometric = BiometricUnlock(context)
        val hadFingerprint = biometric.enabled
        biometric.disable()
        _state.update {
            it.copy(
                passwordChange = false,
                notice = if (hadFingerprint) "Password changed · turn on the fingerprint again at the next unlock" else "Password changed",
            )
        }
    }

    /** Brings back a deleted item as it was before it was deleted. */
    fun restoreDeleted(entry: DeletedEntry) = run("Restoring…") {
        val device = device!!
        device.restore(entry.id, entry.last, entry.heads)
        val now = device.item(entry.id)
        _state.update { it.copy(deleted = null, detail = now, notice = "${entry.title} restored") }
        refresh()
    }

    /** A new password from the shared generator, as the owner chose ([Generator]). */
    fun generatePassword(): String = org.opensecretmanager.vault.generatePassword(Generator.options(context))

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

    /**
     * What the vault offers [requester] for a form that [asks]: for a page,
     * its origin's logins; for an app, those chosen for it, and apart, those
     * of the sites its links were verified for. Each by title. Then, on the
     * main thread, [done].
     */
    fun offering(requester: Requester, asks: Asks, done: (Offer) -> Unit) = run(null) {
        val offer = device!!.offer(requester, asks).let { offer ->
            offer.copy(logins = offer.logins.byTitle(), suggested = offer.suggested.byTitle())
        }
        withContext(Dispatchers.Main) { done(offer) }
    }

    /**
     * Every login a form that [asks] could be filled with, by title, for the
     * owner to choose one for an app; then, on the main thread, [done].
     */
    fun loginsToChoose(asks: Asks, done: (List<ItemSummary>) -> Unit) = run(null) {
        val logins = device!!.loginsToChoose(asks).byTitle()
        withContext(Dispatchers.Main) { done(logins) }
    }

    /**
     * What fills a form that [asks] from the login [id], for [requester]:
     * only a login the vault offers it, unless the owner [chosenNow] chose
     * it on the fill screen, for an app, which the vault then remembers for
     * it. Then, on the main thread, [done].
     */
    fun fill(requester: Requester, id: String, asks: Asks, chosenNow: Boolean, done: (Filled) -> Unit) = run(null) {
        val device = device!!
        val filled = if (chosenNow) device.fillChosen(requester, id, asks) else device.fill(requester, id, asks)
        withContext(Dispatchers.Main) { done(filled) }
    }

    /**
     * For the system's list under another app's field, while the vault is
     * unlocked: the logins a fill would offer [requester] for a form that
     * [asks], by title, which fill at once: for a page, its origin's; for an
     * app, those the owner chose for it. Null while the vault is locked, as
     * [offer] tells. Nothing is shown meanwhile. Then, on the main thread,
     * [done].
     */
    fun offered(requester: Requester, asks: Asks, done: (List<ItemSummary>?) -> Unit) =
        offer({ device -> device.offer(requester, asks).logins.byTitle() }, done)

    /**
     * For the system's list under a card form's field, while the vault is
     * unlocked: every card, which any app or page may be offered. Null while
     * the vault is locked, as [offer] tells. Then, on the main thread, [done].
     */
    fun offeredCards(done: (List<ItemSummary>?) -> Unit) =
        offer({ device -> device.offerCards().byTitle() }, done)

    /**
     * What [read] finds for a list the system shows, while the vault is
     * unlocked. The system waits only some 5 seconds for an answer, and one
     * that comes later is lost, with the offer to save that the autofill
     * service sends with it. So this waits for neither [calls] nor
     * [network], which going online or a sync can hold for longer: the read
     * runs beside them, as the device's own locks allow. Null at once while
     * the vault is locked, a lock was asked for, or the time it stays
     * unlocked for has run out (which then locks it). Null as well if the
     * read fails or takes longer than [OFFER_MILLIS]. Then, on the main
     * thread, [done].
     */
    private fun <T> offer(read: (Device) -> T, done: (T?) -> Unit) {
        val device = device
        val due = lockDue()
        if (due) run(null) { lockIfDue(); refresh() }
        if (device == null || !unlockedNow || locksAsked.get() > 0 || due) {
            scope.launch(Dispatchers.Main.immediate) { done(null) }
            return
        }
        // Not a child of the timeout, which would wait for it to end: a call
        // into the device cannot be stopped part-way.
        val reading = scope.async {
            runCatching { if (device.state() == DeviceState.UNLOCKED) read(device) else null }.getOrNull()
        }
        scope.launch {
            val found = withTimeoutOrNull(OFFER_MILLIS) { reading.await() }
            withContext(Dispatchers.Main) { done(found) }
        }
    }

    /** The fields of the card the owner chose; then, on the main thread, [done]. */
    fun fillCard(id: String, done: (CardFill) -> Unit) = run(null) {
        val card = device!!.fillCard(id)
        withContext(Dispatchers.Main) { done(card) }
    }

    /**
     * As [fillCard], for a card the owner chose in the system's list while
     * the vault was unlocked: [done] with null if it is locked by now, for
     * the fill screen to take over. Nothing is shown meanwhile.
     */
    fun fillCardChosen(id: String, done: (CardFill?) -> Unit) {
        scope.launch {
            val filled = calls.withLock {
                runCatching {
                    lockIfDue()
                    device?.takeIf { it.state() == DeviceState.UNLOCKED }?.fillCard(id)
                }.getOrNull()
            }
            withContext(Dispatchers.Main) { done(filled) }
        }
    }

    /**
     * For the system's list when an app or a page asks for a passkey, while
     * the vault is unlocked: for each of the [asked] requests (its JSON, and
     * who asks), the passkeys the vault holds for its site, or null for a
     * request that is not answered here. Null for all while the vault is
     * locked, as [offer] tells. Then, on the main thread, [done].
     */
    fun offeredPasskeys(asked: List<Pair<String, PasskeyCaller>>, done: (List<PasskeySignIn?>?) -> Unit) =
        offer({ device ->
            asked.map { (options, caller) -> runCatching { device.passkeySignIn(options, caller) }.getOrNull() }
        }, done)

    /**
     * Runs [work] with the device, as every call is, for a passkey's
     * request; then, on the main thread, [done] with what it gave or how it
     * failed, which the passkey screen tells the app that asked.
     */
    fun <T> forPasskey(work: (Device) -> T, done: (Result<T>) -> Unit) {
        scope.launch {
            val result = calls.withLock {
                runCatching {
                    lockIfDue()
                    work(device ?: throw MobileException.NoVault())
                }.also { runCatching { refresh() } }
            }
            withContext(Dispatchers.Main) { done(result) }
        }
    }

    /**
     * As [fill], for a login the owner chose in the system's list while the
     * vault was unlocked, which the vault offered [requester]: [done] with
     * what fills the form, or with null if the vault is locked by now or the
     * login does not fill this form, for the fill screen to take over.
     * Nothing is shown meanwhile.
     */
    fun fillListed(requester: Requester, id: String, asks: Asks, done: (Filled?) -> Unit) {
        scope.launch {
            val filled = calls.withLock {
                runCatching {
                    lockIfDue()
                    device?.takeIf { it.state() == DeviceState.UNLOCKED }?.fill(requester, id, asks)
                }.getOrNull()
            }
            withContext(Dispatchers.Main) { done(filled) }
        }
    }

    /**
     * For saving what a form of [requester] submitted: the logins it could
     * go into, which the vault tells (those the form could be filled with,
     * under its [username]), by title. Then, on the main thread, [done].
     */
    fun saveCandidates(
        requester: Requester,
        username: String,
        password: String,
        done: (List<SaveCandidate>) -> Unit,
    ) = run(null) {
        val candidates = device!!.saveCandidatesFor(requester, username, password).sortedBy { it.title.lowercase() }
        withContext(Dispatchers.Main) { done(candidates) }
    }

    /**
     * Saves what a form of [requester] submitted as a new login: for a
     * page's origin, or for the app, which the vault remembers it for. Then,
     * on the main thread, [done] with its ID.
     */
    fun saveNew(requester: Requester, title: String, username: String, password: String, done: (String) -> Unit) = run("Saving…") {
        val id = device!!.saveNew(requester, title, username, password)
        withContext(Dispatchers.Main) { done(id) }
    }

    /**
     * Puts the password a form of [requester] submitted under [username]
     * into the login [candidate], as it was read; then, on the main thread,
     * [done] with whether it did. A login that changed since is left alone.
     */
    fun updateSaved(requester: Requester, candidate: SaveCandidate, username: String, password: String, done: (Boolean) -> Unit) = run("Saving…") {
        val saved = try {
            device!!.updateSaved(requester, candidate.id, candidate.revision, username, password)
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

    /** Shows `notice`, as the session's own notices show. */
    fun tell(notice: String) {
        _state.update { it.copy(notice = notice) }
    }

    /**
     * The app came to the front, a fill, save, or passkey screen as well:
     * take part again, in [network]'s turn, and keep the list current.
     */
    fun onForeground() {
        inFront = true
        showLockedIfDue()
        lockLater?.cancel()
        lockLater = null
        run(null) {
            lockIfDue()
            lockAt = null
            refresh()
        }
        online { device ->
            val state = device.state()
            if (state == DeviceState.LOCKED || state == DeviceState.UNLOCKED) runCatching { device.goOnline() }
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
     * The app left the screen: stop taking part, in [network]'s turn, and
     * lock the vault, at once or after the time the owner chose
     * ([StayUnlocked]), so that another app's next field is filled from the
     * system's list without unlocking again. A join under way is left alone,
     * since the owner compares the codes on the other device's screen.
     */
    fun onBackground() {
        inFront = false
        askAtOnce.set(true)
        foreground?.cancel()
        foreground = null
        val stay = StayUnlocked.millis(context)
        val atOnce = stay <= 0
        if (atOnce) locksAsked.incrementAndGet()
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
            try {
                val device = device ?: return@run
                if (device.state() == DeviceState.JOINING) return@run
                if (stay > 0 && device.state() == DeviceState.UNLOCKED) {
                    lockAt = SystemClock.elapsedRealtime() + stay
                } else {
                    lockAt = null
                    lockVault(device)
                }
                refresh()
            } finally {
                if (atOnce) locksAsked.decrementAndGet()
            }
        }
        online { device ->
            if (device.state() != DeviceState.JOINING) device.goOffline()
        }
    }

    /**
     * The phone's screen turned off. With a time chosen and a lock screen on
     * the phone ([StayUnlocked.throughScreenOff]), the vault stays unlocked
     * for that time, from when the app left the screen ([onBackground],
     * which follows if it was in front); otherwise it locks at once.
     */
    fun onScreenOff() {
        askAtOnce.set(true)
        if (StayUnlocked.throughScreenOff(context)) return
        locksAsked.incrementAndGet()
        lockLater?.cancel()
        lockLater = null
        run(null) {
            try {
                lockAt = null
                device?.let(::lockIfUnlocked)
                refresh()
            } finally {
                locksAsked.decrementAndGet()
            }
        }
    }

    /**
     * The phone's screen turned on. The timer that locks the vault once the
     * time chosen has run out ([onBackground]) does not run while the phone
     * sleeps, which it may do for most of the time the screen is off: the
     * vault locks now if that time has run out, before the phone's own lock
     * screen can be passed.
     */
    fun onScreenOn() {
        if (lockAt == null) return
        showLockedIfDue()
        run(null) { refresh() }
    }

    /**
     * A sync while the app is closed: takes part just long enough to sync,
     * and never unlocks; what arrives waits for the next unlock. Nothing
     * while the app is on the screen, which syncs anyway, or without a
     * vault this phone belongs to. In [network]'s turn.
     */
    fun syncInBackground(): Job = online { device ->
        if (inFront) return@online
        val state = device.state()
        if (state != DeviceState.LOCKED && state != DeviceState.UNLOCKED) return@online
        runCatching { device.syncInBackground() }
    }

    private companion object {
        /** How long the system's list waits for [offer]: the system gives an answer some 5 seconds. */
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
        is MobileException.NotACard -> "Only a card can be filled into a card form"
        is MobileException.NotChosen -> "That login was not chosen for this app · choose it on this screen"
        is MobileException.NotForThisForm -> "That login is not one this form could be saved into"
        is MobileException.InvalidRequester -> "Open Secret Manager cannot tell who asks, so it fills nothing"
        is MobileException.PasskeyRefused -> "The site's request cannot be answered here · ${error.reason}"
        is MobileException.PasskeyExists -> "Your vault already has a passkey for this account on this site"
        is MobileException.NotVerified -> "The site asks to verify it is you, which did not happen"
        is MobileException.InvalidItem -> error.reason
        is MobileException.ChangedElsewhere -> "This item changed since you opened it · open it again"
        is MobileException.InConflict -> "Two devices changed this item at once · choose a version on your computer"
        is MobileException.NotEditableHere -> "Identities are edited on your computer"
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

/** As the fill and save screens list logins and cards: by title. */
private fun List<ItemSummary>.byTitle() = sortedBy { it.title.lowercase() }
