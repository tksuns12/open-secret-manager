package org.opensecretmanager.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.LifecycleResumeEffect
import org.opensecretmanager.app.autofill.PendingSave
import org.opensecretmanager.app.autofill.SaveActivity
import org.opensecretmanager.vault.DeletedEntry
import org.opensecretmanager.vault.HistoryEntry
import org.opensecretmanager.vault.ItemDetail
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind
import org.opensecretmanager.vault.ItemSummary
import org.opensecretmanager.vault.SyncState
import org.opensecretmanager.vault.SyncStatus

class MainActivity : FragmentActivity() {
    private lateinit var biometric: BiometricUnlock

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Nothing of the vault in screenshots, screen recordings, or the
        // preview of recent apps. Only a debug build made for reviewing the
        // screens leaves this out (see app/build.gradle.kts).
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        val session = (application as VaultApp).session
        biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                VaultScreen(
                    session = session,
                    biometric = biometric,
                    onUnlockWithBiometric = prompts::unlock,
                    onRememberWithBiometric = prompts::keep,
                )
            }
        }
    }

}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(
    session: VaultSession,
    biometric: BiometricUnlock,
    onUnlockWithBiometric: () -> Unit,
    onRememberWithBiometric: (String) -> Unit,
) {
    val state by session.screenState()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.notice) {
        state.notice?.let {
            snackbar.showSnackbar(it)
            session.dismissNotice()
        }
    }
    val fields = state.editor?.takeIf { state.screen == Screen.UNLOCKED }?.let { editor ->
        remember(editor) { EditorFields(editor.detail) }
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when {
                            fields == null && state.history != null -> "History"
                            fields == null && state.deleted != null -> "Recently deleted"
                            fields == null -> "Open Secret Manager"
                            state.editor?.detail == null -> "New item"
                            else -> "Edit item"
                        },
                    )
                },
                actions = {
                    if (fields != null) {
                        // Up here, where no notice covers them.
                        TextButton(onClick = session::closeEditor, modifier = Modifier.testTag("cancel-edit")) { Text("Cancel") }
                        TextButton(
                            onClick = { session.save(fields.draft()) },
                            enabled = fields.title.isNotBlank() && state.busy == null,
                            modifier = Modifier.testTag("save"),
                        ) { Text("Save") }
                    } else if (state.screen == Screen.UNLOCKED) {
                        if (state.detail == null && state.history == null && state.deleted == null) {
                            TextButton(onClick = session::startNew, modifier = Modifier.testTag("new-item")) { Text("New") }
                        }
                        TextButton(onClick = session::lock, modifier = Modifier.testTag("lock")) { Text("Lock") }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (fields == null && (state.screen == Screen.LOCKED || state.screen == Screen.UNLOCKED)) WaitingSave()
            Box(Modifier.weight(1f).fillMaxWidth()) {
                when (state.screen) {
                    Screen.OPENING -> Message("Opening…")
                    Screen.NO_VAULT -> JoinStart(state, session)
                    Screen.JOINING -> JoinConfirm(state, session)
                    Screen.LOCKED -> Unlock(state, session, biometric, onUnlockWithBiometric, onRememberWithBiometric)
                    Screen.UNLOCKED -> fields?.let { ItemEditor(it, state.editor?.detail, session) }
                        ?: state.history?.let { HistoryList(it, session) }
                        ?: state.deleted?.let { DeletedList(it, session) }
                        ?: state.detail?.let { Detail(it, session) }
                        ?: Items(state, session)
                    Screen.REMOVED -> Message(
                        "This phone was removed from the vault",
                        "Your other devices moved to a new key that this phone never received. What it already held stays readable here.",
                    )
                    Screen.UNREADABLE -> Message("The vault on this phone cannot be opened", state.unreadable ?: "")
                }
                state.busy?.let { Busy(it) }
            }
        }
    }
}

/**
 * A login the owner chose to save in the system's offer, whose save screen
 * Android did not open: Android 15 and later open it only while the form's
 * app is on the screen or has just left it. Offered here until it is saved
 * or discarded, or its time is up ([PendingSave.KEPT_MILLIS]).
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun WaitingSave() {
    val context = LocalContext.current
    var waiting by remember { mutableStateOf(PendingSave.waiting()) }
    LifecycleResumeEffect(Unit) {
        waiting = PendingSave.waiting()
        onPauseOrDispose { }
    }
    val shown = waiting ?: return
    // Tags as resource ids: the autofill tests find this from outside.
    Column(Modifier.fillMaxWidth().padding(16.dp).semantics { testTagsAsResourceId = true }.testTag("waiting-save")) {
        Text("A login from ${shown.from} is waiting to be saved", style = MaterialTheme.typography.titleMedium)
        Text(
            "You chose Save, but Android did not open the save screen. The login is kept in this app's memory " +
                "for up to ${PendingSave.KEPT_MILLIS / 60_000} minutes, and nowhere else.",
            style = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { context.startActivity(Intent(context, SaveActivity::class.java).putExtra(SaveActivity.SAVE, shown.id)) },
                modifier = Modifier.testTag("waiting-save-open"),
            ) { Text("Save it") }
            TextButton(
                onClick = {
                    PendingSave.forget(shown.id)
                    waiting = null
                },
                modifier = Modifier.testTag("waiting-save-discard"),
            ) { Text("Discard") }
        }
        HorizontalDivider()
    }
}

@Composable
internal fun Message(title: String, detail: String? = null) {
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center) {
        Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("message"))
        detail?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
internal fun Busy(what: String) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(12.dp))
        Text(what, modifier = Modifier.testTag("busy"))
    }
}

@Composable
private fun JoinStart(state: UiState, session: VaultSession) {
    var invitation by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Join your vault", style = MaterialTheme.typography.titleLarge)
        Text(
            "On your computer, open Devices, choose Invite a device, and pick a phone. Paste the invitation here.",
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = invitation,
            onValueChange = { invitation = it },
            label = { Text("Invitation") },
            modifier = Modifier.fillMaxWidth().testTag("invitation"),
            minLines = 3,
        )
        Button(
            onClick = { session.joinStart(invitation) },
            enabled = invitation.isNotBlank() && state.busy == null,
            modifier = Modifier.testTag("join-continue"),
        ) { Text("Continue") }
    }
}

@Composable
private fun JoinConfirm(state: UiState, session: VaultSession) {
    var password by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Compare the codes", style = MaterialTheme.typography.titleLarge)
        Text("Your computer shows a code too. Continue only if they are identical.", style = MaterialTheme.typography.bodyMedium)
        Text(
            state.joinCode ?: "",
            fontFamily = FontFamily.Monospace,
            fontSize = 34.sp,
            modifier = Modifier.testTag("join-code"),
        )
        Text("This phone's password: at least 12 characters. Your other devices keep their own.", style = MaterialTheme.typography.bodyMedium)
        SecretField(password, { password = it }, "New password for this phone", "new-password")
        SecretField(again, { again = it }, "The same again", "new-password-again")
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = session::cancelJoin, enabled = state.busy == null) { Text("They differ") }
            Button(
                onClick = { session.joinFinish(password) },
                enabled = password.length >= 12 && password == again && state.busy == null,
                modifier = Modifier.testTag("join-finish"),
            ) { Text("Codes match · join") }
        }
    }
}

@Composable
private fun SecretField(value: String, onChange: (String) -> Unit, label: String, tag: String) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth().testTag(tag),
    )
}

@Composable
internal fun Unlock(
    state: UiState,
    session: VaultSession,
    biometric: BiometricUnlock,
    onUnlockWithBiometric: () -> Unit,
    onRememberWithBiometric: (String) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var keepForFingerprint by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Vault locked", style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("locked"))
        SecretField(password, { password = it }, "This phone's password", "password")
        if (biometric.available && !biometric.enabled) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = keepForFingerprint,
                    onCheckedChange = { keepForFingerprint = it },
                    modifier = Modifier.testTag("remember-biometric"),
                )
                Text("Unlock with a fingerprint next time")
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(
                onClick = {
                    val typed = password
                    password = ""
                    session.unlock(typed, onUnlocked = if (keepForFingerprint) ({ onRememberWithBiometric(typed) }) else null)
                },
                enabled = password.isNotEmpty() && state.busy == null,
                modifier = Modifier.testTag("unlock"),
            ) { Text("Unlock") }
            if (biometric.available && biometric.enabled) {
                OutlinedButton(onClick = onUnlockWithBiometric, modifier = Modifier.testTag("unlock-biometric")) {
                    Text("Use a fingerprint")
                }
            }
        }
        SyncLine(state.sync, session)
    }
}

@Composable
private fun Items(state: UiState, session: VaultSession) {
    var query by remember { mutableStateOf("") }
    val shown = state.items.filter {
        query.isBlank() || it.title.contains(query, ignoreCase = true) || it.username.contains(query, ignoreCase = true) ||
            it.url.contains(query, ignoreCase = true)
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        if (state.rowsChanged) RowsChanged(session)
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("Search") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("search"),
        )
        LazyColumn(Modifier.weight(1f)) {
            items(shown, key = { it.id }) { item -> ItemRow(item) { session.open(item.id) } }
        }
        TextButton(onClick = session::openDeleted, modifier = Modifier.testTag("recently-deleted")) { Text("Recently deleted…") }
        AutofillOffer()
        BackgroundSyncSwitch()
        SyncLine(state.sync, session)
    }
}

/** Whether this phone syncs now and then while the app is closed. */
@Composable
private fun BackgroundSyncSwitch() {
    val context = LocalContext.current
    var on by remember { mutableStateOf(BackgroundSync.enabled(context)) }
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("Sync now and then while the app is closed", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(
            checked = on,
            onCheckedChange = {
                on = it
                BackgroundSync.set(context, it)
            },
            modifier = Modifier.testTag("background-sync"),
        )
    }
}

/** Until the owner picks this app to fill logins in other apps: the way to the setting. */
@Composable
private fun AutofillOffer() {
    val context = LocalContext.current
    val manager = context.getSystemService(AutofillManager::class.java) ?: return
    var enabled by remember { mutableStateOf(manager.hasEnabledAutofillServices()) }
    LifecycleResumeEffect(manager) {
        enabled = manager.hasEnabledAutofillServices()
        onPauseOrDispose { }
    }
    if (enabled || !manager.isAutofillSupported) return
    TextButton(
        onClick = {
            context.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${context.packageName}")))
        },
        modifier = Modifier.testTag("turn-on-autofill"),
    ) { Text("Fill logins in other apps…") }
}

/** An unlock found records taken out of the vault's file or changed in it. */
@Composable
private fun RowsChanged(session: VaultSession) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("rows-changed")) {
        Text(
            "Something in this vault's file was taken out or changed",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.error,
        )
        Text(
            "Since this phone last wrote to it, something outside the app removed or changed records in the vault's file: " +
                "an item, an edit, or a device's keys. Your other devices send back what they have at the next sync.",
            style = MaterialTheme.typography.bodySmall,
        )
        TextButton(onClick = session::confirmRowsChanged, modifier = Modifier.testTag("rows-changed-ok")) { Text("I understand") }
        HorizontalDivider()
    }
}

@Composable
private fun ItemRow(item: ItemSummary, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp).testTag("item:${item.title}"),
    ) {
        Text(item.title + if (item.conflict) " · needs a decision on your computer" else "", style = MaterialTheme.typography.titleMedium)
        if (item.username.isNotEmpty()) Text(item.username, style = MaterialTheme.typography.bodySmall)
    }
    HorizontalDivider()
}

@Composable
private fun Detail(detail: ItemDetail, session: VaultSession) {
    var confirmingDelete by remember(detail.id) { mutableStateOf(false) }
    val editable = (detail.kind == ItemKind.LOGIN || detail.kind == ItemKind.SECURE_NOTE) && !detail.conflict
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        TextButton(onClick = session::close, modifier = Modifier.testTag("back")) { Text("‹ All items") }
        Text(detail.title, style = MaterialTheme.typography.headlineSmall)
        if (detail.conflict) {
            Text(
                "Two devices changed this at once. Choose which version to keep on your computer.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }
        if (editable) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = { session.startEdit(detail) }, modifier = Modifier.testTag("edit")) { Text("Edit") }
                OutlinedButton(onClick = { confirmingDelete = true }, modifier = Modifier.testTag("delete")) { Text("Delete…") }
            }
        } else if (!detail.conflict) {
            Text(
                "Identities and cards are edited on your computer.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag("edit-elsewhere"),
            )
        }
        if (detail.username.isNotEmpty()) {
            Field("Username", detail.username, "detail-username") {
                TextButton(onClick = { session.copyUsername(detail) }) { Text("Copy") }
            }
        }
        if (detail.hasPassword) {
            Field("Password", "••••••••••") {
                TextButton(onClick = { session.copyPassword(detail.id) }, modifier = Modifier.testTag("copy-password")) { Text("Copy") }
            }
        }
        if (detail.hasOneTimeCode) {
            Field("One-time code", "••• •••") {
                TextButton(onClick = { session.copyOneTimeCode(detail.id) }, modifier = Modifier.testTag("copy-code")) { Text("Copy") }
            }
        }
        if (detail.url.isNotEmpty()) Field("Website", detail.url)
        // A card's number, an identity's address, a login's own extras:
        // named, and copied rather than shown, as on the computer.
        for (name in detail.fields) {
            Field(name, "••••••••", "field:$name") {
                TextButton(onClick = { session.copyField(detail.id, name) }, modifier = Modifier.testTag("copy-field:$name")) {
                    Text("Copy")
                }
            }
        }
        if (detail.notes.isNotEmpty()) Field("Notes", detail.notes, "detail-notes")
        TextButton(onClick = { session.openHistory(detail) }, modifier = Modifier.testTag("history")) {
            Text("History: every version, and which device made it")
        }
    }
    if (confirmingDelete) {
        AlertDialog(
            onDismissRequest = { confirmingDelete = false },
            title = { Text("Delete ${detail.title}?") },
            text = { Text("It is deleted on all your devices. Its earlier versions stay in the vault's history and in backups.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmingDelete = false
                        session.delete(detail)
                    },
                    modifier = Modifier.testTag("confirm-delete"),
                ) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { confirmingDelete = false }, modifier = Modifier.testTag("keep")) { Text("Keep") }
            },
        )
    }
}

/** Whether a phone restores items of [kind]: logins and secure notes. */
private fun restoresHere(kind: ItemKind) = kind == ItemKind.LOGIN || kind == ItemKind.SECURE_NOTE

private fun said(version: HistoryEntry): String = when {
    version.deleted -> "Deleted the item"
    version.first -> "Made the item"
    version.merged -> "Settled a conflict between versions"
    version.changed.isNotEmpty() -> "Changed ${version.changed.joinToString(", ")}"
    else -> "Saved without a change"
}

/** An item's versions, newest first; one that is not current can be brought back. */
@Composable
private fun HistoryList(history: History, session: VaultSession) {
    var confirming by remember(history) { mutableStateOf<HistoryEntry?>(null) }
    val restorable = restoresHere(history.detail.kind) && history.versions.count { it.current } == 1
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            TextButton(onClick = session::closeHistory, modifier = Modifier.testTag("back")) { Text("‹ ${history.detail.title}") }
            Text(
                "Newest first. Restoring a version makes it the newest; the others stay. Times are not kept, only the order.",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (!restorable) {
                Text(
                    "Identities, cards, and items in conflict are restored on your computer.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 8.dp).testTag("restore-elsewhere"),
                )
            }
        }
        itemsIndexed(history.versions, key = { _, version -> version.revision }) { index, version ->
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("version-$index")) {
                Text(
                    (if (version.thisDevice) "This phone" else "Device ${version.device}") + if (version.current) " · current" else "",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(said(version), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("said-$index"))
                if (!version.deleted) {
                    Text(
                        listOf(version.title, version.username, version.url).filter { it.isNotEmpty() }.joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (restorable && !version.current && !version.deleted) {
                    TextButton(onClick = { confirming = version }, modifier = Modifier.testTag("restore-$index")) {
                        Text("Restore this version…")
                    }
                }
            }
            HorizontalDivider()
        }
    }
    confirming?.let { version ->
        AlertDialog(
            onDismissRequest = { confirming = null },
            title = { Text("Restore this version?") },
            text = { Text("It becomes the newest version on all your devices. The current one stays in the history.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirming = null
                        session.restoreVersion(version)
                    },
                    modifier = Modifier.testTag("confirm-restore"),
                ) { Text("Restore") }
            },
            dismissButton = {
                TextButton(onClick = { confirming = null }, modifier = Modifier.testTag("keep")) { Text("Keep the current") }
            },
        )
    }
}

/** The items deleted on any device, which can be brought back as they were. */
@Composable
private fun DeletedList(deleted: List<DeletedEntry>, session: VaultSession) {
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            TextButton(onClick = session::closeDeleted, modifier = Modifier.testTag("back")) { Text("‹ All items") }
            Text(
                if (deleted.isEmpty()) {
                    "Nothing has been deleted."
                } else {
                    "Deleted on any of your devices, most recently first. Restoring one brings it back on all of them, as it was before it was deleted."
                },
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag("deleted-hint"),
            )
        }
        items(deleted, key = { it.id }) { entry ->
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("deleted:${entry.title}")) {
                Text(entry.title, style = MaterialTheme.typography.titleMedium)
                listOf(entry.username, entry.url).filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }?.let {
                    Text(it.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
                }
                Text(
                    "Deleted on " + if (entry.thisDevice) "this phone" else "device ${entry.device}",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (restoresHere(entry.kind)) {
                    TextButton(onClick = { session.restoreDeleted(entry) }, modifier = Modifier.testTag("restore:${entry.title}")) {
                        Text("Restore")
                    }
                } else {
                    Text("Identities and cards are restored on your computer.", style = MaterialTheme.typography.bodySmall)
                }
            }
            HorizontalDivider()
        }
    }
}

/**
 * What the editor holds while it is open: a new login or secure note, or
 * [detail] as it was read. A blank password or one-time code secret keeps
 * what the item has.
 */
class EditorFields(detail: ItemDetail?) {
    var kind by mutableStateOf(detail?.kind ?: ItemKind.LOGIN)
    var title by mutableStateOf(detail?.title ?: "")
    var username by mutableStateOf(detail?.username ?: "")
    var url by mutableStateOf(detail?.url ?: "")
    var password by mutableStateOf("")
    var showPassword by mutableStateOf(false)
    var code by mutableStateOf("")
    var removeCode by mutableStateOf(false)
    var notes by mutableStateOf(detail?.notes ?: "")
    var favorite by mutableStateOf(detail?.favorite ?: false)

    fun draft(): ItemDraft {
        val login = kind == ItemKind.LOGIN
        return ItemDraft(
            title = title,
            kind = kind,
            username = if (login) username else "",
            url = if (login) url else "",
            notes = notes,
            favorite = favorite,
            password = if (login) password.ifEmpty { null } else null,
            oneTimeCodeSecret = when {
                !login -> null
                removeCode -> ""
                code.isNotBlank() -> code
                else -> null
            },
        )
    }
}

@Composable
private fun ItemEditor(fields: EditorFields, detail: ItemDetail?, session: VaultSession) {
    BackHandler(onBack = session::closeEditor)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (detail != null) Text(detail.title, style = MaterialTheme.typography.titleLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = fields.kind == ItemKind.LOGIN,
                onClick = { fields.kind = ItemKind.LOGIN },
                label = { Text("Login") },
                modifier = Modifier.testTag("kind-login"),
            )
            FilterChip(
                selected = fields.kind == ItemKind.SECURE_NOTE,
                onClick = { fields.kind = ItemKind.SECURE_NOTE },
                label = { Text("Secure note") },
                modifier = Modifier.testTag("kind-note"),
            )
        }
        EditField(fields.title, { fields.title = it }, "Title", "edit-title")
        if (fields.kind == ItemKind.LOGIN) {
            EditField(fields.username, { fields.username = it }, "Username", "edit-username")
            EditField(fields.url, { fields.url = it }, "Website", "edit-url", keyboard = KeyboardType.Uri)
            OutlinedTextField(
                value = fields.password,
                onValueChange = { fields.password = it },
                label = { Text("Password") },
                placeholder = { if (detail?.hasPassword == true) Text("Unchanged") },
                supportingText = { if (detail?.hasPassword == true) Text("Left blank, the password stays as it is") },
                singleLine = true,
                visualTransformation = if (fields.showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth().testTag("edit-password"),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { fields.showPassword = !fields.showPassword }, modifier = Modifier.testTag("show-password")) {
                    Text(if (fields.showPassword) "Hide" else "Show")
                }
                TextButton(
                    onClick = {
                        fields.password = session.generatePassword()
                        fields.showPassword = true
                    },
                    modifier = Modifier.testTag("generate"),
                ) { Text("Generate") }
            }
            OutlinedTextField(
                value = fields.code,
                onValueChange = { fields.code = it },
                label = { Text("One-time code secret") },
                placeholder = { Text(if (detail?.hasOneTimeCode == true) "Unchanged" else "Base32 secret (optional)") },
                supportingText = { if (detail?.hasOneTimeCode == true) Text("Left blank, the one-time code stays as it is") },
                singleLine = true,
                enabled = !fields.removeCode,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth().testTag("edit-code"),
            )
            if (detail?.hasOneTimeCode == true) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = fields.removeCode,
                        onCheckedChange = { fields.removeCode = it },
                        modifier = Modifier.testTag("remove-code"),
                    )
                    Text("Remove the one-time code")
                }
            }
        }
        OutlinedTextField(
            value = fields.notes,
            onValueChange = { fields.notes = it },
            label = { Text("Notes") },
            minLines = if (fields.kind == ItemKind.SECURE_NOTE) 6 else 3,
            modifier = Modifier.fillMaxWidth().testTag("edit-notes"),
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = fields.favorite, onCheckedChange = { fields.favorite = it }, modifier = Modifier.testTag("edit-favorite"))
            Text("Favorite")
        }
    }
}

@Composable
private fun EditField(value: String, onChange: (String) -> Unit, label: String, tag: String, keyboard: KeyboardType = KeyboardType.Text) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        modifier = Modifier.fillMaxWidth().testTag(tag),
    )
}

/** A labelled value, with an action beside it. */
@Composable
private fun Field(label: String, value: String, tag: String? = null, action: @Composable () -> Unit = {}) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge, modifier = tag?.let { Modifier.testTag(it) } ?: Modifier)
        }
        action()
    }
    HorizontalDivider()
}

@Composable
private fun SyncLine(sync: SyncStatus?, session: VaultSession) {
    val text = when (sync?.state) {
        null, SyncState.OFFLINE -> "Offline"
        SyncState.SYNCING -> "Syncing…"
        SyncState.REMOVED -> "Removed from the vault"
        SyncState.ERROR -> "Last sync failed" + (sync.message?.let { " · $it" } ?: "")
        else -> sync.lastSyncedAt?.let {
            "Synced " + DateUtils.getRelativeTimeSpanString(it.toLong() * 1000).toString().lowercase()
        } ?: "Not synced yet"
    }
    val members = sync?.members?.toInt() ?: 0
    Row(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text + if (members > 0) " · $members other ${if (members == 1) "device" else "devices"}" else "",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.weight(1f).testTag("sync"),
        )
        TextButton(onClick = session::syncNow) { Text("Sync now") }
    }
}
