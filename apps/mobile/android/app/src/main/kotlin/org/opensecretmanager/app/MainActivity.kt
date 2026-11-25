package org.opensecretmanager.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.compose.BackHandler
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.Color
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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
import androidx.compose.material3.Surface
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.LifecycleResumeEffect
import org.opensecretmanager.app.autofill.OtherFieldService
import org.opensecretmanager.app.autofill.PendingSave
import org.opensecretmanager.app.autofill.SaveActivity
import org.opensecretmanager.vault.CardDraft
import org.opensecretmanager.vault.DeletedEntry
import org.opensecretmanager.vault.HistoryEntry
import org.opensecretmanager.vault.ItemDetail
import org.opensecretmanager.vault.PasskeyDetail
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind
import org.opensecretmanager.vault.ItemSummary
import org.opensecretmanager.vault.SyncState
import org.opensecretmanager.vault.SyncStatus
import org.opensecretmanager.vault.checkCardNumber

class MainActivity : ProtectedActivity() {
    private lateinit var biometric: BiometricUnlock

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Status and navigation bars drawn to suit the theme, light or dark.
        enableEdgeToEdge()
        val session = (application as VaultApp).session
        biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session)
        setContent {
            OsmTheme {
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
    // Kept while an item or another screen of the vault is open, and let go
    // of when it locks.
    val place = remember(state.screen == Screen.UNLOCKED, state.locks) { ListPlace() }
    LaunchedEffect(state.notice) {
        state.notice?.let {
            snackbar.showSnackbar(it)
            session.dismissNotice()
        }
    }
    val fields = state.editor?.takeIf { state.screen == Screen.UNLOCKED }?.let { editor ->
        remember(editor) { EditorFields(editor.detail, editor.draft, editor.generated) }
    }
    val atItems = fields == null && state.screen == Screen.UNLOCKED && state.detail == null && state.history == null &&
        state.deleted == null && !state.passwordChange
    val inSettings = atItems && place.settings
    // An item shown on its own, as after restoring one, is closed to the list, not to the settings it came from.
    LaunchedEffect(state.detail != null) { if (state.detail != null) place.settings = false }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                title = {
                    val heading = when {
                        fields == null && state.history != null -> "History"
                        fields == null && state.deleted != null -> "Recently deleted"
                        fields == null && state.passwordChange -> "Change password"
                        inSettings -> "Settings"
                        fields == null -> null
                        state.editor?.detail == null -> "New item"
                        else -> "Edit item"
                    }
                    if (heading != null) {
                        Text(heading, style = MaterialTheme.typography.titleLarge)
                    } else if (state.screen == Screen.UNLOCKED) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            BrandMark(26.dp)
                            Text("Open Secret Manager", style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                },
                actions = {
                    if (fields != null) {
                        // Up here, where no notice covers them.
                        TextButton(onClick = session::closeEditor, modifier = Modifier.testTag("cancel-edit")) { Text("Cancel") }
                        Button(
                            onClick = { session.save(fields.draft()) },
                            enabled = fields.title.isNotBlank() && state.busy == null,
                            modifier = Modifier.testTag("save"),
                        ) { Text("Save") }
                        Spacer(Modifier.width(8.dp))
                    } else if (state.screen == Screen.UNLOCKED) {
                        if (atItems && !inSettings) {
                            TextButton(onClick = { place.settings = true }, modifier = Modifier.testTag("settings")) { Text("Settings") }
                        }
                        TextButton(onClick = session::lock, modifier = Modifier.testTag("lock")) { Text("Lock") }
                    }
                },
            )
        },
        floatingActionButton = {
            if (atItems && !inSettings && state.busy == null) {
                ExtendedFloatingActionButton(
                    onClick = session::startNew,
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                    modifier = Modifier.testTag("new-item"),
                ) { Text("+  New item", fontWeight = FontWeight.Bold) }
            }
        },
    ) { padding ->
        // The keyboard's own room: edge to edge, the window no longer shrinks for it.
        Column(Modifier.padding(padding).consumeWindowInsets(padding).imePadding().fillMaxSize()) {
            if (fields == null && (state.screen == Screen.LOCKED || state.screen == Screen.UNLOCKED)) WaitingSave()
            Box(Modifier.weight(1f).fillMaxWidth()) {
                when (state.screen) {
                    Screen.OPENING -> Message("Opening…")
                    Screen.NO_VAULT -> JoinStart(state, session)
                    Screen.JOINING -> JoinConfirm(state, session)
                    Screen.LOCKED -> Unlock(state, session, biometric, onUnlockWithBiometric, onRememberWithBiometric)
                    Screen.UNLOCKED -> fields?.let { ItemEditor(it, state.editor?.detail, state.editor?.changedElsewhere.orEmpty(), session) }
                        ?: state.history?.let { HistoryList(it, session) }
                        ?: state.deleted?.let { DeletedList(it, session) }
                        ?: state.passwordChange.takeIf { it }?.let { PasswordChange(state, session) }
                        ?: state.detail?.let { Detail(it, state.attention[it.id].orEmpty(), session) }
                        ?: if (place.settings) SettingsScreen(state, session, place) else Items(state, session, place)
                    Screen.REMOVED -> Message(
                        "This phone was removed from the vault",
                        "Your other devices moved to a new key that this phone never received. What it already held stays readable here.",
                    )
                    Screen.UNREADABLE -> Message("The vault on this phone cannot be opened", state.unreadable ?: "")
                }
                state.busy?.let { Busy(it) }
            }
            // A row of its own under the screen, inside the keyboard's room: over the screen it would cover
            // a button and swallow its taps, and in the Scaffold's own place the keyboard can be over it.
            SnackbarHost(snackbar)
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
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        BrandMark(56.dp)
        Spacer(Modifier.height(16.dp))
        Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("message"))
        detail?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
    val context = LocalContext.current
    var invitation by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    // The camera is asked for only when the owner chooses to scan.
    val askCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) scanning = true else session.tell("Without the camera, paste the invitation instead")
    }
    if (scanning) {
        ScanInvitation(
            onInvitation = {
                scanning = false
                session.joinStart(it)
            },
            onCancel = { scanning = false },
            onFailed = {
                scanning = false
                session.tell("The camera could not be started · paste the invitation instead")
            },
        )
        return
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        BrandMark(44.dp)
        Text("Join your vault", style = MaterialTheme.typography.headlineMedium)
        Text(
            if (hasCamera) {
                "On your computer, open Devices, choose Invite a device, and pick a phone. Scan the QR code it shows, or paste the invitation here."
            } else {
                "On your computer, open Devices, choose Invite a device, and pick a phone. Paste the invitation here."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (hasCamera) {
            Button(
                onClick = {
                    val allowed = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
                    if (allowed) scanning = true else askCamera.launch(Manifest.permission.CAMERA)
                },
                enabled = state.busy == null,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("join-scan"),
            ) { Text("Scan the QR code") }
        }
        OutlinedTextField(
            value = invitation,
            onValueChange = { invitation = it },
            label = { Text("Invitation") },
            modifier = Modifier.fillMaxWidth().testTag("invitation"),
            minLines = 3,
            shape = MaterialTheme.shapes.medium,
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MaterialTheme.osm.mono),
        )
        Button(
            onClick = { session.joinStart(invitation) },
            enabled = invitation.isNotBlank() && state.busy == null,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("join-continue"),
        ) { Text("Continue") }
    }
}

@Composable
private fun JoinConfirm(state: UiState, session: VaultSession) {
    var password by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("Compare the codes", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Your computer shows a code too. Continue only if they are identical.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Card {
            Text(
                state.joinCode ?: "",
                fontFamily = MaterialTheme.osm.mono,
                fontWeight = FontWeight.Bold,
                fontSize = 34.sp,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp).testTag("join-code"),
            )
        }
        Text(
            "This phone's password: at least 12 characters. Your other devices keep their own.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SecretField(password, { password = it }, "New password for this phone", "new-password")
        SecretField(again, { again = it }, "The same again", "new-password-again")
        Button(
            onClick = { session.joinFinish(password) },
            enabled = password.length >= 12 && password == again && state.busy == null,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("join-finish"),
        ) { Text("Codes match · join") }
        OutlinedButton(
            onClick = session::cancelJoin,
            enabled = state.busy == null,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
        ) { Text("They differ") }
    }
}

@Composable
private fun SecretField(value: String, onChange: (String) -> Unit, label: String, tag: String) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        shape = MaterialTheme.shapes.medium,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth().testTag(tag),
    )
}

/** This phone's password changed, given the current one. */
@Composable
private fun PasswordChange(state: UiState, session: VaultSession) {
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    BackHandler(onBack = session::closePasswordChange)
    // In characters, as the shared code counts them.
    val long = new.codePointCount(0, new.length) >= 12
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        SecretField(current, { current = it }, "Current password", "current-password")
        SecretField(new, { new = it }, "New password, at least 12 characters", "new-password")
        SecretField(again, { again = it }, "New password again", "new-password-again")
        when {
            new.isNotEmpty() && !long -> "Use at least 12 characters"
            again.isNotEmpty() && again != new -> "The two passwords differ"
            else -> null
        }?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("password-problem"))
        }
        Text(
            "Only this phone's password changes: your other devices keep their own, and the recovery key opens the vault as before. " +
                "Unlocking with a fingerprint is turned off, to be turned on again at the next unlock.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = { session.changePassword(current, new) },
            enabled = current.isNotEmpty() && long && again == new && state.busy == null,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("save-password"),
        ) { Text("Change password") }
        OutlinedButton(
            onClick = session::closePasswordChange,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("cancel-password"),
        ) { Text("Cancel") }
    }
}

@Composable
internal fun Unlock(
    state: UiState,
    session: VaultSession,
    biometric: BiometricUnlock,
    onUnlockWithBiometric: () -> Unit,
    onRememberWithBiometric: (String) -> Unit,
    onUnlocked: () -> Unit = {},
) {
    var password by remember { mutableStateOf("") }
    var keepForFingerprint by remember { mutableStateOf(false) }
    // A fingerprint is asked for at once, when the app comes back or a
    // request's screen opens (see VaultSession.takeAskAtOnce): once, so
    // "Use the password" and the owner's own Lock leave the screen as it is.
    LifecycleResumeEffect(Unit) {
        if (session.takeAskAtOnce() && biometric.available && biometric.enabled) onUnlockWithBiometric()
        onPauseOrDispose { }
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        BrandMark(72.dp)
        Text("Vault locked", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.testTag("locked"))
        Text(
            "Enter this phone's password to open your vault.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SecretField(password, { password = it }, "This phone's password", "password")
        if (biometric.available && !biometric.enabled) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = keepForFingerprint,
                    onCheckedChange = { keepForFingerprint = it },
                    modifier = Modifier.testTag("remember-biometric"),
                )
                Text("Unlock with a fingerprint next time")
            }
        }
        Button(
            onClick = {
                val typed = password
                password = ""
                session.unlock(typed) {
                    onUnlocked()
                    if (keepForFingerprint) onRememberWithBiometric(typed)
                }
            },
            enabled = password.isNotEmpty() && state.busy == null,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("unlock"),
        ) { Text("Unlock", style = MaterialTheme.typography.labelLarge) }
        if (biometric.available && biometric.enabled) {
            OutlinedButton(
                onClick = onUnlockWithBiometric,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("unlock-biometric"),
            ) { Text("Use a fingerprint") }
        }
        SyncLine(state.sync, session)
    }
}

/** Where the item list was: its search, and how far it was scrolled. */
private class ListPlace {
    var query by mutableStateOf("")
    val scroll = LazyListState()
    var settings by mutableStateOf(false)
    var filter by mutableStateOf(ItemFilter.ALL)
}

private enum class ItemFilter(val label: String, val tag: String) {
    ALL("All", "filter-all"),
    FAVORITES("Favorites", "filter-favorites"),
    LOGINS("Logins", "filter-logins"),
    CARDS("Cards", "filter-cards"),
    NOTES("Notes", "filter-notes"),
    ATTENTION("Needs attention", "filter-attention"),
}

@Composable
private fun Items(state: UiState, session: VaultSession, place: ListPlace) {
    val query = place.query
    val filter = place.filter
    val shown = state.items.filter {
        (query.isBlank() || it.title.contains(query, ignoreCase = true) || it.username.contains(query, ignoreCase = true) ||
            it.url.contains(query, ignoreCase = true)) &&
            when (filter) {
                ItemFilter.ALL -> true
                ItemFilter.FAVORITES -> it.favorite
                ItemFilter.LOGINS -> it.kind == ItemKind.LOGIN
                ItemFilter.CARDS -> it.kind == ItemKind.CARD
                ItemFilter.NOTES -> it.kind == ItemKind.SECURE_NOTE
                ItemFilter.ATTENTION -> state.attention.containsKey(it.id)
            }
    }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (state.rowsChanged) RowsChanged(session)
            OutlinedTextField(
                value = query,
                onValueChange = { place.query = it },
                placeholder = { Text("Search ${state.items.size} items") },
                singleLine = true,
                shape = androidx.compose.foundation.shape.CircleShape,
                colors = OutlinedTextFieldDefaults.colors(
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                    focusedContainerColor = MaterialTheme.colorScheme.surfaceContainer,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
                ),
                modifier = Modifier.fillMaxWidth().semantics { contentDescription = "Search items" }.testTag("search"),
            )
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ItemFilter.entries.forEach { choice ->
                    FilterChip(
                        selected = filter == choice,
                        onClick = { place.filter = choice },
                        label = { Text(choice.label) },
                        shape = androidx.compose.foundation.shape.CircleShape,
                        modifier = Modifier.testTag(choice.tag),
                    )
                }
            }
        }
        LazyColumn(
            Modifier.weight(1f),
            state = place.scroll,
            contentPadding = androidx.compose.foundation.layout.PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            items(shown, key = { it.id }) { item -> ItemRow(item, state.attention.containsKey(item.id)) { session.open(item.id) } }
            if (shown.isEmpty()) {
                item {
                    Column(Modifier.fillMaxWidth().padding(vertical = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            if (state.items.isEmpty()) "Nothing here yet" else if (filter == ItemFilter.ATTENTION && query.isBlank()) "Nothing needs attention" else "No match",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(
                            if (state.items.isEmpty()) "Add an item, or sync with your computer." else if (filter == ItemFilter.ATTENTION && query.isBlank()) "By what this checks: short, one kind of character, common, its own name, or shared." else "Try another word or filter.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        // Clear of the floating button, which would otherwise cover "Sync now".
        Box(Modifier.padding(start = 16.dp, end = 168.dp)) { SyncLine(state.sync, session) }
    }
}

/** What the list's toolbar and the old bottom of the list held: the phone's own settings. */
@Composable
private fun SettingsScreen(state: UiState, session: VaultSession, place: ListPlace) {
    BackHandler { place.settings = false }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        TextButton(onClick = { place.settings = false }, modifier = Modifier.testTag("back")) { Text("‹ All items") }
        SectionLabel("Vault")
        CardRows(
            listOf(
                { SettingRow("Recently deleted", "Bring back what any device deleted", Modifier.clickable(onClick = session::openDeleted).testTag("recently-deleted")) { Chevron() } },
                { SettingRow("Change this phone's password", null, Modifier.clickable(onClick = session::openPasswordChange).testTag("change-password")) { Chevron() } },
                { Box(Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) { SyncLine(state.sync, session) } },
            ),
        )
        SectionLabel("Security")
        CardRows(listOf({ StayUnlockedChoice() }))
        SectionLabel("Filling and syncing")
        CardRows(listOf({ BackgroundSyncSwitch() }))
        AutofillOffer()
        OtherFieldChoice()
        Spacer(Modifier.height(24.dp))
    }
}

/**
 * How long the vault stays unlocked once the app is left or the phone's
 * screen turns off, for filling other apps' fields from the system's list
 * without unlocking again.
 */
@Composable
private fun StayUnlockedChoice() {
    val context = LocalContext.current
    var minutes by remember { mutableIntStateOf(StayUnlocked.minutes(context)) }
    var choosing by remember { mutableStateOf(false) }
    fun describe(choice: Int) = when {
        choice == 0 -> "At once"
        choice == 1 -> "After 1 minute"
        choice == 60 -> "After 1 hour"
        choice % 60 == 0 -> "After ${choice / 60} hours"
        else -> "After $choice minutes"
    }
    SettingRow("Lock once the app is left or the screen is off") {
        Box {
            TextButton(onClick = { choosing = true }, modifier = Modifier.testTag("stay-unlocked")) { Text(describe(minutes)) }
            DropdownMenu(expanded = choosing, onDismissRequest = { choosing = false }) {
                StayUnlocked.CHOICES.forEach { choice ->
                    DropdownMenuItem(
                        text = { Text(describe(choice)) },
                        onClick = {
                            minutes = choice
                            StayUnlocked.set(context, choice)
                            choosing = false
                        },
                        modifier = Modifier.testTag("stay-unlocked:$choice"),
                    )
                }
            }
        }
    }
}

/** Whether this phone syncs now and then while the app is closed. */
@Composable
private fun BackgroundSyncSwitch() {
    val context = LocalContext.current
    var on by remember { mutableStateOf(BackgroundSync.enabled(context)) }
    SettingRow("Sync now and then while the app is closed") {
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
    CardRows(
        listOf({
            SettingRow(
                "Fill logins in other apps",
                "Choose this app as Android's autofill service",
                Modifier.clickable {
                    context.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${context.packageName}")))
                }.testTag("turn-on-autofill"),
            ) { Chevron() }
        }),
    )
}

/**
 * Once this app fills logins in other apps: whether a login chosen for one
 * field of an app's page that tells autofill of one field at a time fills
 * the other too ([OtherFieldService]). It is turned on and off in Android's
 * accessibility settings, which open from here.
 */
@Composable
private fun OtherFieldChoice() {
    val context = LocalContext.current
    val manager = context.getSystemService(AutofillManager::class.java) ?: return
    var filling by remember { mutableStateOf(manager.hasEnabledAutofillServices()) }
    var on by remember { mutableStateOf(OtherFieldService.enabled(context)) }
    LifecycleResumeEffect(manager) {
        filling = manager.hasEnabledAutofillServices()
        on = OtherFieldService.enabled(context)
        onPauseOrDispose { }
    }
    if (!filling) return
    Card { Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "Fill the ID and the password together, in apps that show them to autofill one at a time",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = { context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) },
                modifier = Modifier.testTag("other-field"),
            ) { Text(if (on) "On" else "Off") }
        }
        if (!on) {
            Text(
                "Turned on in Android's accessibility settings, as \"${context.getString(R.string.other_field_label)}\". " +
                    "Android may first say the setting is restricted for an app installed from a file: " +
                    "allow it in this app's App info, in the ⋮ menu.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    } }
}

/** An unlock found records taken out of the vault's file or changed in it. */
@Composable
private fun RowsChanged(session: VaultSession) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier.fillMaxWidth().testTag("rows-changed"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                "Something in this vault's file was taken out or changed",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                "Since this phone last wrote to it, something outside the app removed or changed records in the vault's file: " +
                    "an item, an edit, or a device's keys. Your other devices send back what they have at the next sync.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            TextButton(onClick = session::confirmRowsChanged, modifier = Modifier.testTag("rows-changed-ok")) { Text("I understand") }
        }
    }
}

@Composable
private fun ItemRow(item: ItemSummary, needsAttention: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(MaterialTheme.shapes.medium).clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 10.dp).testTag("item:${item.title}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        ItemAvatar(item.title, item.kind)
        Column(Modifier.weight(1f)) {
            Text(item.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val below = if (item.kind == ItemKind.CARD) cardLine(item.brand, item.cardEnding) else loginLine(item.username, item.passkeys)
            if (item.conflict) {
                Text("Needs a decision on your computer", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            } else if (below.isNotEmpty()) {
                Text(
                    below,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (needsAttention) Text("!", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { contentDescription = "Needs attention" }.testTag("attention:${item.title}"))
        if (item.favorite) Text("★", color = MaterialTheme.colorScheme.primary, modifier = Modifier.semantics { contentDescription = "Favorite" })
    }
}

/** Copies one of an item's other fields, which is not shown. */
@Composable
private fun CopyField(detail: ItemDetail, name: String, session: VaultSession) {
    TextButton(onClick = { session.copyField(detail.id, name) }, modifier = Modifier.testTag("copy-field:$name")) { Text("Copy") }
}

/** A login as a list names it: its username, and its passkeys if it has any. */
internal fun loginLine(username: String, passkeys: UInt): String =
    listOfNotNull(
        username.takeIf { it.isNotEmpty() },
        when (passkeys) {
            0u -> null
            1u -> "passkey"
            else -> "$passkeys passkeys"
        },
    ).joinToString(" · ")

/** A card as a list names it: its brand and the last four digits of its number, nothing else of it. */
internal fun cardLine(brand: String?, ending: String?): String =
    listOfNotNull(brand?.takeIf { it.isNotBlank() } ?: "Card", ending?.let { "•••• $it" }).joinToString(" ")

@Composable
private fun Detail(detail: ItemDetail, attention: List<String>, session: VaultSession) {
    var confirmingDelete by remember(detail.id) { mutableStateOf(false) }
    var removing by remember(detail.id) { mutableStateOf<PasskeyDetail?>(null) }
    val editable = detail.kind != ItemKind.IDENTITY && !detail.conflict
    BackHandler(onBack = session::close)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = session::close, modifier = Modifier.testTag("back")) { Text("‹ All items") }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            ItemAvatar(detail.title, detail.kind, 56.dp)
            Text(detail.title, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
        }
        if (detail.conflict) {
            Surface(shape = MaterialTheme.shapes.medium, color = MaterialTheme.colorScheme.errorContainer) {
                Text(
                    "Two devices changed this at once. Choose which version to keep on your computer.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(16.dp),
                )
            }
        }
        if (attention.isNotEmpty()) {
            Surface(shape = MaterialTheme.shapes.medium, color = MaterialTheme.colorScheme.tertiaryContainer, modifier = Modifier.semantics(mergeDescendants = true) {}.testTag("attention-note")) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Worth changing this password", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onTertiaryContainer)
                    Text(attention.joinToString(" "), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onTertiaryContainer)
                }
            }
        }
        if (editable) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = { session.startEdit(detail) }, modifier = Modifier.weight(1f).height(48.dp).testTag("edit")) { Text("Edit") }
                OutlinedButton(onClick = { confirmingDelete = true }, modifier = Modifier.weight(1f).height(48.dp).testTag("delete")) { Text("Delete…") }
            }
        } else if (!detail.conflict) {
            Text(
                "Identities are edited on your computer.",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag("edit-elsewhere"),
            )
        }
        // A card's own fields: its number by its last four digits only, and
        // the number and code copied rather than shown, as on the computer.
        detail.card?.let { card ->
            if (card.cardholder.isNotEmpty()) {
                Field("Cardholder name", card.cardholder, "card-cardholder") { CopyField(detail, "Cardholder name", session) }
            }
            if (card.hasNumber) {
                Field("Number", card.numberEnding?.let { "•••• $it" } ?: "••••••••", "card-number") { CopyField(detail, "Number", session) }
            }
            if (card.expiryMonth.isNotEmpty() || card.expiryYear.isNotEmpty()) {
                Field("Expires", "${card.expiryMonth.ifEmpty { "--" }} / ${card.expiryYear.ifEmpty { "----" }}", "card-expiry")
            }
            if (card.hasSecurityCode) Field("Security code", "•••", "card-code") { CopyField(detail, "Security code", session) }
            if (card.brand.isNotEmpty()) Field("Brand", card.brand, "card-brand")
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
        // A login's passkeys, by site and account; never a key.
        for (passkey in detail.passkeys) {
            Field("Passkey for ${passkey.rpId}", passkeyAccount(passkey), "passkey:${passkey.rpId}") {
                if (!detail.conflict) {
                    TextButton(onClick = { removing = passkey }, modifier = Modifier.testTag("remove-passkey:${passkey.rpId}")) {
                        Text("Remove")
                    }
                }
            }
        }
        // An identity's address, a login's own extras: named, and copied
        // rather than shown, as on the computer.
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
    removing?.let { passkey ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text("Remove this passkey?") },
            text = {
                Text(
                    "It is removed on all your devices, and you will no longer sign in to ${passkey.rpId} with it. " +
                        "Its key stays in this item's history and in backups.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        removing = null
                        session.removePasskey(detail, passkey)
                    },
                    modifier = Modifier.testTag("confirm-remove-passkey"),
                ) { Text("Remove") }
            },
            dismissButton = {
                TextButton(onClick = { removing = null }, modifier = Modifier.testTag("keep")) { Text("Keep") }
            },
        )
    }
}

/** The account a passkey is for, and when it was made, if that is known. */
private fun passkeyAccount(passkey: PasskeyDetail): String {
    val account = when {
        passkey.userName.isEmpty() -> "No account name"
        passkey.userDisplayName.isNotEmpty() && passkey.userDisplayName != passkey.userName -> "${passkey.userName} (${passkey.userDisplayName})"
        else -> passkey.userName
    }
    if (passkey.createdAt == 0uL) return account
    val made = java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(passkey.createdAt.toLong() * 1000))
    return "$account · made $made"
}

/** Whether a phone restores items of [kind]: all but identities. */
private fun restoresHere(kind: ItemKind) = kind != ItemKind.IDENTITY

/** A time a device recorded, in seconds since 1970, as this phone writes dates. */
private fun savedTime(seconds: ULong): String =
    java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT)
        .format(java.util.Date(seconds.toLong() * 1000))

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
    BackHandler(onBack = session::closeHistory)
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 24.dp),
    ) {
        item {
            TextButton(onClick = session::closeHistory, modifier = Modifier.testTag("back")) { Text("‹ ${history.detail.title}") }
            Text(
                "Newest first. Restoring a version makes it the newest; the others stay. Each time is by the clock of the device that saved the version; versions saved before times were kept have none.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp),
            )
            if (!restorable) {
                Text(
                    "Identities, and items in conflict, are restored on your computer.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp).testTag("restore-elsewhere"),
                )
            }
        }
        itemsIndexed(history.versions, key = { _, version -> version.revision }) { index, version ->
            Card(Modifier.testTag("version-$index")) {
                Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            if (version.thisDevice) "This phone" else "Device ${version.device}",
                            style = MaterialTheme.typography.titleSmall,
                        )
                        if (version.current) {
                            Text(
                                "CURRENT",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier
                                    .background(MaterialTheme.colorScheme.primaryContainer, CircleShape)
                                    .padding(horizontal = 8.dp, vertical = 2.dp),
                            )
                        }
                    }
                    Text(
                        version.savedAt?.let(::savedTime) ?: "Time not recorded",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("time-$index"),
                    )
                    Text(
                        said(version),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(top = 6.dp).testTag("said-$index"),
                    )
                    if (!version.deleted) {
                        Text(
                            listOf(version.title, version.username, version.url).filter { it.isNotEmpty() }.joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (restorable && !version.current && !version.deleted) {
                        OutlinedButton(
                            onClick = { confirming = version },
                            modifier = Modifier.padding(top = 8.dp).testTag("restore-$index"),
                        ) { Text("Restore this version…") }
                    }
                }
            }
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
    BackHandler(onBack = session::closeDeleted)
    LazyColumn(
        Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(bottom = 24.dp),
    ) {
        item {
            TextButton(onClick = session::closeDeleted, modifier = Modifier.testTag("back")) { Text("‹ Settings") }
            Text(
                if (deleted.isEmpty()) {
                    "Nothing has been deleted."
                } else {
                    "Deleted on any of your devices, most recently first. Restoring one brings it back on all of them, as it was before it was deleted."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp).testTag("deleted-hint"),
            )
        }
        items(deleted, key = { it.id }) { entry ->
            Card(Modifier.testTag("deleted:${entry.title}")) {
                Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    ItemAvatar(entry.title, entry.kind)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(entry.title, style = MaterialTheme.typography.titleMedium)
                        listOf(entry.username, entry.url).filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }?.let {
                            Text(it.joinToString(" · "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Text(
                            "Deleted on " + (if (entry.thisDevice) "this phone" else "device ${entry.device}") +
                                (entry.deletedAt?.let { " · " + savedTime(it) } ?: ""),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (restoresHere(entry.kind)) {
                            OutlinedButton(
                                onClick = { session.restoreDeleted(entry) },
                                modifier = Modifier.padding(top = 8.dp).testTag("restore:${entry.title}"),
                            ) { Text("Restore") }
                        } else {
                            Text("Identities are restored on your computer.", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

/**
 * What the editor holds while it is open: a new item, or [detail] as it was
 * read, from [draft] if there is one. A blank password or one-time code
 * secret keeps what the item has. A new item's password is the one made for
 * it, [generated], shown, until the owner types over it.
 */
class EditorFields(detail: ItemDetail?, draft: ItemDraft? = null, generated: String? = null) {
    var kind by mutableStateOf(draft?.kind ?: detail?.kind ?: ItemKind.LOGIN)
    var title by mutableStateOf(draft?.title ?: detail?.title ?: "")
    var username by mutableStateOf(draft?.username ?: detail?.username ?: "")
    var url by mutableStateOf(draft?.url ?: detail?.url ?: "")
    var password by mutableStateOf(draft?.password ?: generated ?: "")
    var showPassword by mutableStateOf(draft == null && generated != null)
    /** The password is one the generator made. */
    var made by mutableStateOf(draft == null && generated != null)
    var generatorOpen by mutableStateOf(false)
    var code by mutableStateOf(draft?.oneTimeCodeSecret?.takeIf { it.isNotEmpty() } ?: "")
    var removeCode by mutableStateOf(draft?.oneTimeCodeSecret == "")
    var notes by mutableStateOf(draft?.notes ?: detail?.notes ?: "")
    var favorite by mutableStateOf(draft?.favorite ?: detail?.favorite ?: false)
    var cardholder by mutableStateOf(draft?.card?.cardholder ?: detail?.card?.cardholder ?: "")
    var number by mutableStateOf(draft?.card?.number ?: "")
    var showNumber by mutableStateOf(false)
    var expiryMonth by mutableStateOf(draft?.card?.expiryMonth ?: detail?.card?.expiryMonth ?: "")
    var expiryYear by mutableStateOf(draft?.card?.expiryYear ?: detail?.card?.expiryYear ?: "")
    var securityCode by mutableStateOf(draft?.card?.securityCode?.takeIf { it.isNotEmpty() } ?: "")
    var removeSecurityCode by mutableStateOf(draft?.card?.securityCode == "")
    /** The brand the owner typed; `null` until then, for the one the number names. */
    var brand by mutableStateOf(draft?.card?.brand)

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
            // Blank, the number and the code stay as they are.
            card = if (kind == ItemKind.CARD) {
                CardDraft(
                    cardholder = cardholder,
                    expiryMonth = expiryMonth,
                    expiryYear = expiryYear,
                    brand = brand,
                    number = number.ifEmpty { null },
                    securityCode = when {
                        removeSecurityCode -> ""
                        securityCode.isNotBlank() -> securityCode
                        else -> null
                    },
                )
            } else {
                null
            },
        )
    }
}

@Composable
private fun ItemEditor(fields: EditorFields, detail: ItemDetail?, changedElsewhere: List<String>, session: VaultSession) {
    BackHandler(onBack = session::closeEditor)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (detail != null) Text(detail.title, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(horizontal = 4.dp))
        if (changedElsewhere.isNotEmpty()) {
            Column(
                Modifier.fillMaxWidth()
                    .background(MaterialTheme.colorScheme.errorContainer, MaterialTheme.shapes.medium)
                    .padding(16.dp)
                    .testTag("changed-elsewhere"),
            ) {
                Text(
                    "Another device changed this item while you edited it",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
                Text(
                    "It changed its ${changedElsewhere.joinToString(", ")}. What you typed is kept, on top of the item as it is " +
                        "now; nothing is saved until you save.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }
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
            FilterChip(
                selected = fields.kind == ItemKind.CARD,
                onClick = { fields.kind = ItemKind.CARD },
                label = { Text("Card") },
                modifier = Modifier.testTag("kind-card"),
            )
        }
        EditField(fields.title, { fields.title = it }, "Title", "edit-title")
        if (fields.kind == ItemKind.LOGIN) {
            EditField(fields.username, { fields.username = it }, "Username", "edit-username")
            EditField(fields.url, { fields.url = it }, "Website", "edit-url", keyboard = KeyboardType.Uri)
            OutlinedTextField(
                value = fields.password,
                onValueChange = {
                    fields.password = it
                    fields.made = false
                },
                label = { Text("Password") },
                placeholder = { if (detail?.hasPassword == true) Text("Unchanged") },
                supportingText = {
                    when {
                        fields.made -> Text("Made for this item with the generator's choice. Type over it, or clear it.", modifier = Modifier.testTag("password-made"))
                        detail?.hasPassword == true -> Text("Left blank, the password stays as it is")
                    }
                },
                singleLine = true,
                visualTransformation = if (fields.showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth().testTag("edit-password"),
            )
            val context = LocalContext.current
            fun generate() {
                fields.password = session.generatePassword()
                fields.made = true
                fields.showPassword = true
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = { fields.showPassword = !fields.showPassword }, modifier = Modifier.testTag("show-password")) {
                    Text(if (fields.showPassword) "Hide" else "Show")
                }
                TextButton(onClick = ::generate, modifier = Modifier.testTag("generate")) { Text("Generate") }
                TextButton(
                    onClick = { fields.generatorOpen = !fields.generatorOpen },
                    modifier = Modifier.testTag("generator-open"),
                ) { Text(if (fields.generatorOpen) "Close options" else "Options") }
                TextButton(
                    onClick = {
                        fields.password = ""
                        fields.made = false
                    },
                    enabled = fields.password.isNotEmpty(),
                    modifier = Modifier.testTag("clear-password"),
                ) { Text("Clear") }
            }
            if (fields.generatorOpen) {
                // Each change makes the password again with it.
                var options by remember { mutableStateOf(Generator.options(context)) }
                GeneratorOptions(options) {
                    Generator.set(context, it)
                    options = it
                    generate()
                }
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
        if (fields.kind == ItemKind.CARD) CardEditor(fields, detail)
        OutlinedTextField(
            value = fields.notes,
            onValueChange = { fields.notes = it },
            label = { Text("Notes") },
            minLines = if (fields.kind == ItemKind.SECURE_NOTE) 6 else 3,
            modifier = Modifier.fillMaxWidth().testTag("edit-notes"),
        )
        Card {
            Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = fields.favorite, onCheckedChange = { fields.favorite = it }, modifier = Modifier.testTag("edit-favorite"))
                Text("Favorite", style = MaterialTheme.typography.bodyLarge)
            }
        }
        Spacer(Modifier.height(16.dp))
    }
}

/** A card's own fields in the editor. */
@Composable
private fun CardEditor(fields: EditorFields, detail: ItemDetail?) {
    val stored = detail?.card
    val check = remember(fields.number) { checkCardNumber(fields.number) }
    EditField(fields.cardholder, { fields.cardholder = it }, "Cardholder name", "edit-cardholder")
    OutlinedTextField(
        value = fields.number,
        onValueChange = { fields.number = it },
        label = { Text("Number") },
        placeholder = { if (stored?.hasNumber == true) Text("Unchanged" + (stored.numberEnding?.let { " (•••• $it)" } ?: "")) },
        supportingText = { if (stored?.hasNumber == true && fields.number.isEmpty()) Text("Left blank, the number stays as it is") },
        singleLine = true,
        visualTransformation = if (fields.showNumber) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = if (fields.showNumber) KeyboardType.Number else KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth().testTag("edit-number"),
    )
    if (check.complete && !check.passes) {
        Text(
            "This number fails a card number's check: a digit may be mistyped. It is saved as typed.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.testTag("number-check"),
        )
    }
    TextButton(onClick = { fields.showNumber = !fields.showNumber }, modifier = Modifier.testTag("show-number")) {
        Text(if (fields.showNumber) "Hide" else "Show")
    }
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = fields.expiryMonth,
            onValueChange = { fields.expiryMonth = it },
            label = { Text("Expiry month") },
            placeholder = { Text("MM") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.weight(1f).testTag("edit-expiry-month"),
        )
        OutlinedTextField(
            value = fields.expiryYear,
            onValueChange = { fields.expiryYear = it },
            label = { Text("Expiry year") },
            placeholder = { Text("YYYY") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.weight(1f).testTag("edit-expiry-year"),
        )
    }
    OutlinedTextField(
        value = fields.securityCode,
        onValueChange = { fields.securityCode = it },
        label = { Text("Security code") },
        placeholder = { if (stored?.hasSecurityCode == true) Text("Unchanged") },
        supportingText = { if (stored?.hasSecurityCode == true) Text("Left blank, the security code stays as it is") },
        singleLine = true,
        enabled = !fields.removeSecurityCode,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth().testTag("edit-security-code"),
    )
    if (stored?.hasSecurityCode == true) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = fields.removeSecurityCode,
                onCheckedChange = { fields.removeSecurityCode = it },
                modifier = Modifier.testTag("remove-security-code"),
            )
            Text("Remove the security code")
        }
    }
    // Untouched, the brand is the one a new number names, or else the stored one.
    EditField(
        fields.brand ?: if (fields.number.isNotEmpty()) check.brand.orEmpty() else stored?.brand.orEmpty(),
        { fields.brand = it },
        "Brand",
        "edit-brand",
    )
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

/** A labelled value, with an action beside it, in a card of its own. */
@Composable
private fun Field(label: String, value: String, tag: String? = null, action: @Composable () -> Unit = {}) {
    Card {
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(value, style = MaterialTheme.typography.bodyLarge, modifier = tag?.let { Modifier.testTag(it) } ?: Modifier)
            }
            action()
        }
    }
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
