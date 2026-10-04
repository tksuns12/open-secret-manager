package org.opensecretmanager.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.view.WindowManager
import android.view.autofill.AutofillManager
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.opensecretmanager.vault.ItemDetail
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
    val state by session.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.notice) {
        state.notice?.let {
            snackbar.showSnackbar(it)
            session.dismissNotice()
        }
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Open Secret Manager") },
                actions = {
                    if (state.screen == Screen.UNLOCKED) {
                        TextButton(onClick = session::lock, modifier = Modifier.testTag("lock")) { Text("Lock") }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state.screen) {
                Screen.OPENING -> Message("Opening…")
                Screen.NO_VAULT -> JoinStart(state, session)
                Screen.JOINING -> JoinConfirm(state, session)
                Screen.LOCKED -> Unlock(state, session, biometric, onUnlockWithBiometric, onRememberWithBiometric)
                Screen.UNLOCKED -> state.detail?.let { Detail(it, session) } ?: Items(state, session)
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
        AutofillOffer()
        SyncLine(state.sync, session)
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
    Column(Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        TextButton(onClick = session::close, modifier = Modifier.testTag("back")) { Text("‹ All items") }
        Text(detail.title, style = MaterialTheme.typography.headlineSmall)
        if (detail.conflict) {
            Text(
                "Two devices changed this at once. Choose which version to keep on your computer.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
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
        if (detail.notes.isNotEmpty()) Field("Notes", detail.notes)
    }
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
