package org.opensecretmanager.app.autofill

import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
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
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import org.opensecretmanager.app.BiometricUnlock
import org.opensecretmanager.app.BuildConfig
import org.opensecretmanager.app.Busy
import org.opensecretmanager.app.FingerprintPrompts
import org.opensecretmanager.app.Message
import org.opensecretmanager.app.Screen
import org.opensecretmanager.app.Unlock
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.VaultSession
import org.opensecretmanager.app.screenState
import org.opensecretmanager.vault.ItemDraft
import org.opensecretmanager.vault.ItemKind
import org.opensecretmanager.vault.SaveCandidate

/**
 * Where the owner saves what another app's login form or a page submitted,
 * after choosing to save it in the system's offer: unlock, see who sent it,
 * and either update the password of a login that form could be filled with,
 * or save a new login. A new login for a trusted browser's page is saved for
 * its origin; one for an app, for that app. Once this screen goes, the vault
 * locks as when the app is left.
 */
class SaveActivity : FragmentActivity() {
    private var id = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        id = intent.getIntExtra(SAVE, 0)
        val save = PendingSave.open(id)
        // Android can start this screen late, once the form's app is opened
        // again, for a save the owner already handled from the app's screen.
        if (save == null && PendingSave.settled(id)) {
            Toast.makeText(applicationContext, "That login was already saved or discarded", Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        val session = (application as VaultApp).session
        if (savedInstanceState == null) session.askAtOnceNext()
        val requester = save?.let { Requester.of(this, it.form) }
        val biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session, requester?.said)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                SaveScreen(
                    save = save,
                    requester = requester,
                    session = session,
                    appLogins = AppLogins(this),
                    biometric = biometric,
                    prompts = prompts,
                    onSaved = ::saved,
                    onCancel = ::finish,
                )
            }
        }
    }

    private fun saved(what: String?) {
        what?.let { Toast.makeText(applicationContext, it, Toast.LENGTH_SHORT).show() }
        finish()
    }

    override fun onDestroy() {
        if (isFinishing) PendingSave.forget(id)
        super.onDestroy()
    }

    companion object {
        /** The extra naming the save in [PendingSave]. */
        const val SAVE = "save"
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
private fun SaveScreen(
    save: PendingSave.Save?,
    requester: Requester?,
    session: VaultSession,
    appLogins: AppLogins,
    biometric: BiometricUnlock,
    prompts: FingerprintPrompts,
    onSaved: (String?) -> Unit,
    onCancel: () -> Unit,
) {
    val state by session.screenState()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.notice) {
        state.notice?.let {
            snackbar.showSnackbar(it)
            session.dismissNotice()
        }
    }
    Scaffold(
        // Tags as resource ids: the tests drive this screen from outside the
        // app, as the system shows it over another one.
        modifier = Modifier.semantics { testTagsAsResourceId = true },
        topBar = {
            TopAppBar(
                title = { Text("Save a login") },
                actions = { TextButton(onClick = onCancel, modifier = Modifier.testTag("cancel")) { Text("Cancel") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when {
                save == null -> Message("Nothing to save", "Submit the form again to save its login.")
                requester == null -> Message(
                    "Nothing to save",
                    "Open Secret Manager cannot tell which app sent this login, so it saves nothing.",
                )
                state.screen == Screen.OPENING -> Message("Opening…")
                state.screen == Screen.LOCKED -> Column {
                    Asker(requester)
                    Unlock(state, session, biometric, prompts::unlock, prompts::keep)
                }
                state.screen == Screen.UNLOCKED -> Column {
                    Asker(requester)
                    SaveChoices(save, requester, session, appLogins, state.busy == null, onSaved)
                }
                state.screen == Screen.REMOVED -> Message("This phone was removed from the vault")
                state.screen == Screen.UNREADABLE -> Message("The vault on this phone cannot be opened", state.unreadable)
                else -> Message("This phone has no vault yet", "Join your vault in Open Secret Manager first.")
            }
            state.busy?.let { Busy(it) }
        }
    }
}

/**
 * The logins the form's password could go into, which are those the same
 * form could be filled with under the username it sent, and a new login.
 */
@Composable
private fun SaveChoices(
    save: PendingSave.Save,
    requester: Requester,
    session: VaultSession,
    appLogins: AppLogins,
    idle: Boolean,
    onSaved: (String?) -> Unit,
) {
    var candidates by remember { mutableStateOf<List<SaveCandidate>?>(null) }
    // Read again after an update found its login changed.
    var reads by remember { mutableIntStateOf(0) }
    LaunchedEffect(reads) {
        val origin = (requester as? Requester.Web)?.origin
        val chosen = (requester as? Requester.App)?.let(appLogins::chosen).orEmpty()
        session.saveCandidates(origin, chosen, save.username, save.password) { candidates = it }
    }
    val shown = candidates ?: return
    var title by remember { mutableStateOf(requester.title) }
    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column {
            Text("Username", style = MaterialTheme.typography.labelMedium)
            Text(save.username.ifEmpty { "None" }, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.testTag("save-username"))
            Text("The password the form sent is not shown.", style = MaterialTheme.typography.bodySmall)
        }
        val already = shown.firstOrNull { it.hasThisPassword }
        if (already != null) {
            Text(
                "Already saved, in ${already.title}",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.testTag("already-saved"),
            )
            Button(onClick = { onSaved(null) }, modifier = Modifier.testTag("done")) { Text("Done") }
        } else {
            if (shown.isNotEmpty()) {
                HorizontalDivider()
                Text("Update a login", style = MaterialTheme.typography.titleMedium)
                shown.forEach { candidate ->
                    OutlinedButton(
                        onClick = {
                            session.updatePassword(candidate, save.password) { saved ->
                                if (saved) onSaved("Password updated in ${candidate.title}") else reads++
                            }
                        },
                        enabled = idle,
                        modifier = Modifier.fillMaxWidth().testTag("update:${candidate.title}"),
                    ) { Text("Update the password of ${candidate.title}") }
                }
            }
            HorizontalDivider()
            Text(if (shown.isEmpty()) "Save a new login" else "Or save a new login", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Title") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("save-title"),
            )
            Text(
                when (requester) {
                    is Requester.Web -> "It is offered on ${requester.origin.removePrefix("https://")} only."
                    is Requester.App -> "It is offered to ${requester.label} again, and to no other app."
                },
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                onClick = {
                    val draft = ItemDraft(
                        title = title,
                        kind = ItemKind.LOGIN,
                        username = save.username,
                        url = (requester as? Requester.Web)?.origin.orEmpty(),
                        notes = "",
                        favorite = false,
                        password = save.password,
                        oneTimeCodeSecret = null,
                        card = null,
                    )
                    session.saveNew(draft) { id ->
                        if (requester is Requester.App) appLogins.remember(requester, id)
                        onSaved("Saved in Open Secret Manager")
                    }
                },
                enabled = title.isNotBlank() && idle,
                modifier = Modifier.testTag("save-new"),
            ) { Text("Save as a new login") }
        }
    }
}
