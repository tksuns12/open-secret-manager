package org.opensecretmanager.app.autofill

import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.opensecretmanager.app.BiometricUnlock
import org.opensecretmanager.app.BuildConfig
import org.opensecretmanager.app.Busy
import org.opensecretmanager.app.FingerprintPrompts
import org.opensecretmanager.app.Message
import org.opensecretmanager.app.Screen
import org.opensecretmanager.app.Unlock
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.VaultSession
import org.opensecretmanager.vault.FillCredentials
import org.opensecretmanager.vault.ItemKind
import org.opensecretmanager.vault.ItemSummary

/**
 * Where the owner fills a login into another app or a page, after choosing
 * "unlock to fill" in it: unlock, see who asks, choose the login. A page of
 * a trusted browser is offered the logins saved for its origin and nothing
 * else; an app is offered the logins the owner chose for it before, or the
 * owner chooses one, warned. The vault locks again once this screen goes,
 * as it does when the app is left.
 */
class FillActivity : FragmentActivity() {
    private lateinit var form: Form

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setResult(RESULT_CANCELED)
        form = intent.extras?.let(Form::fromBundle) ?: return finish()
        val session = (application as VaultApp).session
        val biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session)
        val requester = Requester.of(this, form)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                FillScreen(
                    requester = requester,
                    session = session,
                    appLogins = AppLogins(this),
                    biometric = biometric,
                    prompts = prompts,
                    onFill = ::finishWith,
                    onCancel = ::finish,
                )
            }
        }
    }

    /** Hands the login to the form that asked, which fills it at once. */
    private fun finishWith(credentials: FillCredentials) {
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, getString(org.opensecretmanager.app.R.string.app_name))
        }
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(presentation).apply {
            // An empty username leaves what the owner typed there alone.
            form.username?.takeIf { credentials.username.isNotEmpty() }?.let { setValue(it, AutofillValue.forText(credentials.username)) }
            form.password?.let { setValue(it, AutofillValue.forText(credentials.password)) }
        }.build()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        finish()
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
private fun FillScreen(
    requester: Requester?,
    session: VaultSession,
    appLogins: AppLogins,
    biometric: BiometricUnlock,
    prompts: FingerprintPrompts,
    onFill: (FillCredentials) -> Unit,
    onCancel: () -> Unit,
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
        // Tags as resource ids: the tests drive this screen from outside the
        // app, as the system shows it over another one.
        modifier = Modifier.semantics { testTagsAsResourceId = true },
        topBar = {
            TopAppBar(
                title = { Text("Fill a login") },
                actions = { TextButton(onClick = onCancel, modifier = Modifier.testTag("cancel")) { Text("Cancel") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when {
                requester == null -> Message(
                    "Nothing to fill",
                    "Open Secret Manager cannot tell which app asks, so it fills nothing.",
                )
                state.screen == Screen.OPENING -> Message("Opening…")
                state.screen == Screen.LOCKED -> Column {
                    Asker(requester)
                    Unlock(state, session, biometric, prompts::unlock, prompts::keep)
                }
                state.screen == Screen.UNLOCKED -> Column {
                    Asker(requester)
                    when (requester) {
                        is Requester.Web -> WebLogins(requester, session, onFill)
                        is Requester.App -> AppLoginsList(requester, state.items, appLogins, session, onFill)
                    }
                }
                state.screen == Screen.REMOVED -> Message("This phone was removed from the vault")
                state.screen == Screen.UNREADABLE -> Message("The vault on this phone cannot be opened", state.unreadable)
                else -> Message("This phone has no vault yet", "Join your vault in Open Secret Manager first.")
            }
            state.busy?.let { Busy(it) }
        }
    }
}

/** Who the login would go to, as the owner should check it. */
@Composable
private fun Asker(requester: Requester) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 12.dp)) {
        when (requester) {
            is Requester.Web -> {
                Text(
                    "For ${requester.origin.removePrefix("https://")}",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.testTag("asker"),
                )
                Text("A page in ${requester.browserLabel}", style = MaterialTheme.typography.bodySmall)
            }
            is Requester.App -> {
                Text("For the app ${requester.label}", style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("asker"))
                Text(requester.packageName, style = MaterialTheme.typography.bodySmall)
                requester.claimedDomain?.let {
                    Text(
                        "It says it shows $it, but it is not a browser Open Secret Manager trusts to say so.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.testTag("claimed"),
                    )
                }
            }
        }
    }
    HorizontalDivider()
}

@Composable
private fun WebLogins(requester: Requester.Web, session: VaultSession, onFill: (FillCredentials) -> Unit) {
    var logins by remember(requester) { mutableStateOf<List<ItemSummary>?>(null) }
    LaunchedEffect(requester) { session.loginsForWeb(requester.origin) { logins = it } }
    val shown = logins ?: return
    if (shown.isEmpty()) {
        Column(Modifier.padding(24.dp)) {
            Text("No login for this site", style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("no-logins"))
            Text(
                "A login is offered only on the site it was saved for: over https, on the same host and port. " +
                    "Browsers on Android do not say which port a page uses, so a login saved for an unusual port is not offered here.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        return
    }
    LoginRows(shown) { item -> session.fill(item.id, requester.origin, onFill) }
}

@Composable
private fun AppLoginsList(
    requester: Requester.App,
    items: List<ItemSummary>,
    appLogins: AppLogins,
    session: VaultSession,
    onFill: (FillCredentials) -> Unit,
) {
    val logins = items.filter { it.kind == ItemKind.LOGIN }
    val chosen = appLogins.chosen(requester)
    val remembered = logins.filter { it.id in chosen }
    var choosing by remember(requester) { mutableStateOf(false) }
    if (!choosing) {
        Column {
            LoginRows(remembered, Modifier.weight(1f, fill = false)) { item -> session.fill(item.id, null, onFill) }
            TextButton(
                onClick = { choosing = true },
                modifier = Modifier.padding(horizontal = 12.dp).testTag("choose-another"),
            ) { Text(if (remembered.isEmpty()) "Choose a login for this app…" else "Choose another login…") }
        }
        return
    }
    Column {
        Text(
            "An app cannot be checked against a login's address. Choose only a login meant for ${requester.label}: " +
                "it is offered to this app again, and to no other.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp).testTag("warning"),
        )
        LoginRows(logins) { item ->
            session.fill(item.id, null) { credentials ->
                appLogins.remember(requester, item.id)
                onFill(credentials)
            }
        }
    }
}

@Composable
private fun LoginRows(logins: List<ItemSummary>, modifier: Modifier = Modifier, onChoose: (ItemSummary) -> Unit) {
    LazyColumn(modifier.padding(horizontal = 24.dp)) {
        items(logins, key = { it.id }) { item ->
            Column(Modifier.fillMaxWidth().clickable { onChoose(item) }.padding(vertical = 12.dp).testTag("fill:${item.title}")) {
                Text(item.title, style = MaterialTheme.typography.titleMedium)
                if (item.username.isNotEmpty()) Text(item.username, style = MaterialTheme.typography.bodySmall)
            }
            HorizontalDivider()
        }
    }
}
