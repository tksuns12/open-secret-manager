package org.opensecretmanager.app.autofill

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.net.Uri
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Toast
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
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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
import org.opensecretmanager.vault.FillCredentials
import org.opensecretmanager.vault.ItemKind
import org.opensecretmanager.vault.ItemSummary

/**
 * Where the owner fills a login into another app or a page, after choosing
 * "unlock to fill" in it: unlock, see who asks, choose the login. A page of
 * a trusted browser is offered the logins saved for its origin and nothing
 * else; an app is offered the logins the owner chose for it before, is
 * suggested those saved for a site that names it as its app ([LinkedSites]),
 * or the owner chooses one, warned. A form that asks for a one-time code is offered
 * only logins that have one, and gets the login's current code; a form with
 * a password field and a code field gets both. A login the owner chose in
 * the system's list while the vault was unlocked ([ITEM]) is filled without
 * this screen showing, or once unlocked if the vault locked meanwhile. Once
 * this screen goes, the vault locks as when the app is left. A page of an
 * app that told of the username alone, or the password alone, gets the
 * other through [OtherFieldService], if the owner turned it on.
 */
class FillActivity : FragmentActivity() {
    private lateinit var form: Form
    private var requester: Requester? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setResult(RESULT_CANCELED)
        form = intent.extras?.let(Form::fromBundle) ?: return finish()
        val session = (application as VaultApp).session
        val requester = Requester.of(this, form)
        this.requester = requester
        val appLogins = AppLogins(this)
        // Chosen in the list: for an app, only a login the owner chose for it.
        val chosen = intent.getStringExtra(ITEM)?.takeIf { item ->
            requester is Requester.Web || (requester is Requester.App && item in appLogins.chosen(requester))
        }
        if (chosen == null) return show(session, requester, appLogins, null)
        // Nothing drawn while it fills: the app that asked stays in sight.
        val background = window.decorView.background
        window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
        session.fillChosen(chosen, (requester as? Requester.Web)?.origin, login = !form.codeOnly, code = form.oneTimeCode != null) { filled ->
            if (filled != null) {
                finishWith(filled.first, filled.second)
            } else {
                window.setBackgroundDrawable(background)
                show(session, requester, appLogins, chosen)
            }
        }
    }

    private fun show(session: VaultSession, requester: Requester?, appLogins: AppLogins, chosen: String?) {
        val biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                FillScreen(
                    requester = requester,
                    codeOnly = form.codeOnly,
                    withCode = form.oneTimeCode != null,
                    chosen = chosen,
                    session = session,
                    appLogins = appLogins,
                    biometric = biometric,
                    prompts = prompts,
                    onFill = ::finishWith,
                    onCancel = ::finish,
                )
            }
        }
    }

    /** Hands what was chosen to the form that asked, which fills it at once. */
    private fun finishWith(credentials: FillCredentials?, code: String?) {
        credentials?.let(::fillOther)
        val values = buildList {
            credentials?.let { login ->
                // An empty username leaves what the owner typed there alone.
                form.username?.takeIf { login.username.isNotEmpty() }?.let { add(it to login.username) }
                form.password?.let { add(it to login.password) }
            }
            code?.let { value -> form.oneTimeCode?.let { add(it to value) } }
        }
        // A login with no username, for a field that asks for the username
        // alone: nothing to fill.
        if (values.isEmpty()) return finish()
        val presentation = entry(this, getString(org.opensecretmanager.app.R.string.app_name), credentials?.username)
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(presentation).apply {
            values.forEach { (id, value) -> setValue(id, AutofillValue.forText(value)) }
        }.build()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        finish()
    }

    /**
     * A page of an app that told of a login's username alone, or its
     * password alone, as a page whose fields are each in a form of their own
     * does: the other goes into the page's other field once the system has
     * filled this one. Not a browser's page, trusted or not, whose next page
     * can be another site's before the other field is filled.
     */
    private fun fillOther(login: FillCredentials) {
        if (!form.page || requester !is Requester.App || form.oneTimeCode != null || opensAnyAddress(form.packageName)) return
        when {
            form.username != null && form.password == null && login.password.isNotEmpty() ->
                OtherFieldService.fillAfter(form.packageName, password = true, value = login.password, filled = login.username)
            form.password != null && form.username == null && login.username.isNotEmpty() ->
                OtherFieldService.fillAfter(form.packageName, password = false, value = login.username, filled = login.password)
        }
    }

    /** Whether the app opens a link to any site, as a browser does. */
    private fun opensAnyAddress(packageName: String): Boolean {
        val link = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.invalid/"))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(packageName)
        return packageManager.queryIntentActivities(link, PackageManager.MATCH_ALL).isNotEmpty()
    }

    companion object {
        /** The extra naming the login the owner chose in the system's list. */
        const val ITEM = "item"
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
private fun FillScreen(
    requester: Requester?,
    codeOnly: Boolean,
    withCode: Boolean,
    chosen: String?,
    session: VaultSession,
    appLogins: AppLogins,
    biometric: BiometricUnlock,
    prompts: FingerprintPrompts,
    onFill: (FillCredentials?, String?) -> Unit,
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
    // A login chosen in the system's list, the vault locked meanwhile:
    // filled once it is unlocked, or tried once more, with what went wrong
    // shown, if it was unlocked.
    var pending by remember { mutableStateOf(chosen) }
    LaunchedEffect(state.screen, pending) {
        val item = pending ?: return@LaunchedEffect
        if (state.screen != Screen.UNLOCKED || requester == null) return@LaunchedEffect
        pending = null
        session.fill(item, (requester as? Requester.Web)?.origin, login = !codeOnly, code = withCode, done = onFill)
    }
    // Fills what the form asks for from a login; one chosen for an app from
    // every login is remembered for it, and the owner told so, as nothing
    // asks to save a login that was filled.
    val context = LocalContext.current
    val fill: (ItemSummary, String?, Boolean) -> Unit = { item, origin, chosenNow ->
        session.fill(item.id, origin, login = !codeOnly, code = withCode) { credentials, code ->
            if (chosenNow && requester is Requester.App) {
                appLogins.remember(requester, item.id)
                Toast.makeText(context.applicationContext, "${item.title} is offered in ${requester.label} from now on", Toast.LENGTH_LONG).show()
            }
            onFill(credentials, code)
        }
    }
    Scaffold(
        // Tags as resource ids: the tests drive this screen from outside the
        // app, as the system shows it over another one.
        modifier = Modifier.semantics { testTagsAsResourceId = true },
        topBar = {
            TopAppBar(
                title = { Text(if (codeOnly) "Fill a one-time code" else "Fill a login") },
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
                        is Requester.Web -> WebLogins(requester, codeOnly, session) { fill(it, requester.origin, false) }
                        is Requester.App -> AppLoginsList(requester, state.items, codeOnly, appLogins, session, fill)
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
internal fun Asker(requester: Requester) {
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
private fun WebLogins(requester: Requester.Web, codeOnly: Boolean, session: VaultSession, onChoose: (ItemSummary) -> Unit) {
    var logins by remember(requester) { mutableStateOf<List<ItemSummary>?>(null) }
    LaunchedEffect(requester) {
        session.loginsForWeb(requester.origin) { found ->
            if (codeOnly) session.withOneTimeCodes(found) { logins = it } else logins = found
        }
    }
    val shown = logins ?: return
    if (shown.isEmpty()) {
        Column(Modifier.padding(24.dp)) {
            Text(
                if (codeOnly) "No login with a one-time code for this site" else "No login for this site",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.testTag("no-logins"),
            )
            Text(
                "A login is offered only on the site it was saved for: over https, on the same host and port. " +
                    "Browsers on Android do not say which port a page uses, so a login saved for an unusual port is not offered here.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        return
    }
    LoginRows(shown, onChoose = onChoose)
}

@Composable
private fun AppLoginsList(
    requester: Requester.App,
    items: List<ItemSummary>,
    codeOnly: Boolean,
    appLogins: AppLogins,
    session: VaultSession,
    fill: (ItemSummary, String?, Boolean) -> Unit,
) {
    var logins by remember(requester) { mutableStateOf<List<ItemSummary>?>(null) }
    LaunchedEffect(items, codeOnly) {
        val all = items.filter { it.kind == ItemKind.LOGIN }
        if (codeOnly) session.withOneTimeCodes(all) { logins = it } else logins = all
    }
    val context = LocalContext.current
    val sites = remember(requester) { LinkedSites.of(context, requester.packageName) }
    val offered = logins ?: return
    val chosen = appLogins.chosen(requester)
    val remembered = offered.filter { it.id in chosen }
    // Saved for a site that says this app is its own: suggested, and the
    // app's once the owner chooses one.
    val linked = offered.filter { it.id !in chosen && LinkedSites.cover(sites, it.url) }
    var choosing by remember(requester) { mutableStateOf(false) }
    if (!choosing) {
        Column {
            LoginRows(remembered, Modifier.weight(1f, fill = false)) { item -> fill(item, null, false) }
            if (linked.isNotEmpty()) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 12.dp)) {
                    Text(
                        "For a site that names ${requester.label} as its app",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.testTag("linked"),
                    )
                    Text(
                        "Android checked with the site that this app is its own. A login you choose here is offered in this app from now on.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                LoginRows(linked, Modifier.weight(1f, fill = false)) { item -> fill(item, null, true) }
            }
            TextButton(
                onClick = { choosing = true },
                modifier = Modifier.padding(horizontal = 12.dp).testTag("choose-another"),
            ) { Text(if (remembered.isEmpty() && linked.isEmpty()) "Choose a login for this app…" else "Choose another login…") }
        }
        return
    }
    var query by remember(requester) { mutableStateOf("") }
    val shown = offered.filter {
        query.isBlank() || it.title.contains(query, ignoreCase = true) || it.username.contains(query, ignoreCase = true) ||
            it.url.contains(query, ignoreCase = true)
    }
    Column {
        Text(
            "An app cannot be checked against a login's address. Choose only a login meant for ${requester.label}: " +
                "it is offered to this app again, and to no other.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp).testTag("warning"),
        )
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("Search") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp).testTag("fill-search"),
        )
        LoginRows(shown) { item -> fill(item, null, true) }
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
