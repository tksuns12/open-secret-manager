package org.opensecretmanager.app.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import org.opensecretmanager.app.BiometricUnlock
import org.opensecretmanager.app.BuildConfig
import org.opensecretmanager.app.Busy
import org.opensecretmanager.app.FingerprintPrompts
import org.opensecretmanager.app.Generator
import org.opensecretmanager.app.GeneratorOptions
import org.opensecretmanager.app.Message
import org.opensecretmanager.app.R
import org.opensecretmanager.app.Screen
import org.opensecretmanager.app.Unlock
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.VaultSession
import org.opensecretmanager.app.screenState
import org.opensecretmanager.vault.Asks
import org.opensecretmanager.vault.PasswordOptions
import org.opensecretmanager.vault.generatePassword

/**
 * Where the owner makes a strong password for a sign-up or a change of
 * password, after choosing "make a strong password" in the form's offer:
 * unlock, see who asks, see the password made with the generator's choice
 * (made again, or with another choice, at will), and choose where it goes,
 * as on the save screen ([SaveChoices]). It is saved then, before the form
 * is sent: Android offers no save for values a fill put there unchanged.
 * Then the form's new password fields get it, and its username field the
 * username, if one is given here.
 */
class GenerateActivity : FragmentActivity() {
    private lateinit var form: Form

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setResult(RESULT_CANCELED)
        form = intent.extras?.let(Form::fromBundle)?.takeIf { it.newPasswords.isNotEmpty() } ?: return finish()
        val session = (application as VaultApp).session
        if (savedInstanceState == null) session.askAtOnceNext()
        val requester = Requester.of(this, form)
        // The username as the screen was when the form asked: Android shows
        // this screen nothing typed after that.
        @Suppress("DEPRECATION")
        val structure = intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        val typed = form.username?.let { id -> structure?.let { Form.values(it, setOf(id))[id] } }.orEmpty()
        val biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session, requester?.said)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                GenerateScreen(
                    form = form,
                    requester = requester,
                    typed = typed,
                    session = session,
                    biometric = biometric,
                    prompts = prompts,
                    onSaved = ::finishWith,
                    onCancel = ::finish,
                )
            }
        }
    }

    /** Hands the password made, and the username, to the form, which fills them at once. */
    private fun finishWith(username: String, password: String, told: String?) {
        val values = buildList {
            form.username?.takeIf { username.isNotEmpty() }?.let { add(it to username) }
            form.newPasswords.forEach { add(it to password) }
        }
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(entry(this, getString(R.string.app_name), username.ifEmpty { null })).apply {
            values.forEach { (id, value) -> setValue(id, AutofillValue.forText(value)) }
        }.build()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        told?.let { Toast.makeText(applicationContext, it, Toast.LENGTH_LONG).show() }
        finish()
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
private fun GenerateScreen(
    form: Form,
    requester: Requester?,
    typed: String,
    session: VaultSession,
    biometric: BiometricUnlock,
    prompts: FingerprintPrompts,
    onSaved: (String, String, String?) -> Unit,
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
                title = { Text("Make a strong password") },
                actions = { TextButton(onClick = onCancel, modifier = Modifier.testTag("cancel")) { Text("Cancel") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when {
                requester == null -> Message(
                    "Nothing to make",
                    "Open Secret Manager cannot tell which app asks, so it makes nothing for it.",
                )
                state.screen == Screen.OPENING -> Message("Opening…")
                state.screen == Screen.LOCKED -> Column {
                    Asker(requester)
                    Unlock(state, session, biometric, prompts::unlock, prompts::keep)
                }
                state.screen == Screen.UNLOCKED -> Column {
                    Asker(requester)
                    Made(form, requester, typed, session, state.busy == null, onSaved)
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
 * The username and the password made, which the owner can make again or
 * with another choice, and where they go. A field that takes fewer
 * characters than chosen gets a password of its length, since the form
 * would cut a longer one and the vault keep what the site never got.
 */
@Composable
private fun Made(
    form: Form,
    requester: Requester,
    typed: String,
    session: VaultSession,
    idle: Boolean,
    onSaved: (String, String, String?) -> Unit,
) {
    val context = LocalContext.current
    var options by remember { mutableStateOf(Generator.options(context)) }
    val cap = form.newPasswordMaxLength
    fun capped(choice: PasswordOptions): PasswordOptions {
        val kinds = listOf(choice.lowercase, choice.uppercase, choice.digits, choice.symbols).count { it }
        return if (cap > 0 && choice.length.toInt() > cap) choice.copy(length = maxOf(cap, kinds).toUInt()) else choice
    }
    fun make(choice: PasswordOptions) = runCatching { generatePassword(capped(choice)) }.getOrDefault("")
    var password by remember { mutableStateOf(make(options)) }
    var username by remember { mutableStateOf(typed) }
    var optionsOpen by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (form.username != null) {
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("generate-username"),
            )
            if (typed.isEmpty()) {
                Text(
                    "Android shows this screen nothing typed in the form: type the username here to save it with the password.",
                    style = MaterialTheme.typography.bodySmall,
                )
                // Or choose one of the accounts saved for here, for a change
                // of password.
                var accounts by remember { mutableStateOf(emptyList<String>()) }
                LaunchedEffect(requester) {
                    session.offered(requester.asked(), Asks.LOGIN) { logins ->
                        accounts = logins.orEmpty().map { it.username }.filter { it.isNotEmpty() }.distinct()
                    }
                }
                if (accounts.isNotEmpty()) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        accounts.forEach { account ->
                            TextButton(onClick = { username = account }, modifier = Modifier.testTag("account:$account")) { Text(account) }
                        }
                    }
                }
            }
        }
        Column {
            Text("Password", style = MaterialTheme.typography.labelMedium)
            Text(password, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace, modifier = Modifier.testTag("generated-password"))
            if (capped(options).length != options.length) {
                Text(
                    "This field takes at most $cap characters, so the password has ${capped(options).length}.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("generated-capped"),
                )
            }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            TextButton(onClick = { password = make(options) }, modifier = Modifier.testTag("regenerate")) { Text("Make another") }
            TextButton(onClick = { optionsOpen = !optionsOpen }, modifier = Modifier.testTag("generator-open")) {
                Text(if (optionsOpen) "Close options" else "Options")
            }
        }
        if (optionsOpen) {
            // Each change makes the password again with it.
            GeneratorOptions(options) {
                Generator.set(context, it)
                options = it
                password = make(it)
            }
        }
        SaveChoices(username, password, requester, session, idle, made = true) { told ->
            onSaved(username, password, told)
        }
    }
}
