package org.opensecretmanager.app.passkey

import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.os.SystemClock
import org.opensecretmanager.app.OsmTheme
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.domerrors.DataError
import androidx.credentials.exceptions.domerrors.DomError
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.domerrors.SecurityError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.PendingIntentHandler
import org.opensecretmanager.app.BiometricUnlock
import org.opensecretmanager.app.Busy
import org.opensecretmanager.app.FingerprintPrompts
import org.opensecretmanager.app.Message
import org.opensecretmanager.app.ProtectedActivity
import org.opensecretmanager.app.Screen
import org.opensecretmanager.app.UiState
import org.opensecretmanager.app.Unlock
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.VaultSession
import org.opensecretmanager.app.autofill.Asker
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.app.screenState
import org.opensecretmanager.vault.MobileException
import org.opensecretmanager.vault.PasskeyCreation
import org.opensecretmanager.vault.PasskeyRefusal
import org.opensecretmanager.vault.PasskeySignIn
import org.opensecretmanager.vault.PasskeyVerification

/**
 * Where a passkey is made or used, after the owner chose this app in the
 * system's list: unlock if the vault is locked, see who asks, and, for a
 * new passkey, choose where it goes. An app that is not a browser is named
 * as such the first time it asks for a site's passkeys, with whether
 * Android verified the site names it as its own; the owner's choice is
 * remembered for that app and site only after verification and signing
 * succeed. The owner is verified when the site asks for it and does not
 * refuse it: an explicit unlock performed inside this screen verifies the
 * owner once within [UNLOCK_VERIFICATION_TTL_MS], and otherwise a Class 3
 * strong biometric (`BIOMETRIC_STRONG`) or this phone's vault password does,
 * every time; nothing is said to be verified that was not.
 */
@RequiresApi(34)
class PasskeyActivity : ProtectedActivity() {
    private lateinit var session: VaultSession
    private lateinit var asked: Asked

    /**
     * Monotonic timestamp when the owner explicitly unlocked the vault inside
     * this Activity instance. Cleared on [onStop] and consumed once by
     * [consumeUnlockedHere] so an external unlock cannot spoof UV=1.
     */
    private var unlockedInActivityAt: Long? = null

    /** Pending vault-password verification fallback when strong biometrics are unavailable or declined. */
    internal var verifyPasswordPrompt by mutableStateOf<VerifyPasswordRequest?>(null)
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        session = (application as VaultApp).session
        if (savedInstanceState == null) session.askAtOnceNext()
        asked = read(intent) ?: return finish()
        val current = asked
        if (current is Asked.Get && session.state.value.screen == Screen.UNLOCKED && passkeyAllowed(current.asker, null)) {
            // Chosen from an unlocked vault: nothing drawn but the check.
            background = window.decorView.background
            window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            return signIn(current)
        }
        show()
    }

    override fun onStop() {
        super.onStop()
        unlockedInActivityAt = null
    }

    /** What [onCreate] drew over, while nothing is drawn. */
    private var background: android.graphics.drawable.Drawable? = null

    private fun show() {
        background?.let(window::setBackgroundDrawable)
        background = null
        val biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session, asked.asker?.requester?.said, ::markUnlockedHere)
        setContent {
            OsmTheme {
                PasskeyScreen(asked, session, biometric, prompts, this)
            }
        }
    }

    /** What the system asked of the entry the owner chose. */
    private fun read(intent: Intent): Asked? = when (intent.action) {
        CREATE -> PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)?.let { request ->
            val create = request.callingRequest as? CreatePublicKeyCredentialRequest ?: return@let null
            PasskeyAsker.of(this, request.callingAppInfo, create.clientDataHash)?.let { Asked.Create(create.requestJson, it, create.isConditional) }
        }
        GET -> PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)?.let { request ->
            val option = request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull() ?: return@let null
            val item = intent.getStringExtra(ITEM) ?: return@let null
            val credential = intent.getStringExtra(CREDENTIAL) ?: return@let null
            PasskeyAsker.of(this, request.callingAppInfo, option.clientDataHash)?.let { Asked.Get(option.requestJson, it, item, credential) }
        }
        UNLOCK -> PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)?.let { Asked.Unlock(it) }
        else -> null
    }

    /** Whether the app asking may use [rpId]'s passkeys without asking the owner first: a page of a trusted browser always may. */
    internal fun passkeyAllowed(asker: PasskeyAsker, rpId: String?): Boolean {
        val app = asker.requester as? Requester.App ?: return true
        return rpId != null && PasskeyApps(this).allowed(app, rpId)
    }

    internal fun allow(asker: PasskeyAsker, rpId: String) {
        (asker.requester as? Requester.App)?.let { PasskeyApps(this).allow(it, rpId) }
    }

    /** Records an explicit unlock completed inside this Activity. */
    internal fun markUnlockedHere() {
        unlockedInActivityAt = SystemClock.elapsedRealtime()
    }

    /** Consumes a fresh in-activity unlock once for user verification. */
    private fun consumeUnlockedHere(): Boolean {
        val at = unlockedInActivityAt ?: return false
        unlockedInActivityAt = null
        return session.state.value.screen == Screen.UNLOCKED &&
            SystemClock.elapsedRealtime() - at <= UNLOCK_VERIFICATION_TTL_MS
    }

    private fun askVaultPassword(title: String, done: (Boolean) -> Unit) {
        verifyPasswordPrompt = VerifyPasswordRequest(title, done)
        if (background != null) show()
    }

    internal fun finishPasswordVerification(password: String) {
        val pending = verifyPasswordPrompt ?: return
        if (pending.submitting) return
        verifyPasswordPrompt = pending.copy(submitting = true)
        session.verifyVaultPassword(password) { verified ->
            if (verified) {
                pending.done(true)
            } else {
                verifyPasswordPrompt = null
                cancel()
            }
        }
    }

    /**
     * Verifies the owner as the site asks, then [done] with whether the owner
     * was verified, or ends the request if the owner cancelled. Only Class 3
     * strong biometrics (`BIOMETRIC_STRONG`) or this phone's vault password
     * satisfy user verification (never weak device credentials).
     */
    internal fun verify(verification: PasskeyVerification, title: String, done: (Boolean) -> Unit) {
        if (consumeUnlockedHere()) return done(true)
        if (verification == PasskeyVerification.DISCOURAGED) return done(false)
        val canStrong = BiometricManager.from(this).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        if (!canStrong) {
            if (verification == PasskeyVerification.PREFERRED) return done(false)
            return askVaultPassword(title, done)
        }
        BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = done(true)

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        askVaultPassword(title, done)
                    } else {
                        cancel()
                    }
                }
            },
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(asked.asker?.requester?.said ?: "")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setNegativeButtonText("Use vault password")
                .build(),
        )
    }

    /** Signs in with the passkey the owner chose, once the site's request is read and the owner verified. */
    internal fun signIn(get: Asked.Get, allowOnSuccess: Boolean = false) {
        session.forPasskey({ it.passkeySignIn(get.options, get.asker.caller) }) { read ->
            val signIn = read.getOrElse { error ->
                // Locked since the system's list: unlocked here, then signed.
                if (error is MobileException.Locked && background != null) {
                    return@forPasskey show()
                }
                return@forPasskey fail(error)
            }
            if (signIn.passkeys.none { it.itemId == get.item && it.credentialId == get.credential }) {
                return@forPasskey fail(NotAllowedError(), "That passkey is not one this site takes")
            }
            verify(signIn.verification, "Sign in to ${signIn.rpId}") { verified ->
                session.forPasskey({ it.signInWithPasskey(get.options, get.asker.caller, get.item, get.credential, verified) }) { signed ->
                    signed.onSuccess { json ->
                        if (allowOnSuccess) allow(get.asker, signIn.rpId)
                        signedIn(json)
                    }.onFailure(::fail)
                }
            }
        }
    }

    /** Makes the passkey once the owner chose to save it, into the login [into] or a new one. */
    internal fun create(create: Asked.Create, creation: PasskeyCreation, into: String?) {
        verify(creation.verification, "Save a passkey for ${creation.rpId}") { verified ->
            session.forPasskey({ it.createPasskey(create.options, create.asker.caller, verified, into) }) { made ->
                made.onSuccess { json ->
                    allow(create.asker, creation.rpId)
                    created(json)
                }.onFailure(::fail)
            }
        }
    }

    /** After an unlock that the system's list asked for: the passkeys for the site, in the list. */
    internal fun unlocked(unlock: Asked.Unlock) {
        val requests = PasskeyEntries.asked(this, unlock.request)
        session.forPasskey({ device -> requests.map { (option, asker) -> runCatching { device.passkeySignIn(option.requestJson, asker.caller) }.getOrNull() } }) { found ->
            val result = Intent()
            PendingIntentHandler.setBeginGetCredentialResponse(result, PasskeyEntries.response(this, requests, found.getOrElse { emptyList<PasskeySignIn?>() }))
            setResult(RESULT_OK, result)
            finish()
        }
    }

    private fun created(json: String) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(json))
        setResult(RESULT_OK, result)
        finish()
    }

    private fun signedIn(json: String) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(json)))
        setResult(RESULT_OK, result)
        finish()
    }

    /** Ends the request with what failed, as the site is told it. */
    internal fun fail(error: Throwable) {
        val reason = (error as? MobileException)?.message ?: error.message
        when (error) {
            is MobileException.PasskeyRefused -> fail(
                when (error.refusal) {
                    PasskeyRefusal.SITE -> SecurityError()
                    PasskeyRefusal.ALGORITHM -> NotSupportedError()
                    PasskeyRefusal.MALFORMED -> DataError()
                },
                error.reason,
            )
            is MobileException.PasskeyExists -> fail(InvalidStateError(), "Your vault already has a passkey for this account")
            is MobileException.NotVerified -> fail(NotAllowedError(), "The site asks to verify it is you")
            else -> {
                val result = Intent()
                when (asked) {
                    is Asked.Create -> PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException(reason))
                    else -> PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException(reason))
                }
                setResult(RESULT_OK, result)
                finish()
            }
        }
    }

    internal fun fail(error: DomError, reason: String?) {
        val result = Intent()
        when (asked) {
            is Asked.Create -> PendingIntentHandler.setCreateCredentialException(result, CreatePublicKeyCredentialDomException(error, reason))
            else -> PendingIntentHandler.setGetCredentialException(result, GetPublicKeyCredentialDomException(error, reason))
        }
        setResult(RESULT_OK, result)
        finish()
    }

    /** The owner said no: the app is told the request was cancelled. */
    internal fun cancel() {
        val result = Intent()
        when (asked) {
            is Asked.Create -> PendingIntentHandler.setCreateCredentialException(result, CreateCredentialCancellationException())
            is Asked.Get -> PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
            is Asked.Unlock -> return finish()
        }
        setResult(RESULT_OK, result)
        finish()
    }

    companion object {
        const val CREATE = "org.opensecretmanager.app.passkey.CREATE"
        const val GET = "org.opensecretmanager.app.passkey.GET"
        const val UNLOCK = "org.opensecretmanager.app.passkey.UNLOCK"
        /** For [GET]: the login and the passkey the owner chose. */
        const val ITEM = "item"
        const val CREDENTIAL = "credential"
        /** Maximum age of an in-activity unlock counted as fresh user verification. */
        private const val UNLOCK_VERIFICATION_TTL_MS = 60_000L
    }
}

internal data class VerifyPasswordRequest(
    val title: String,
    val done: (Boolean) -> Unit,
    val submitting: Boolean = false,
)

/** What the system asked for. */
internal sealed interface Asked {
    val asker: PasskeyAsker?

    /** A new passkey, from a site's `PublicKeyCredentialCreationOptionsJSON`. */
    data class Create(val options: String, override val asker: PasskeyAsker, val conditional: Boolean) : Asked

    /** A sign-in with the passkey the owner chose, from `PublicKeyCredentialRequestOptionsJSON`. */
    data class Get(val options: String, override val asker: PasskeyAsker, val item: String, val credential: String) : Asked

    /** The vault unlocked, for the system's list to name the passkeys. */
    data class Unlock(val request: BeginGetCredentialRequest) : Asked {
        override val asker: PasskeyAsker? get() = null
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
private fun PasskeyScreen(
    asked: Asked,
    session: VaultSession,
    biometric: BiometricUnlock,
    prompts: FingerprintPrompts,
    activity: PasskeyActivity,
) {
    val state by session.screenState()
    val passwordPrompt = activity.verifyPasswordPrompt
    Scaffold(
        // Tags as resource ids: the tests drive this screen from outside the
        // app, as the system shows it over another one.
        modifier = Modifier.semantics { testTagsAsResourceId = true },
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when (asked) {
                            is Asked.Create -> "Save a passkey"
                            is Asked.Get -> "Sign in with a passkey"
                            is Asked.Unlock -> "Unlock for passkeys"
                        },
                    )
                },
                actions = { TextButton(onClick = activity::cancel, modifier = Modifier.testTag("cancel")) { Text("Cancel") } },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when {
                passwordPrompt != null -> VerifyPasswordScreen(passwordPrompt, asked.asker?.requester, state, activity)
                state.screen == Screen.OPENING -> Message("Opening…")
                state.screen == Screen.LOCKED -> Column {
                    asked.asker?.let { Asker(it.requester) }
                    Unlock(state, session, biometric, prompts::unlock, prompts::keep, activity::markUnlockedHere)
                }
                state.screen == Screen.UNLOCKED -> Unlocked(asked, session, activity)
                state.screen == Screen.REMOVED -> Message("This phone was removed from the vault")
                state.screen == Screen.UNREADABLE -> Message("The vault on this phone cannot be opened", state.unreadable)
                else -> Message("This phone has no vault yet", "Join your vault in Open Secret Manager first.")
            }
            state.busy?.let { Busy(it) }
        }
    }
}

@Composable
private fun VerifyPasswordScreen(
    request: VerifyPasswordRequest,
    requester: Requester?,
    state: UiState,
    activity: PasskeyActivity,
) {
    var password by remember { mutableStateOf("") }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        requester?.let { Asker(it) }
        Column(
            Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(request.title, style = MaterialTheme.typography.titleMedium)
            Text(
                "Enter this phone's vault password to verify it is you.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Vault password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth().testTag("verify-password"),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = {
                        val typed = password
                        password = ""
                        activity.finishPasswordVerification(typed)
                    },
                    enabled = password.isNotEmpty() && !request.submitting && state.busy == null,
                    modifier = Modifier.testTag("verify-password-confirm"),
                ) {
                    Text("Verify")
                }
                TextButton(onClick = activity::cancel) {
                    Text("Cancel")
                }
            }
        }
    }
}

/** Once the vault is open: what the request needs of the owner. */
@Composable
private fun Unlocked(asked: Asked, session: VaultSession, activity: PasskeyActivity) {
    when (asked) {
        is Asked.Unlock -> {
            LaunchedEffect(Unit) { activity.unlocked(asked) }
            Busy("Opening…")
        }
        is Asked.Get -> {
            // The site's request read, to name it for an app not yet allowed.
            var signIn by remember { mutableStateOf<PasskeySignIn?>(null) }
            LaunchedEffect(Unit) {
                session.forPasskey({ it.passkeySignIn(asked.options, asked.asker.caller) }) { read ->
                    read.onSuccess { found ->
                        if (activity.passkeyAllowed(asked.asker, found.rpId)) activity.signIn(asked) else signIn = found
                    }.onFailure(activity::fail)
                }
            }
            val found = signIn ?: return Busy("Opening…")
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Asker(asked.asker.requester)
                AppWarning(asked.asker, found.rpId, "to sign in to ${found.rpId} with a passkey")
                Row(Modifier.padding(24.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = { activity.signIn(asked, allowOnSuccess = true) }, modifier = Modifier.testTag("allow-passkey")) {
                        Text("Sign in")
                    }
                }
            }
        }
        is Asked.Create -> {
            var creation by remember { mutableStateOf<PasskeyCreation?>(null) }
            LaunchedEffect(Unit) {
                if (asked.conditional) return@LaunchedEffect activity.fail(NotAllowedError(), "A passkey is made here only when you choose to")
                session.forPasskey({ it.passkeyCreation(asked.options, asked.asker.caller) }) { read ->
                    read.onSuccess { creation = it }.onFailure(activity::fail)
                }
            }
            val shown = creation ?: return Busy("Opening…")
            SaveChoice(asked, shown, activity)
        }
    }
}

/** For an app that is not a browser, the first time it asks for a site's passkeys: what that means. */
@Composable
private fun AppWarning(asker: PasskeyAsker, rpId: String, asks: String) {
    val app = asker.requester as? Requester.App ?: return
    Column(Modifier.padding(horizontal = 24.dp, vertical = 12.dp).testTag("app-warning")) {
        Text(
            "${app.label} is an app, not a browser, and asks $asks. Go on only if it is that site's own app.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            if (asker.linkedTo(rpId)) {
                "Android verified that $rpId names this app as its own."
            } else {
                "Android has not verified that $rpId names this app as its own."
            },
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp).testTag("linked"),
        )
    }
    HorizontalDivider()
}

/** Where a new passkey goes: a new login for the site, or one of its logins. */
@Composable
private fun SaveChoice(create: Asked.Create, creation: PasskeyCreation, activity: PasskeyActivity) {
    var into by remember { mutableStateOf<String?>(null) }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        Asker(create.asker.requester)
        if (!activity.passkeyAllowed(create.asker, creation.rpId)) AppWarning(create.asker, creation.rpId, "to save a passkey for ${creation.rpId}")
        Column(Modifier.padding(horizontal = 24.dp, vertical = 12.dp)) {
            Text("For ${creation.rpId}", style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("passkey-site"))
            Text(
                listOf(creation.userName, creation.userDisplayName).filter { it.isNotEmpty() }.distinct().joinToString(" · ").ifEmpty { "No account name" },
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag("passkey-account"),
            )
        }
        HorizontalDivider()
        Choice("A new login for ${creation.rpId}", null, into == null, "save-new") { into = null }
        creation.logins.forEach { login ->
            Choice("Add to ${login.title}", login.username, into == login.id, "save-into:${login.title}") { into = login.id }
        }
        Row(Modifier.padding(24.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { activity.create(create, creation, into) }, modifier = Modifier.testTag("save-passkey")) { Text("Save") }
        }
    }
}

@Composable
private fun Choice(title: String, below: String?, chosen: Boolean, tag: String, onChoose: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onChoose).padding(horizontal = 12.dp, vertical = 4.dp).testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = chosen, onClick = onChoose)
        Column {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            below?.takeIf { it.isNotEmpty() }?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
