package org.opensecretmanager.app.passkey

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.opensecretmanager.app.R
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.vault.PasskeySignIn
import org.opensecretmanager.vault.checkPasskeyRequest

/**
 * Passkeys for Android's Credential Manager, from Android 14 on. Asked to
 * make one, it offers one place, the vault, whether it is locked or not.
 * Asked for one while the vault is locked, it says nothing of what the vault
 * holds: the only entry is "Unlock Open Secret Manager". While it is
 * unlocked, it names each passkey the vault holds for the site that asks.
 * Choosing an entry opens [PasskeyActivity], which unlocks, says who asks,
 * verifies the owner if the site wants it, and makes or signs. A request
 * this app does not answer, such as one for a site no passkey may be for,
 * or from an app that speaks for a page but is not a browser it trusts, is
 * left to the other providers.
 */
@RequiresApi(34)
class PasskeyProviderService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        val info = request.callingAppInfo
        val asker = (request as? BeginCreatePublicKeyCredentialRequest)?.let { create ->
            info?.let { PasskeyAsker.of(this, it, create.clientDataHash) }
                ?.takeIf { runCatching { checkPasskeyRequest(create.requestJson, it.caller, true) }.isSuccess }
        }
        if (asker == null || info?.packageName == packageName) return callback.onResult(BeginCreateCredentialResponse())
        val entry = CreateEntry(
            getString(R.string.passkey_account),
            PasskeyEntries.pending(this, Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.CREATE)),
            description = getString(R.string.passkey_saved_where),
        )
        callback.onResult(BeginCreateCredentialResponse(listOf(entry)))
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val info = request.callingAppInfo
        if (info == null || info.packageName == packageName) return callback.onResult(BeginGetCredentialResponse())
        val asked = PasskeyEntries.asked(this, request)
        if (asked.isEmpty()) return callback.onResult(BeginGetCredentialResponse())
        (application as VaultApp).session.offeredPasskeys(asked.map { (option, asker) -> option.requestJson to asker.caller }) { found ->
            callback.onResult(
                if (found == null) {
                    BeginGetCredentialResponse(
                        authenticationActions = listOf(
                            AuthenticationAction(
                                getString(R.string.passkey_unlock),
                                PasskeyEntries.pending(this, Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.UNLOCK)),
                            ),
                        ),
                    )
                } else {
                    PasskeyEntries.response(this, asked, found)
                },
            )
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // Nothing is kept of a sign-in to clear.
        callback.onResult(null)
    }
}

/** What the system's list shows for a request for a passkey, from the service and once [PasskeyActivity] unlocked. */
@RequiresApi(34)
internal object PasskeyEntries {
    /** Each entry's own request code, so that each keeps its own extras. */
    private val requests = AtomicInteger()

    /** Mutable, as the system adds the request to it; not one-shot, as an entry can be chosen again after going back. */
    fun pending(context: Context, intent: Intent): PendingIntent =
        PendingIntent.getActivity(context, requests.incrementAndGet(), intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    /** The requests for a passkey this app answers, each with who asks. */
    fun asked(context: Context, request: BeginGetCredentialRequest): List<Pair<BeginGetPublicKeyCredentialOption, PasskeyAsker>> {
        val info = request.callingAppInfo ?: return emptyList()
        val apps = PasskeyApps(context)
        return request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>().mapNotNull { option ->
            val asker = PasskeyAsker.of(context, info, option.clientDataHash) ?: return@mapNotNull null
            if (asker.requester is Requester.App) {
                val rpId = runCatching { JSONObject(option.requestJson).optString("rpId") }.getOrNull()?.trim().orEmpty()
                if (rpId.isEmpty() || (!apps.allowed(asker.requester, rpId) && !asker.linkedTo(rpId))) {
                    return@mapNotNull null
                }
            }
            asker.takeIf { runCatching { checkPasskeyRequest(option.requestJson, it.caller, false) }.isSuccess }
                ?.let { option to it }
        }
    }

    /** An entry for each passkey [found] names for its request. */
    fun response(
        context: Context,
        asked: List<Pair<BeginGetPublicKeyCredentialOption, PasskeyAsker>>,
        found: List<PasskeySignIn?>,
    ): BeginGetCredentialResponse {
        val apps = PasskeyApps(context)
        return BeginGetCredentialResponse(
            credentialEntries = asked.zip(found).flatMap { (request, signIn) ->
                val asker = request.second
                val app = asker.requester as? Requester.App
                if (signIn == null || (app != null && !apps.allowed(app, signIn.rpId) && !asker.linkedTo(signIn.rpId))) {
                    emptyList()
                } else {
                    signIn.passkeys.map { passkey ->
                        val intent = Intent(context, PasskeyActivity::class.java)
                            .setAction(PasskeyActivity.GET)
                            .putExtra(PasskeyActivity.ITEM, passkey.itemId)
                            .putExtra(PasskeyActivity.CREDENTIAL, passkey.credentialId)
                        PublicKeyCredentialEntry(
                            context,
                            passkey.userName.ifEmpty { passkey.title },
                            pending(context, intent),
                            request.first,
                            displayName = passkey.userDisplayName.takeIf { it.isNotEmpty() && it != passkey.userName },
                        )
                    }
                }
            },
        )
    }
}
