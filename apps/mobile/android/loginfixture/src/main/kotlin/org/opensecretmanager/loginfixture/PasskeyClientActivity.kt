package org.opensecretmanager.loginfixture

import android.app.Activity
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import java.security.SecureRandom
import org.json.JSONArray
import org.json.JSONObject

/**
 * An app that makes and uses a passkey through Android's Credential Manager,
 * as a site's own app does, for the passkey tests. Its extras say for which
 * site (`rp`, example.test if none), whether the owner is to be verified
 * (`verification`), which credential to exclude or allow (`exclude`,
 * `allow`), and whether it sends a client data hash of its own (`hash`),
 * which only a trusted browser may, and the challenge (`challenge`, a
 * random one if none). It shows the challenge it sent (`challenge`) and the
 * response, or `ERROR <type> <message>` (`result`).
 */
class PasskeyClientActivity : Activity() {
    private lateinit var challenge: TextView
    private lateinit var result: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val create = Button(this).apply { text = "Create passkey"; tag = "create"; setOnClickListener { create() } }
        val signIn = Button(this).apply { text = "Sign in with passkey"; tag = "sign-in"; setOnClickListener { signIn() } }
        challenge = TextView(this).apply { tag = "challenge" }
        result = TextView(this).apply { tag = "result"; setTextIsSelectable(true) }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
            listOf(create, signIn, challenge, result).forEach(::addView)
        })
        // The views by name, for UI Automator.
        create.contentDescription = "create"
        signIn.contentDescription = "sign-in"
        challenge.contentDescription = "challenge"
        result.contentDescription = "result"
    }

    private val rp get() = intent.getStringExtra("rp") ?: "example.test"
    private val verification get() = intent.getStringExtra("verification") ?: "preferred"

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun newChallenge(): String =
        (intent.getStringExtra("challenge") ?: b64(ByteArray(32).also(SecureRandom()::nextBytes))).also { challenge.text = it }

    private fun descriptors(extra: String) = JSONArray().apply {
        intent.getStringExtra(extra)?.let { put(JSONObject().put("type", "public-key").put("id", it)) }
    }

    /** A hash of its own, which the provider is to ignore. */
    private val hash: ByteArray? get() = if (intent.getBooleanExtra("hash", false)) ByteArray(32) { 0x5a } else null

    private fun create() {
        result.text = ""
        val options = JSONObject()
            .put("rp", JSONObject().put("id", rp).put("name", "Example"))
            .put("user", JSONObject().put("id", "AQIDBA").put("name", "fixture-user").put("displayName", "Fixture User"))
            .put("challenge", newChallenge())
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("timeout", 60000)
            .put("excludeCredentials", descriptors("exclude"))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", verification))
        CredentialManager.create(this).createCredentialAsync(
            this,
            CreatePublicKeyCredentialRequest(options.toString(), hash),
            null,
            mainExecutor,
            object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(response: CreateCredentialResponse) {
                    result.text = (response as? CreatePublicKeyCredentialResponse)?.registrationResponseJson ?: "ERROR not a passkey"
                }

                override fun onError(error: CreateCredentialException) {
                    val type = (error as? CreatePublicKeyCredentialDomException)?.domError?.type ?: error.type
                    result.text = "ERROR $type ${error.errorMessage}"
                }
            },
        )
    }

    private fun signIn() {
        result.text = ""
        val options = JSONObject()
            .put("challenge", newChallenge())
            .put("rpId", rp)
            .put("allowCredentials", descriptors("allow"))
            .put("userVerification", verification)
        CredentialManager.create(this).getCredentialAsync(
            this,
            GetCredentialRequest(listOf(GetPublicKeyCredentialOption(options.toString(), hash))),
            null,
            mainExecutor,
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(response: GetCredentialResponse) {
                    result.text = (response.credential as? PublicKeyCredential)?.authenticationResponseJson ?: "ERROR not a passkey"
                }

                override fun onError(error: GetCredentialException) {
                    val type = (error as? GetPublicKeyCredentialDomException)?.domError?.type ?: error.type
                    result.text = "ERROR $type ${error.errorMessage}"
                }
            },
        )
    }
}
