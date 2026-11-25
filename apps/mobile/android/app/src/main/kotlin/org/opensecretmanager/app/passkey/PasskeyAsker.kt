package org.opensecretmanager.app.passkey

import android.content.Context
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import java.security.MessageDigest
import org.opensecretmanager.app.R
import org.opensecretmanager.app.autofill.LinkedSites
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.vault.PasskeyCaller

/**
 * Who asks for a passkey, from what Android says of the app that called its
 * Credential Manager. A page's origin is believed only from a browser on the
 * list Google publishes for this (`res/raw/privileged_browsers.json`, the
 * apps of `trusted_browsers.json`), which the library checks against the
 * browser's certificate as installed; only then is the client data the
 * browser made used. Any other app is itself, by its signing certificate:
 * whatever client data it sends is ignored, and its own is made, so it
 * cannot speak for a site's pages.
 */
internal class PasskeyAsker(
    /** As the fill screens name who asks. */
    val requester: Requester,
    val caller: PasskeyCaller,
    /** For an app, the sites Android verified name it as theirs ([LinkedSites]). */
    val linkedSites: Set<String>,
) {
    /** Whether Android verified that [rpId] itself (exact host match) names this app as its own. */
    fun linkedTo(rpId: String): Boolean {
        val norm = rpId.lowercase()
        return norm.isNotEmpty() && linkedSites.any { it == norm }
    }

    companion object {
        /**
         * Who asks, or null for an app that says it speaks for a page but is
         * not a browser this app trusts to: its request is left to others.
         */
        @RequiresApi(34)
        fun of(context: Context, info: CallingAppInfo, clientDataHash: ByteArray?): PasskeyAsker? {
            val label = runCatching {
                val manager = context.packageManager
                manager.getApplicationLabel(manager.getApplicationInfo(info.packageName, 0)).toString()
            }.getOrDefault(info.packageName)
            if (info.isOriginPopulated()) {
                val origin = runCatching { info.getOrigin(allowlist(context)) }.getOrNull() ?: return null
                return PasskeyAsker(
                    Requester.Web(origin.trimEnd('/'), info.packageName, label),
                    PasskeyCaller.Page(origin, clientDataHash),
                    emptySet(),
                )
            }
            val signing = info.signingInfoCompat
            // The origin is the current certificate's, as Android's guide has
            // it; the app is remembered by its canonical signing identity
            // (original signer for single-signer, combined digest for multi-signer).
            val current = signing.apkContentsSigners.firstOrNull() ?: return null
            val appCertificate = Requester.canonicalCertificateId(
                hasMultipleSigners = signing.hasMultipleSigners,
                apkContentsSigners = signing.apkContentsSigners.map { it.toByteArray() },
                signingCertificateHistory = signing.signingCertificateHistory.map { it.toByteArray() },
            ) ?: return null
            val sha256 = { bytes: ByteArray -> MessageDigest.getInstance("SHA-256").digest(bytes) }
            return PasskeyAsker(
                Requester.App(info.packageName, label, appCertificate, null),
                PasskeyCaller.App(sha256(current.toByteArray())),
                LinkedSites.exactOf(context, info.packageName),
            )
        }

        @Volatile private var list: String? = null

        private fun allowlist(context: Context): String =
            list ?: context.resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }.also { list = it }
    }
}

/**
 * The sites the owner let an app that is not a browser use passkeys of, on
 * this phone only, by the app's package and signing certificate, as
 * [org.opensecretmanager.app.autofill.AppLogins] keeps the logins chosen for
 * an app: another app under the same name, signed by someone else, is asked
 * about again.
 */
internal class PasskeyApps(context: Context) {
    private val preferences = context.getSharedPreferences("passkey-apps", Context.MODE_PRIVATE)

    private fun key(app: Requester.App) = "${app.packageName}:${app.certificate}"

    fun allowed(app: Requester.App, rpId: String): Boolean =
        rpId.lowercase() in preferences.getStringSet(key(app), emptySet()).orEmpty()

    fun allow(app: Requester.App, rpId: String) {
        val norm = rpId.lowercase()
        preferences.edit().putStringSet(key(app), preferences.getStringSet(key(app), emptySet()).orEmpty() + norm).apply()
    }
}
