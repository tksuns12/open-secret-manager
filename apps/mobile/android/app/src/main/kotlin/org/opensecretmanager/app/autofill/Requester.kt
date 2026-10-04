package org.opensecretmanager.app.autofill

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest
import org.json.JSONObject
import org.opensecretmanager.app.R

/**
 * Who asks for a login. A web page's origin is believed only from an app
 * on the list of those trusted to report it, checked by its signing
 * certificate as installed: any app can claim a domain in its own views.
 * Every other request is an app's, known by its package and certificate.
 */
sealed interface Requester {
    /**
     * A page of `origin` (`https://host`), shown by a trusted browser. A
     * browser reports the page's host and scheme only, not its port.
     */
    data class Web(val origin: String, val browser: String, val browserLabel: String) : Requester

    /**
     * An app, by its package and the SHA-256 of its signing certificate.
     * [claimedDomain] is the web domain it says it shows, if any: not
     * believed, it only narrows which logins the owner chose are offered.
     */
    data class App(val packageName: String, val label: String, val certificate: String, val claimedDomain: String?) : Requester

    companion object {
        /** Packages trusted as browsers in tests only, whatever their certificate. */
        internal val trustedForTests = mutableSetOf<String>()

        fun of(context: Context, form: Form): Requester? {
            val certificates = certificates(context, form.packageName)
            val domain = form.webDomain?.takeIf { it.isNotBlank() }
            val label = runCatching {
                val manager = context.packageManager
                manager.getApplicationLabel(manager.getApplicationInfo(form.packageName, 0)).toString()
            }.getOrDefault(form.packageName)
            // Pages over https only, as on the desktop.
            if (domain != null && form.webScheme == "https" && trusts(context, form.packageName, certificates)) {
                return Web("https://${domain.lowercase()}", form.packageName, label)
            }
            // The original certificate, which stays first in its history when
            // the app moves to a new one: the app keeps its identity here.
            val certificate = certificates.firstOrNull() ?: return null
            return App(form.packageName, label, certificate, domain?.lowercase())
        }

        private fun trusts(context: Context, packageName: String, certificates: Set<String>): Boolean {
            if (packageName in trustedForTests) return true
            val list = context.resources.openRawResource(R.raw.trusted_browsers).bufferedReader().use { JSONObject(it.readText()) }
            val apps = list.getJSONArray("apps")
            for (index in 0 until apps.length()) {
                val app = apps.getJSONObject(index)
                if (app.getString("package") != packageName) continue
                val trusted = app.getJSONArray("sha256")
                return (0 until trusted.length()).any { trusted.getString(it) in certificates }
            }
            return false
        }

        /**
         * The SHA-256 of each certificate the installed package is signed
         * with, in hex: its rotation history from the original on, or each
         * of several signers.
         */
        fun certificates(context: Context, packageName: String): Set<String> {
            val info = runCatching {
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            }.getOrNull() ?: return emptySet()
            val signing = info.signingInfo ?: return emptySet()
            val signatures = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
            return signatures.orEmpty().map { signature ->
                MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02X".format(it) }
            }.toSet()
        }
    }
}
