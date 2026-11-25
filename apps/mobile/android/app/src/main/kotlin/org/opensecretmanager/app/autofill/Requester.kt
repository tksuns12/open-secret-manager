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
 * What each is offered, filled, and saved into is the vault's to decide
 * ([asked]).
 */
sealed interface Requester {
    /**
     * Who asks, as the vault decides by: a page by its origin, an app by
     * its [App.key]. [linkedDomains], for an app, are the domains of its
     * links that Android verified ([LinkedSites]), whose logins the fill
     * screen suggests.
     */
    fun asked(linkedDomains: List<String> = emptyList()): org.opensecretmanager.vault.Requester = when (this) {
        is Web -> org.opensecretmanager.vault.Requester.Page(listOf(origin))
        is App -> org.opensecretmanager.vault.Requester.App(key, linkedDomains)
    }

    /**
     * What a new login from here is called at first: the page's host, or
     * the domain an app says it shows, without `www.`, or else the app's
     * name.
     */
    val title: String
        get() = when (this) {
            is Web -> origin.removePrefix("https://").removePrefix("www.")
            is App -> claimedDomain?.removePrefix("www.") ?: label
        }

    /** Who asks, in a line: under a fingerprint prompt, which covers the screen that names them. */
    val said: String
        get() = when (this) {
            is Web -> "For ${origin.removePrefix("https://")}, in $browserLabel"
            is App -> "For the app $label"
        }

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
    data class App(val packageName: String, val label: String, val certificate: String, val claimedDomain: String?) : Requester {
        /** What the vault keeps the logins chosen for this app by, on this phone only. */
        val key: String get() = "$packageName:$certificate" + (claimedDomain?.let { ":$it" } ?: "")
    }

    companion object {
        /** Packages trusted as browsers in tests only, whatever their certificate. */
        internal val trustedForTests = mutableSetOf<String>()

        @Volatile private var trustedBrowsers: Map<String, Set<String>>? = null

        fun of(context: Context, form: Form): Requester? = of(context, form.packageName, form.webDomain, form.webScheme)

        fun of(context: Context, form: CardForm): Requester? = of(context, form.packageName, form.webDomain, form.webScheme)

        internal fun of(context: Context, packageName: String, webDomain: String?, webScheme: String?): Requester? {
            val certificates = certificates(context, packageName)
            val domain = webDomain?.takeIf { it.isNotBlank() }
            val label = runCatching {
                val manager = context.packageManager
                manager.getApplicationLabel(manager.getApplicationInfo(packageName, 0)).toString()
            }.getOrDefault(packageName)
            // Branch on trusted browsers FIRST: a trusted browser without a
            // valid https webDomain (chrome://, about:blank, file://, http://,
            // or a missing webDomain) must NEVER fall through to Requester.App.
            if (trusts(context, packageName, certificates)) {
                if (domain == null || !webScheme.equals("https", ignoreCase = true)) return null
                return Web("https://${domain.lowercase()}", packageName, label)
            }
            // The original certificate, which stays first in its history when
            // the app moves to a new one: the app keeps its identity here.
            val certificate = certificates.firstOrNull() ?: return null
            return App(packageName, label, certificate, domain?.lowercase())
        }

        private fun trustedMap(context: Context): Map<String, Set<String>> =
            trustedBrowsers ?: synchronized(this) {
                trustedBrowsers ?: run {
                    val list = context.resources.openRawResource(R.raw.trusted_browsers).bufferedReader().use { JSONObject(it.readText()) }
                    val apps = list.getJSONArray("apps")
                    buildMap {
                        for (index in 0 until apps.length()) {
                            val app = apps.getJSONObject(index)
                            val pkg = app.getString("package")
                            val hashes = app.getJSONArray("sha256")
                            put(pkg, (0 until hashes.length()).map { hashes.getString(it) }.toSet())
                        }
                    }.also { trustedBrowsers = it }
                }
            }

        private fun trusts(context: Context, packageName: String, certificates: Set<String>): Boolean {
            if (packageName in trustedForTests) return true
            val trusted = trustedMap(context)[packageName] ?: return false
            return certificates.any { it in trusted }
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
