package org.opensecretmanager.app.autofill

import android.content.Context
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.net.Uri
import android.os.Build

/**
 * The sites that say an app is theirs: the hosts of the app's links that
 * Android verified, the site's `/.well-known/assetlinks.json` naming the
 * app, not those the owner only set it to open. A login saved for one of
 * them, or for a host under one, is suggested for the app, and filled only
 * once the owner chooses it. Nothing is fetched: Android verified them when
 * the app was installed or updated. Before Android 12 links were verified
 * for a whole app at once, and nothing is suggested.
 */
object LinkedSites {
    /** The domains, without `*.` or `www.`, each of two labels or more. */
    fun of(context: Context, packageName: String): Set<String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return emptySet()
        val manager = context.getSystemService(DomainVerificationManager::class.java) ?: return emptySet()
        val state = runCatching { manager.getDomainVerificationUserState(packageName) }.getOrNull() ?: return emptySet()
        return state.hostToStateMap
            .filterValues { it == DomainVerificationUserState.DOMAIN_STATE_VERIFIED }
            .keys.map { it.lowercase().removePrefix("*.").removePrefix("www.") }
            .filter { '.' in it }
            .toSet()
    }

    /**
     * Whether [url] is on one of [domains], or on a host under one: over
     * https and on its usual port, as an app's links are.
     */
    fun cover(domains: Set<String>, url: String): Boolean {
        if (domains.isEmpty()) return false
        val uri = Uri.parse(url)
        if (uri.scheme?.lowercase() != "https" || uri.port !in setOf(-1, 443)) return false
        val host = uri.host?.lowercase()?.trimEnd('.') ?: return false
        return domains.any { host == it || host.endsWith(".$it") }
    }
}
