package org.opensecretmanager.app.autofill

import android.content.Context
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.os.Build

/**
 * The sites that say an app is theirs: the hosts of the app's links that
 * Android verified, the site's `/.well-known/assetlinks.json` naming the
 * app, not those the owner only set it to open. The vault suggests the
 * logins saved for one of them, or for a host under one, to the app
 * ([Requester.asked]), and fills them only once the owner chooses one.
 * Nothing is fetched: Android verified them when the app was installed or
 * updated. Before Android 12 links were verified for a whole app at once,
 * and nothing is suggested.
 */
object LinkedSites {
    /** The domains, without `*.`, preserving `www.`, each of two labels or more. */
    fun of(context: Context, packageName: String): Set<String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return emptySet()
        val manager = context.getSystemService(DomainVerificationManager::class.java) ?: return emptySet()
        val state = runCatching { manager.getDomainVerificationUserState(packageName) }.getOrNull() ?: return emptySet()
        return state.hostToStateMap
            .filterValues { it == DomainVerificationUserState.DOMAIN_STATE_VERIFIED }
            .keys.map { it.lowercase().removePrefix("*.") }
            .filter { '.' in it }
            .toSet()
    }

    /**
     * Exact verified hosts for passkey authorization: preserves `www.` and
     * drops wildcard entries (`*.example.com`) so a subdomain or wildcard app
     * link cannot silently authorize a parent or sibling RP ID.
     */
    fun exactOf(context: Context, packageName: String): Set<String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return emptySet()
        val manager = context.getSystemService(DomainVerificationManager::class.java) ?: return emptySet()
        val state = runCatching { manager.getDomainVerificationUserState(packageName) }.getOrNull() ?: return emptySet()
        return state.hostToStateMap
            .filterValues { it == DomainVerificationUserState.DOMAIN_STATE_VERIFIED }
            .keys.map { it.lowercase() }
            .filter { !it.startsWith("*.") && '.' in it }
            .toSet()
    }
}
