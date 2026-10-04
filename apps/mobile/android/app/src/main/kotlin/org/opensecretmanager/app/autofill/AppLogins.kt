package org.opensecretmanager.app.autofill

import android.content.Context

/**
 * Which logins the owner chose for which app, on this phone only: an app
 * has no origin to match a login's address against, so it is offered only
 * the logins the owner picked for it before, by package and signing
 * certificate. Another app under the same package name, signed by someone
 * else, is a different app here. A page in an app that is not a trusted
 * browser is keyed by the domain the app says it shows too: a login chosen
 * for one page of such an app is not offered on its other pages.
 */
class AppLogins(context: Context) {
    private val preferences = context.getSharedPreferences("app-logins", Context.MODE_PRIVATE)

    private fun key(app: Requester.App) = "${app.packageName}:${app.certificate}" + (app.claimedDomain?.let { ":$it" } ?: "")

    fun chosen(app: Requester.App): Set<String> = preferences.getStringSet(key(app), emptySet()).orEmpty()

    fun remember(app: Requester.App, itemId: String) {
        preferences.edit().putStringSet(key(app), chosen(app) + itemId).apply()
    }

    fun forget(app: Requester.App, itemId: String) {
        preferences.edit().putStringSet(key(app), chosen(app) - itemId).apply()
    }
}
