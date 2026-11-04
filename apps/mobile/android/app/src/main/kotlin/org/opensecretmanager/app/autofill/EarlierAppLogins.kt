package org.opensecretmanager.app.autofill

import android.content.Context
import org.opensecretmanager.vault.Device

/**
 * Where builds before the vault kept them, this app held the logins the
 * owner chose for each app: in its own preferences, by the key the vault
 * keeps them by now ([Requester.App.key]). They move into the device once,
 * as it opens, and are then gone from here.
 */
object EarlierAppLogins {
    private const val NAME = "app-logins"

    fun moveInto(context: Context, device: Device) {
        val preferences = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
        val earlier = preferences.all.mapNotNull { (key, ids) ->
            (ids as? Set<*>)?.filterIsInstance<String>()?.let { key to it }
        }.toMap()
        if (earlier.isEmpty()) return
        device.importAppChoices(earlier)
        // Only once the device has them: a failure leaves them for the next open.
        preferences.edit().clear().commit()
    }
}
