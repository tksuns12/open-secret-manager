package org.opensecretmanager.app

import org.opensecretmanager.vault.PasswordHealth
import org.opensecretmanager.vault.Weakness

/** What a weak password is told as. */
private fun weakText(reason: Weakness): String = when (reason) {
    Weakness.TOO_SHORT -> "is short"
    Weakness.ONE_KIND -> "uses one kind of character"
    Weakness.COMMON -> "is a common one"
    Weakness.HOLDS_OWN_NAME -> "holds this item's own name"
}

/**
 * What each login that needs attention is told, by id: a weak password and
 * why, and that it is shared. Made from what the shared code says, which
 * names no password.
 */
internal fun attentionOf(health: PasswordHealth): Map<String, List<String>> {
    val told = LinkedHashMap<String, MutableList<String>>()
    for (weak in health.weak) {
        told.getOrPut(weak.id) { mutableListOf() }.add("The password ${weak.reasons.joinToString(" and ") { weakText(it) }}.")
    }
    for (set in health.reused) {
        for (id in set.ids) told.getOrPut(id) { mutableListOf() }.add("The password is also used by another login.")
    }
    return told
}
