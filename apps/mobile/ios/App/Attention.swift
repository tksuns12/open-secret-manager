// What the owner is told of the logins whose password is worth changing.
// Made from what the shared code says, which names no password.

/// What a weak password is told as.
private func weakText(_ reason: Weakness) -> String {
    switch reason {
    case .tooShort: "is short"
    case .oneKind: "uses one kind of character"
    case .common: "is a common one"
    case .holdsOwnName: "holds this item's own name"
    }
}

/// What each login that needs attention is told, by id: a weak password and
/// why, and that it is shared.
func attentionOf(_ health: PasswordHealth) -> [String: [String]] {
    var told: [String: [String]] = [:]
    for weak in health.weak {
        told[weak.id, default: []].append("The password \(weak.reasons.map(weakText).joined(separator: " and ")).")
    }
    for set in health.reused {
        for id in set.ids { told[id, default: []].append("The password is also used by another login.") }
    }
    return told
}
