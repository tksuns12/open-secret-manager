import Foundation

/// What a failure means, as the owner reads it.
func describe(_ error: Error) -> String {
    guard let error = error as? MobileError else {
        return "Something went wrong on this phone · \(error.localizedDescription)"
    }
    switch error {
    case .Locked: return "The vault is locked"
    case .InvalidCredentials: return "That password was rejected"
    case .NotFound: return "That item is no longer in the vault"
    case .NoVault: return "This phone has no vault yet"
    case .VaultExists: return "This phone already has a vault"
    case .UnreadableVault: return "The vault on this phone cannot be opened"
    case .NotJoining: return "Start again with an invitation"
    case let .PasswordTooShort(minimum): return "Use at least \(minimum) characters"
    case .NotConfirmed: return "The other device did not confirm · nothing was changed"
    case .EnrollmentTimeout: return "Your other devices did not add this phone in time · cancel on the computer and try again"
    case .Removed: return "This phone was removed from the vault"
    case .InvalidInvitation: return "That is not an invitation · copy it again from your computer"
    case .NoOneTimeCode: return "This item has no one-time code"
    case .NoSuchField: return "This item no longer has that field · open it again"
    case .InvalidOrigin: return "Logins are filled only into https pages"
    case .NotForThisPage: return "That login is not saved for this page"
    case .NotALogin: return "Only a login can be filled"
    case .NotACard: return "Only a card can be filled into a card form"
    case let .InvalidItem(reason): return reason
    case .ChangedElsewhere: return "This item changed since you opened it · open it again"
    case .InConflict: return "Two devices changed this item at once · choose a version on your computer"
    case .NotEditableHere: return "Identities are edited on your computer"
    case let .Network(reason): return "Could not reach your other devices · \(reason)"
    case let .Storage(reason): return "Something went wrong on this phone · \(reason)"
    case .KeystoreUnavailable: return "This phone's keychain did not answer · try again"
    case .KeystoreLost: return "This phone no longer holds its network key · remove it on your computer and join again"
    }
}

/// A login as a list names it: its username, and its passkeys if it has any.
func loginLine(username: String, passkeys: UInt32) -> String {
    let passkeys = passkeys == 0 ? nil : passkeys == 1 ? "passkey" : "\(passkeys) passkeys"
    return [username.isEmpty ? nil : username, passkeys].compactMap { $0 }.joined(separator: " · ")
}

/// A card as a list names it: its brand and the last four digits of its number, nothing else of it.
func cardLine(brand: String?, ending: String?) -> String {
    let brand = (brand?.trimmingCharacters(in: .whitespaces).isEmpty ?? true) ? "Card" : brand!
    return [brand, ending.map { "•••• \($0)" }].compactMap { $0 }.joined(separator: " ")
}
