// The phone interface through its generated Swift bindings, on a copy of
// the frozen format 7 vault: the same checks as
// crates/mobile/tests/frozen_vault.rs. Run in an iOS simulator by
// scripts/test-mobile.sh, with the folder holding the copy as its
// argument. It prints what passed and exits non-zero at the first failure.

import Foundation

var passed = 0

func check(_ condition: Bool, _ what: String, line: Int = #line) {
    if condition {
        passed += 1
    } else {
        print("FAILED at line \(line): \(what)")
        exit(1)
    }
}

func fails<T>(_ call: () throws -> T, with expected: (MobileError) -> Bool) -> Bool {
    do {
        _ = try call()
        return false
    } catch let error as MobileError {
        return expected(error)
    } catch {
        return false
    }
}

/// No keystore: this program has no entitlement to the app group's
/// Keychain items, so a network key would be kept unsealed. The app's own
/// keystore (Shared/KeychainKeystore.swift) is used through the app.
final class NoKeystore: PhoneKeystore {
    func seal(key: Data) throws -> Data { throw KeystoreFailure.Unavailable }
    func unseal(sealed: Data) throws -> Data { throw KeystoreFailure.Unavailable }
}

let folder = CommandLine.arguments[1]
let password = "fixture password, not a secret"

do {
    let device = try Device.open(folder: folder, keystore: NoKeystore())
    check(device.state() == .locked, "a vault opens locked")
    check(fails({ try device.items() }) { if case .Locked = $0 { true } else { false } }, "nothing is listed while locked")
    check(fails({ try device.unlock(password: "not the password") }) { if case .InvalidCredentials = $0 { true } else { false } }, "a wrong password is refused")
    try device.unlock(password: password)
    check(device.state() == .unlocked, "the password unlocks it")

    let items = try device.items()
    let titles = items.map { $0.title }
    check(titles.contains("Bank") && titles.contains("Mail"), "the items are listed: \(titles)")
    check(items.contains { $0.conflict }, "a conflict is shown as one")

    let bank = try device.item(id: "fixture-bank")
    check(bank.title == "Bank" && bank.kind == .login && bank.username == "account 42", "an item reads as written")
    check(bank.hasPassword && bank.hasOneTimeCode && bank.favorite, "its flags are right")
    check(bank.notes == "line one\nline two", "its notes keep their line break")
    check(bank.fields == ["Branch", "PIN"], "its other fields are named in order: \(bank.fields)")
    check(try device.field(id: "fixture-bank", name: "PIN") == "0000", "another field's value crosses intact")
    check(fails({ try device.field(id: "fixture-bank", name: "pin") }) { if case .NoSuchField = $0 { true } else { false } }, "a field the item lacks is not given")
    check(try device.password(id: "fixture-bank") == "p@ss \"quoted\" \\ and 🔑", "a password crosses intact")
    let code = try device.oneTimeCode(id: "fixture-bank")
    check(code.count == 6 && code.allSatisfy { $0.isNumber }, "a one-time code has six digits: \(code)")
    check(try device.password(id: "fixture-mail") == "third password, with ünïcödé", "accented letters cross intact")
    check(fails({ try device.oneTimeCode(id: "fixture-mail") }) { if case .NoOneTimeCode = $0 { true } else { false } }, "an item without a one-time code says so")
    check(fails({ try device.item(id: "no such item") }) { if case .NotFound = $0 { true } else { false } }, "an unknown item is not found")
    let forMail = try device.loginsForWeb(origin: "https://mail.example.test").map { $0.title }
    check(forMail == ["Mail"], "a page is offered the logins for its origin: \(forMail)")
    check(try device.loginsForWeb(origin: "https://bank.example.test:8443").map { $0.title } == ["Bank"], "the port counts")
    check(try device.loginsForWeb(origin: "https://bank.example.test").isEmpty, "a page without the port is offered nothing")
    check(fails({ try device.loginsForWeb(origin: "http://mail.example.test") }) { if case .InvalidOrigin = $0 { true } else { false } }, "only https")
    let filled = try device.fillForWeb(id: "fixture-mail", origin: "https://mail.example.test")
    check(filled.username == "owner@example.test" && filled.password == "third password, with ünïcödé", "a login fills its page")
    check(fails({ try device.fillForWeb(id: "fixture-bank", origin: "https://mail.example.test") }) { if case .NotForThisPage = $0 { true } else { false } }, "a login fills no other page")
    check(try device.fillForApp(id: "fixture-bank").username == "account 42", "a login fills the app it was chosen for")
    // An item's history, and a deleted note, come back.
    let history = try device.history(id: "fixture-mail")
    check(history.map { $0.changed } == [["password", "notes"], ["password"], []], "a history says what each version changed")
    try device.restore(id: "fixture-mail", revision: history[2].revision, heads: [history[0].revision])
    check(try device.password(id: "fixture-mail") == "first password", "an earlier version comes back")
    let note = try device.deletedItems().first { $0.title == "A note that was deleted" }!
    try device.restore(id: note.id, revision: note.last, heads: note.heads)
    check(try device.item(id: note.id).notes == "gone", "a deleted note comes back as it was")
    // A one-time code goes only where its login would.
    check(try device.withOneTimeCodes(ids: try device.items().map { $0.id }).map { $0.title } == ["Bank"], "only Bank has a one-time code")
    check(try device.oneTimeCodeForWeb(id: "fixture-bank", origin: "https://bank.example.test:8443").count == 6, "a code fills its login's page")
    check(fails({ try device.oneTimeCodeForWeb(id: "fixture-bank", origin: "https://bank.example.test") }) { if case .NotForThisPage = $0 { true } else { false } }, "a code fills no other page")
    check(fails({ try device.oneTimeCodeForWeb(id: "fixture-mail", origin: "https://mail.example.test") }) { if case .NoOneTimeCode = $0 { true } else { false } }, "a login without a code fills none")
    // The owner's edits cross the other way, unicode and all.
    let draft = ItemDraft(title: "Forum", kind: .login, username: "me", url: "https://forum.example.test", notes: "", favorite: false, password: "新しい 🔑 \"pass\"", oneTimeCodeSecret: nil)
    let created = try device.createItem(draft: draft)
    check(try device.password(id: created) == "新しい 🔑 \"pass\"", "a new login keeps its password intact")
    let read = try device.item(id: created)
    var renamed = draft
    renamed.username = "someone else"
    renamed.password = nil
    try device.updateItem(id: created, revision: read.revision, draft: renamed)
    check(try device.item(id: created).username == "someone else", "an edit is kept")
    check(try device.password(id: created) == "新しい 🔑 \"pass\"", "an edit keeps the password it does not name")
    check(fails({ try device.updateItem(id: created, revision: read.revision, draft: renamed) }) { if case .ChangedElsewhere = $0 { true } else { false } }, "an edit of an older reading is refused")
    var passport = draft
    passport.kind = .identity
    check(fails({ try device.createItem(draft: passport) }) { if case .NotEditableHere = $0 { true } else { false } }, "an identity is made on a computer")
    // What a form submitted goes into a login the form could fill, as its password only.
    let forum = try device.loginsForWeb(origin: "https://forum.example.test").map { $0.id }
    let candidates = try device.saveCandidates(ids: forum, username: "someone else", password: "新しい 🔑 \"pass\"")
    check(candidates.map { $0.hasThisPassword } == [true], "a save finds the login that has its password already")
    check(try device.saveCandidates(ids: forum, username: "another", password: "x").isEmpty, "another username is another account")
    try device.updatePassword(id: created, revision: candidates[0].revision, password: "次の 🔑")
    check(try device.password(id: created) == "次の 🔑", "a saved password is kept")
    check(try device.item(id: created).username == "someone else", "a saved password changes nothing else")
    try device.deleteItem(id: created, revision: try device.item(id: created).revision)
    check(fails({ try device.item(id: created) }) { if case .NotFound = $0 { true } else { false } }, "a deleted item is gone")
    check(try generatePassword(length: 24).count == 24, "the generator makes the length asked for")
    check(fails({ try device.goOnline() }) { if case .Network = $0 { true } else { false } }, "a copy of a vault does not go online")
    check(device.syncStatus().state == .offline, "it reports being offline")
    device.lock()
    check(fails({ try device.password(id: "fixture-bank") }) { if case .Locked = $0 { true } else { false } }, "locking hides the passwords again")
} catch {
    print("FAILED: \(error)")
    exit(1)
}
print("OK \(passed) checks")
