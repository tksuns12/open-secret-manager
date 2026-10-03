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

let folder = CommandLine.arguments[1]
let password = "fixture password, not a secret"

do {
    let device = try Device.open(folder: folder)
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
    check(try device.password(id: "fixture-bank") == "p@ss \"quoted\" \\ and 🔑", "a password crosses intact")
    let code = try device.oneTimeCode(id: "fixture-bank")
    check(code.count == 6 && code.allSatisfy { $0.isNumber }, "a one-time code has six digits: \(code)")
    check(try device.password(id: "fixture-mail") == "third password, with ünïcödé", "accented letters cross intact")
    check(fails({ try device.oneTimeCode(id: "fixture-mail") }) { if case .NoOneTimeCode = $0 { true } else { false } }, "an item without a one-time code says so")
    check(fails({ try device.item(id: "no such item") }) { if case .NotFound = $0 { true } else { false } }, "an unknown item is not found")
    check(fails({ try device.goOnline() }) { if case .Network = $0 { true } else { false } }, "a copy of a vault does not go online")
    check(device.syncStatus().state == .offline, "it reports being offline")
    device.lock()
    check(fails({ try device.password(id: "fixture-bank") }) { if case .Locked = $0 { true } else { false } }, "locking hides the passwords again")
} catch {
    print("FAILED: \(error)")
    exit(1)
}
print("OK \(passed) checks")
