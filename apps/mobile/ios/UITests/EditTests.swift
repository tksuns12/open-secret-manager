import XCTest

/// Writing on the phone through the app's screens, over the real shared
/// code, on a copy of the frozen format 7 vault: new items, edits,
/// deletions, and what is left to a computer.
final class EditTests: UITestCase {
    private func unlocked() -> XCUIApplication {
        let app = launchApp(vault: frozenVault)
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        return app
    }

    private func field(_ identifier: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any)[identifier].firstMatch
    }

    private func type(_ text: String, into identifier: String, in app: XCUIApplication) {
        let field = field(identifier, in: app)
        field.waitAndTap()
        field.typeText(text)
    }

    /// Empties a text field and types `text` into it: the field is tapped at
    /// its end, where the deleting starts from.
    private func replace(_ identifier: String, with text: String, in app: XCUIApplication) {
        let field = field(identifier, in: app)
        XCTAssert(field.waitForExistence(timeout: 20))
        field.coordinate(withNormalizedOffset: CGVector(dx: 0.98, dy: 0.5)).tap()
        let current = (field.value as? String) ?? ""
        field.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: current.count) + text)
    }

    /// Copies the open item's password, pastes it into the stand-in app, and
    /// returns what arrived there. Leaving the app locks it.
    private func pastedPassword(from app: XCUIApplication) -> String {
        app.buttons["copy-password"].waitAndTap()
        fixture.launch()
        let username = fixture.textFields["fixture-username"]
        username.waitAndTap(timeout: startTimeout)
        username.press(forDuration: 1.2)
        fixture.menuItems["Paste"].waitAndTap()
        let filled = fixture.staticTexts["filled"]
        let deadline = Date().addingTimeInterval(10)
        while filled.label == "|" && Date() < deadline { Thread.sleep(forTimeInterval: 0.25) }
        return String(filled.label.dropLast())
    }

    /// Back in the app after leaving it, unlocked and on `title`.
    private func backTo(_ title: String, in app: XCUIApplication) {
        app.activate()
        unlock(in: app)
        app.buttons["item:\(title)"].waitAndTap(timeout: 30)
    }

    func testALoginIsCreatedEditedAndDeleted() {
        let app = unlocked()
        app.buttons["new-item"].tap()
        XCTAssert(field("edit-title", in: app).waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["save"].isEnabled)
        type("Forum", into: "edit-title", in: app)
        type("me@forum.example.test", into: "edit-username", in: app)
        type("https://forum.example.test", into: "edit-url", in: app)
        type("forum password", into: "edit-password", in: app)
        app.buttons["save"].tap()
        // The new item opens.
        XCTAssert(app.staticTexts["detail-username"].waitForLabel("me@forum.example.test"))
        XCTAssertEqual(pastedPassword(from: app), "forum password")

        // An edit keeps the password it does not change.
        backTo("Forum", in: app)
        XCTAssert(app.buttons["edit"].waitForExistence(timeout: 15))
        capture("edit-1-item")
        app.buttons["edit"].tap()
        XCTAssert(field("edit-username", in: app).waitForExistence(timeout: 10))
        capture("edit-2-editor")
        replace("edit-username", with: "someone else", in: app)
        app.buttons["save"].tap()
        XCTAssert(app.staticTexts["detail-username"].waitForLabel("someone else"))
        XCTAssertEqual(pastedPassword(from: app), "forum password")

        // Deleting asks first.
        backTo("Forum", in: app)
        app.buttons["delete"].waitAndTap()
        XCTAssert(app.alerts.buttons["Keep"].firstMatch.waitForExistence(timeout: 10))
        capture("edit-3-delete")
        app.alerts.buttons["Keep"].firstMatch.tap()
        XCTAssert(app.staticTexts["detail-username"].waitForExistence(timeout: 5))
        app.buttons["delete"].tap()
        app.alerts.buttons["Delete"].firstMatch.waitAndTap()
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 15))
        XCTAssert(app.buttons["item:Forum"].waitForNonExistence(timeout: 10))
    }

    func testAGeneratedPasswordIsSavedAndASecureNoteHasOnlyItsText() {
        let app = unlocked()
        app.buttons["new-item"].tap()
        type("Router", into: "edit-title", in: app)
        app.buttons["generate"].waitAndTap()
        let generated = (field("edit-password", in: app).value as? String) ?? ""
        XCTAssertEqual(generated.count, 20)
        app.buttons["save"].tap()
        XCTAssert(app.buttons["copy-password"].waitForExistence(timeout: 15))
        XCTAssertEqual(pastedPassword(from: app), generated)

        app.activate()
        unlock(in: app)
        app.buttons["new-item"].waitAndTap(timeout: 30)
        app.buttons["Secure note"].waitAndTap()
        XCTAssertFalse(field("edit-username", in: app).exists)
        XCTAssertFalse(field("edit-password", in: app).exists)
        type("Recovery codes", into: "edit-title", in: app)
        type("first code\nsecond code", into: "edit-notes", in: app)
        capture("edit-4-note")
        app.buttons["save"].tap()
        XCTAssert(app.staticTexts["detail-notes"].waitForLabel("first code\nsecond code"))
        XCTAssertFalse(app.buttons["copy-password"].exists)
    }

    func testAnItemInConflictIsLeftToAComputer() {
        let app = unlocked()
        app.buttons["item:Shared, as this device has it"].tap()
        XCTAssert(app.buttons["back"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["edit"].exists)
        XCTAssertFalse(app.buttons["delete"].exists)
    }

    func testASaveOfAnItemThatChangedMeanwhileKeepsWhatWasTypedOnTopOfIt() {
        // As the editor opens for Bank, a second device object on the same
        // folder changes its notes (App/TestSupport.swift), as a sync would.
        let app = XCUIApplication()
        app.launchEnvironment["OSM_TEST_VAULT"] = frozenVault
        app.launchEnvironment["OSM_TEST_BIOMETRICS"] = "off"
        app.launchEnvironment["OSM_TEST_CHANGE_WHILE_EDITING"] = "fixture-bank|changed elsewhere|\(fixturePassword)"
        app.launch()
        unlock(in: app)
        app.buttons["item:Bank"].waitAndTap(timeout: 30)
        app.buttons["edit"].waitAndTap()
        replace("edit-username", with: "changed here", in: app)
        app.buttons["save"].tap()

        // Refused, the edit stays open: what was typed is kept, on top of the
        // item as it is now, and what changed elsewhere is named.
        let note = field("changed-elsewhere", in: app)
        XCTAssert(note.waitForExistence(timeout: 15))
        XCTAssert(note.label.contains("It changed its notes."), note.label)
        XCTAssertEqual(field("edit-username", in: app).value as? String, "changed here")
        // The notes are further down the form, which shows only what fits.
        let notes = field("edit-notes", in: app)
        for _ in 0..<5 where !notes.waitForExistence(timeout: 3) { app.swipeUp() }
        XCTAssertEqual(notes.value as? String, "changed elsewhere")

        // Saved again, both changes stand.
        app.buttons["save"].tap()
        XCTAssert(app.staticTexts["detail-username"].waitForLabel("changed here"))
        XCTAssert(app.staticTexts["detail-notes"].waitForLabel("changed elsewhere"))
    }
}
