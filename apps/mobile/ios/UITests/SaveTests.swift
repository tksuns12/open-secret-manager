import XCTest

/// Saving what another app's login form submitted through the system's
/// AutoFill, from iOS 26.2, end to end: the stand-in app (LoginFixture)
/// signs in with what the test typed, the system asks where to save it, and
/// the test chooses Open Secret Manager, unlocks its save screen, and
/// chooses, as the owner would.
final class SaveTests: UITestCase {
    /// Types into the stand-in app's form, signs in, and chooses Open Secret
    /// Manager in the system's offer to save; then unlocks the save screen.
    private func signInAndSave(username: String, password: String, name: String? = nil) {
        fixture.launch()
        let usernameField = fixture.textFields["fixture-username"]
        usernameField.waitAndTap(timeout: startTimeout)
        usernameField.typeText(username)
        let passwordField = fixture.secureTextFields["fixture-password"]
        passwordField.tap()
        passwordField.typeText(password)
        fixture.buttons["fixture-sign-in"].tap()
        let ours = fixture.sheets["Save Password?"].buttons["Open Secret Manager"]
        XCTAssert(ours.waitForExistence(timeout: 20), "no offer to save")
        name.map { capture("save-\($0)-offer") }
        ours.settledTap { fixture.staticTexts["asker"].exists }
        name.map { capture("save-\($0)-locked") }
        unlock(in: fixture)
    }

    /// The screen gone, the stand-in app shows it signed in.
    private func assertSaved(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssert(fixture.staticTexts["asker"].waitForNonExistence(timeout: 20), "the save screen stayed", file: file, line: line)
        XCTAssert(fixture.staticTexts["signed-in"].exists, file: file, line: line)
        XCTAssertFalse(fixture.sheets["Save Password?"].exists, file: file, line: line)
    }

    /// Fills the stand-in app's form with `title`, which it names by nothing
    /// in a fill request, and returns what was filled.
    private func filled(with title: String) -> String {
        askToFill()
        unlock(in: fixture)
        fixture.buttons["fill:\(title)"].waitAndTap(timeout: 30)
        let filled = fixture.staticTexts["filled"]
        let deadline = Date().addingTimeInterval(15)
        while filled.label == "|" && Date() < deadline { Thread.sleep(forTimeInterval: 0.25) }
        return filled.label
    }

    func testAnAppsNewLoginIsSavedForItAndItsNextPasswordIntoThatLogin() {
        let app = launchApp(vault: frozenVault)
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        turnOnAutoFill(in: app)
        XCUIDevice.shared.press(.home)

        // The save request names the app: a new login, for that app.
        signInAndSave(username: "new account", password: "new password", name: "1")
        let saveNew = fixture.buttons["save-new"]
        XCTAssert(saveNew.waitForExistence(timeout: 30))
        XCTAssertEqual(fixture.staticTexts["asker"].label, "For the app Login fixture")
        XCTAssertEqual(fixture.textFields["save-title"].value as? String, "Login fixture")
        XCTAssertFalse(fixture.buttons["update:Bank"].exists)
        capture("save-1-new")
        saveNew.tap()
        assertSaved()
        XCTAssertEqual(filled(with: "Login fixture"), "new account|new password")

        // The next password for that account goes into that login.
        signInAndSave(username: "new account", password: "newer password")
        let update = fixture.buttons["update:Login fixture"]
        XCTAssert(update.waitForExistence(timeout: 30))
        capture("save-2-update")
        update.tap()
        assertSaved()
        XCTAssertEqual(filled(with: "Login fixture"), "new account|newer password")

        // What the vault has already is not saved again.
        signInAndSave(username: "new account", password: "newer password")
        XCTAssert(fixture.staticTexts["already-saved"].waitForExistence(timeout: 30))
        fixture.buttons["done"].tap()
        assertSaved()
    }
}
