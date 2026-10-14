import XCTest

/// Filling another app's login form through the system's AutoFill, end to
/// end: the app is made the phone's AutoFill provider, the stand-in app
/// (LoginFixture) shows a form, and the test chooses Open Secret Manager in
/// the keyboard's Passwords, unlocks the fill screen, and picks a login, as
/// the owner would.
final class AutoFillTests: UITestCase {
    /// Puts the frozen vault where the app keeps its vault, makes the app the
    /// AutoFill provider if it is not yet, and leaves the app.
    private func prepare() {
        let app = launchApp(vault: frozenVault)
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        turnOnAutoFill(in: app)
        XCUIDevice.shared.press(.home)
    }

    func testAnAppThatNamesNoSiteIsFilledOnlyWithTheLoginTheOwnerChooses() {
        prepare()
        askToFill()
        // iOS names this app by nothing: the owner chooses, warned, after
        // unlocking; nothing is listed before.
        XCTAssertEqual(fixture.staticTexts["asker"].label, "For an app that does not say which site it belongs to")
        XCTAssert(fixture.staticTexts["locked"].exists)
        XCTAssertFalse(fixture.buttons["fill:Bank"].exists)
        capture("fill-3-locked")
        unlock(in: fixture)
        XCTAssert(fixture.staticTexts["warning"].waitForExistence(timeout: 30))
        capture("fill-4-choose")
        // Every login is listed, and a search narrows them, as in the app.
        XCTAssert(fixture.buttons["fill:Mail"].waitForExistence(timeout: 30))
        let search = fixture.textFields["fill-search"]
        search.tap()
        search.typeText("BAN")
        XCTAssert(fixture.buttons["fill:Mail"].waitForNonExistence(timeout: 10))
        fixture.buttons["fill:Bank"].waitAndTap()
        XCTAssert(fixture.staticTexts["filled"].waitForLabel("account 42|p@ss \"quoted\" \\ and 🔑"))
        capture("fill-5-filled")

        // The next request finds the vault locked again; cancelling fills nothing.
        askToFill()
        XCTAssert(fixture.staticTexts["locked"].waitForExistence(timeout: 30))
        fixture.buttons["cancel"].tap()
        XCTAssert(fixture.staticTexts["filled"].waitForLabel("|"))
    }
}
