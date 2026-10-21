import notify
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

    /// iOS lets no other app fill a card: from iOS 18 its number goes into
    /// a field as text, which the owner asks for in the field's menu. The
    /// screen is unlocked with Face ID: unlocked with the password typed
    /// there, iOS 26.5 in the simulator mostly ended the request at the
    /// next touch, as the keyboard did not go back to the app's field and
    /// that touch took it.
    func testACardsNumberIsInsertedIntoAFieldAsText() {
        // A face enrolled, as the simulator's Features menu does.
        var token: Int32 = 0
        notify_register_check("com.apple.BiometricKit.enrollmentChanged", &token)
        notify_set_state(token, 1)
        notify_cancel(token)
        notify_post("com.apple.BiometricKit.enrollmentChanged")
        let cards = Bundle(for: AppTests.self).path(forResource: "cards-vault", ofType: "sqlite3")!
        let app = launchApp(vault: cards)
        let keep = app.switches["remember-biometric"]
        XCTAssert(keep.waitForExistence(timeout: startTimeout), "Face ID is not offered: no face enrolled")
        keep.switches.firstMatch.exists ? keep.switches.firstMatch.tap() : keep.tap()
        unlock(in: app)
        XCTAssert(app.buttons["item:Visa"].waitForExistence(timeout: 30))
        turnOnAutoFill(in: app)
        XCUIDevice.shared.press(.home)
        let screen = askToInsert()
        // iOS says nothing of where the text goes.
        XCTAssertEqual(screen.staticTexts["asker"].label, "Into the field you chose")
        XCTAssertFalse(screen.buttons["insert:Visa"].exists)
        // A matching face, shown until it takes.
        let useFace = screen.buttons["unlock-biometric"]
        useFace.waitAndTap(timeout: 30)
        let deadline = Date().addingTimeInterval(45)
        while !screen.buttons["insert:Visa"].exists && Date() < deadline {
            notify_post("com.apple.BiometricKit_Sim.pearl.match")
            Thread.sleep(forTimeInterval: 1.5)
        }
        // Any item, the card among them by its brand and last four digits.
        screen.buttons["insert:Visa"].waitAndTap(timeout: 30)
        capture("insert-3-fields")
        // Its fields, the secrets not shown.
        XCTAssert(screen.buttons["insert-field:Number"].waitForExistence(timeout: 15))
        XCTAssert(screen.buttons["insert-field:Security code"].exists && screen.buttons["insert-field:Expiry (MM/YY)"].exists)
        XCTAssertFalse(screen.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "4111")).firstMatch.exists)
        let number = screen.buttons["insert-field:Number"]
        number.settledTap { !number.exists }
        XCTAssert(fixture.staticTexts["filled"].waitForLabel("4111111111111111|"))
        capture("insert-4-inserted")
    }
}
