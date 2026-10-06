import XCTest

/// The app's screens over the real shared code, in a simulator. Before each
/// test the app empties its vault's folder and, for most, puts a copy of the
/// frozen format 7 vault there (what a debug build does at launch when asked;
/// see App/TestSupport.swift).
final class AppTests: UITestCase {
    func testWithoutAVaultItOffersToJoinAndRefusesWhatIsNoInvitation() {
        let app = launchApp(vault: nil)
        let invitation = app.descendants(matching: .any)["invitation"].firstMatch
        XCTAssert(invitation.waitForExistence(timeout: startTimeout))
        capture("app-1-join")
        invitation.tap()
        invitation.typeText("not an invitation")
        app.buttons["join-continue"].tap()
        XCTAssert(app.staticTexts["notice"].waitForLabel("That is not an invitation · copy it again from your computer"))
    }

    func testRecordsTakenOutOfTheFileAreSaidAfterUnlockingUntilConfirmed() {
        // The format 8 fixture with the first version of Mail taken out
        // (prepare.sh makes it).
        let takenOut = Bundle(for: AppTests.self).path(forResource: "sealed-taken-out-vault", ofType: "sqlite3")!
        let app = launchApp(vault: takenOut)
        unlock(in: app)
        let said = app.descendants(matching: .any)["rows-changed"].firstMatch
        XCTAssert(said.waitForExistence(timeout: 30), "the taking out was not said")
        XCTAssert(app.buttons["item:Mail"].exists)
        capture("app-rows-changed")
        app.buttons["rows-changed-ok"].tap()
        XCTAssert(said.waitForNonExistence(timeout: 15))
        // Confirmed, it is not said again.
        XCUIDevice.shared.press(.home)
        app.activate()
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        XCTAssertFalse(said.exists)
    }

    func testAWrongPasswordIsRefused() {
        let app = launchApp(vault: frozenVault)
        unlock(in: app, password: "not the password")
        XCTAssert(app.staticTexts["notice"].waitForLabel("That password was rejected"))
        XCTAssert(app.staticTexts["locked"].exists)
    }

    func testALockedVaultUnlocksListsCopiesAndLocksWhenTheAppIsLeft() {
        let app = launchApp(vault: frozenVault)
        XCTAssert(app.staticTexts["locked"].waitForExistence(timeout: startTimeout))
        capture("app-2-locked")
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        capture("app-3-items")
        app.buttons["item:Bank"].tap()
        XCTAssert(app.staticTexts["detail-username"].waitForLabel("account 42"))
        capture("app-4-detail")

        // The password goes to the pasteboard, from which the owner pastes
        // it into another app.
        app.buttons["copy-password"].tap()
        XCTAssert(app.staticTexts["notice"].waitForLabel("Password copied · cleared in 30 seconds"))
        let fixture = XCUIApplication(bundleIdentifier: "org.opensecretmanager.loginfixture")
        fixture.launch()
        let field = fixture.textFields["fixture-username"]
        field.waitAndTap(timeout: startTimeout)
        field.press(forDuration: 1.2)
        fixture.menuItems["Paste"].waitAndTap()
        XCTAssert(fixture.staticTexts["filled"].waitForLabel("p@ss \"quoted\" \\ and 🔑|"))

        // Leaving the app locked it.
        app.activate()
        XCTAssert(app.staticTexts["locked"].waitForExistence(timeout: 15))

        // And the copy is gone from the pasteboard 30 seconds after it was made.
        Thread.sleep(forTimeInterval: 31)
        XCTAssertFalse(UIPasteboard.general.hasStrings)
    }
}
