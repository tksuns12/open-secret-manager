import XCTest

/// The app joins a desktop-side device on this machine over the network, as
/// a phone joins a computer (scripts/test-mobile-join.sh ios). The test and
/// the script talk through files in the folder OSM_TEST_JOIN: once the app is
/// up the test writes `ready`, the script writes the desktop's `invitation`,
/// the test pastes it into the join screen and writes the `phone-code` the
/// app shows, which the script compares with the desktop's before it answers
/// for the owner there; then the test sets the phone's password, and the
/// desktop's item shows once it synced. Skipped without OSM_TEST_JOIN.
final class JoinTests: UITestCase {
    func testJoinsTheDesktopAndShowsItsVault() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let folder = environment["OSM_TEST_JOIN"] else { throw XCTSkip("run by scripts/test-mobile-join.sh ios") }
        let app = launchApp(vault: nil)
        try "".write(toFile: folder + "/ready", atomically: true, encoding: .utf8)
        var invitation: String?
        for _ in 0..<240 where invitation == nil {
            invitation = try? String(contentsOfFile: folder + "/invitation", encoding: .utf8)
            if invitation == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        UIPasteboard.general.string = try XCTUnwrap(invitation, "the script gave no invitation")
        let field = app.descendants(matching: .any)["invitation"].firstMatch
        field.waitAndTap(timeout: startTimeout)
        field.press(forDuration: 1.2)
        app.menuItems["Paste"].waitAndTap()
        app.buttons["join-continue"].tap()

        let code = app.staticTexts["join-code"]
        XCTAssert(code.waitForExistence(timeout: 60))
        try code.label.write(toFile: folder + "/phone-code", atomically: true, encoding: .utf8)
        capture("app-6-join-code")

        let password = "phone password, long enough"
        for identifier in ["new-password", "new-password-again"] {
            let secure = app.secureTextFields[identifier]
            secure.tap()
            secure.typeText(password)
        }
        app.buttons["join-finish"].tap()
        XCTAssert(app.buttons["item:Mail"].waitForExistence(timeout: 180), "the desktop's item never arrived")
    }
}
