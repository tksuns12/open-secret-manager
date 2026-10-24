import XCTest

/// The app joins a desktop-side device on this machine over the network, as
/// a phone joins a computer (scripts/test-mobile-join.sh ios). The test and
/// the script talk through files in the folder OSM_TEST_JOIN: the test writes
/// `ready`, the script writes the desktop's `invitation`, the test starts the
/// app with its camera reading that invitation (the simulator has none),
/// scans it on the join screen, and writes the `phone-code` the app shows, which the script compares with the desktop's before it answers
/// for the owner there; then the test sets the phone's password, and the
/// desktop's item shows once it synced. Last, the test makes a login and
/// writes `phone-made`, and the script writes `desktop-has` once the desktop
/// lists it. Skipped without OSM_TEST_JOIN.
final class JoinTests: UITestCase {
    func testJoinsTheDesktopAndShowsItsVault() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let folder = environment["OSM_TEST_JOIN"] else { throw XCTSkip("run by scripts/test-mobile-join.sh ios") }
        try "".write(toFile: folder + "/ready", atomically: true, encoding: .utf8)
        var invitation: String?
        for _ in 0..<240 where invitation == nil {
            invitation = try? String(contentsOfFile: folder + "/invitation", encoding: .utf8)
            if invitation == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        let app = launchApp(vault: nil, scanned: try XCTUnwrap(invitation, "the script gave no invitation"))
        app.buttons["join-scan"].waitAndTap(timeout: startTimeout)

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

        // A login made on the phone goes the other way; the script says when
        // the desktop has it.
        app.buttons["new-item"].waitAndTap()
        let title = app.descendants(matching: .any)["edit-title"].firstMatch
        title.waitAndTap()
        title.typeText("From the phone")
        // In place of the password made for it.
        app.buttons["clear-password"].waitAndTap()
        let secret = app.descendants(matching: .any)["edit-password"].firstMatch
        secret.waitAndTap()
        secret.typeText("phone-made password")
        app.buttons["save"].tap()
        XCTAssert(app.buttons["copy-password"].waitForExistence(timeout: 30))
        try "".write(toFile: folder + "/phone-made", atomically: true, encoding: .utf8)
        var arrived = false
        for _ in 0..<240 where !arrived {
            arrived = FileManager.default.fileExists(atPath: folder + "/desktop-has")
            if !arrived { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssert(arrived, "the desktop never had the phone's login")
    }
}
