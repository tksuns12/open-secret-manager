import XCTest

/// Filling and saving in real Safari, not a stand-in: run by
/// scripts/test-mobile-safari.sh, which serves a test site over HTTPS on
/// this computer, has the simulator trust the certificate authority that
/// signed it, and names the site in OSM_TEST_SAFARI_SITE; the site logs what
/// its forms send, which the script compares. Skipped without it.
final class SafariTests: UITestCase {
    private let site = ProcessInfo.processInfo.environment["OSM_TEST_SAFARI_SITE"]
    private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")

    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipIf(site == nil, "no OSM_TEST_SAFARI_SITE")
    }

    /// The frozen vault with a login for the site, the app made the AutoFill
    /// provider, and the app left.
    private func prepare() {
        let app = launchApp(vault: frozenVault)
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        app.buttons["new-item"].tap()
        for (text, identifier) in [("Test site", "edit-title"), ("site-user", "edit-username"),
                                   (site!, "edit-url"), ("site-pass-1", "edit-password")] {
            let field = app.descendants(matching: .any)[identifier].firstMatch
            field.waitAndTap()
            field.typeText(text)
        }
        app.buttons["save"].tap()
        XCTAssert(app.staticTexts["detail-username"].waitForLabel("site-user"))
        app.buttons["back"].firstMatch.tap()
        turnOnAutoFill(in: app)
        XCUIDevice.shared.press(.home)
    }

    /// Opens the page in Safari and returns its first text field.
    private func open(_ path: String) -> XCUIElement {
        XCUIDevice.shared.system.open(URL(string: "\(site!)\(path)?at=\(Date().timeIntervalSince1970)")!)
        let field = safari.webViews.textFields.firstMatch
        XCTAssert(field.waitForExistence(timeout: startTimeout), "the page never showed")
        return field
    }

    /// Taps the field, chooses Open Secret Manager in the keyboard's
    /// Passwords, and unlocks the fill screen.
    private func askToFill(_ field: XCUIElement) {
        focus(field)
        let ours = safari.buttons["Open Secret Manager"]
        XCTAssert(safari.buttons["Passwords"].waitForExistence(timeout: 30), "no Passwords key")
        safari.buttons["Passwords"].settledTap { ours.exists }
        ours.settledTap { !ours.exists }
        XCTAssert(safari.staticTexts["asker"].waitForExistence(timeout: startTimeout), "no fill screen")
        unlock(in: safari)
    }

    /// Taps the field until the keyboard shows: a tap on a page still
    /// laying itself out can miss.
    private func focus(_ field: XCUIElement) {
        Thread.sleep(forTimeInterval: 2)
        for _ in 0..<3 {
            field.tap()
            if safari.keyboards.firstMatch.waitForExistence(timeout: 10) { return }
        }
        XCTFail("no keyboard for \(field)")
    }

    func testALoginFillsIntoSafariAndOneTypedThereIsSaved() {
        prepare()

        // The site's login fills both fields.
        askToFill(open("/login"))
        capture("safari-1-logins")
        safari.buttons["fill:Test site"].waitAndTap(timeout: 30)
        XCTAssert(safari.webViews.textFields.firstMatch.waitForValue("site-user"), "the username was not filled")
        safari.webViews.buttons["Sign in"].tap()
        XCTAssert(safari.webViews.staticTexts["Enter the code from your authenticator"].waitForExistence(timeout: 30))

        // A login typed into the page is saved for the site.
        let username = open("/login")
        focus(username)
        username.typeText("new-user")
        let password = safari.webViews.secureTextFields.firstMatch
        password.tap()
        password.typeText("new-pass-1")
        safari.webViews.buttons["Sign in"].tap()
        // Safari asks in an alert of its own, not the sheet an app's form gets.
        let ours = safari.alerts["Save Password?"].buttons["Open Secret Manager"]
        XCTAssert(ours.waitForExistence(timeout: 30), "no offer to save")
        capture("safari-2-save-offer")
        ours.settledTap { safari.staticTexts["asker"].exists }
        unlock(in: safari)
        let saveNew = safari.buttons["save-new"]
        XCTAssert(saveNew.waitForExistence(timeout: 30))
        capture("safari-3-save")
        // Named for the address Safari gave, its port included: on iOS a
        // request names it whole.
        let address = URL(string: site!)!
        let host = address.port.map { "\(address.host!):\($0)" } ?? address.host!
        XCTAssertEqual(safari.textFields["save-title"].value as? String, host)
        saveNew.tap()
        XCTAssert(safari.staticTexts["asker"].waitForNonExistence(timeout: 20), "the save screen stayed")

        // Offered on the site from now on, beside the login it had.
        askToFill(open("/login"))
        XCTAssert(safari.buttons["fill:\(host)"].waitForExistence(timeout: 30))
        XCTAssert(safari.buttons["fill:Test site"].exists)
        capture("safari-4-both")
        safari.buttons["cancel"].tap()
    }
}

private extension XCUIElement {
    /// Waits until the element's value is `expected`.
    func waitForValue(_ expected: String, timeout: TimeInterval = 15) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if exists && (value as? String) == expected { return true }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return false
    }
}
