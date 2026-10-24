import notify
import XCTest

/// Unlocking with Face ID in a simulator, whose biometrics answer to the
/// notifications its Features menu sends: one to enroll a face, and one each
/// to show a matching and a non-matching face. The simulator's keychain does
/// not itself require the check for the kept password, as a phone's does;
/// the app asks for it before reading the password, which this tests. The
/// app asks for a face at once when it comes back locked, and the fill
/// screen as it opens, but not after the owner's own Lock.
final class BiometricTests: UITestCase {
    private func post(_ name: String, state: UInt64? = nil) {
        if let state {
            var token: Int32 = 0
            notify_register_check(name, &token)
            notify_set_state(token, state)
            notify_cancel(token)
        }
        notify_post(name)
    }

    /// Shows the simulator a face again and again until `done`: the prompt
    /// can take a moment to come up, and a face shown before it is lost.
    /// `button` is tapped again when nothing happens for a while, as a tap
    /// on a screen still moving in can be lost.
    private func show(_ face: String, in app: XCUIApplication, after button: XCUIElement? = nil, until done: () -> Bool, file: StaticString = #filePath, line: UInt = #line) {
        let deadline = Date().addingTimeInterval(45)
        var tries = 0
        while !done() && Date() < deadline {
            let notice = app.staticTexts["notice"]
            if notice.exists {
                XCTFail("the app said: \(notice.label)", file: file, line: line)
                return
            }
            if let button, tries % 6 == 0, button.exists {
                button.tap()
                Thread.sleep(forTimeInterval: 1.5)
            }
            post("com.apple.BiometricKit_Sim.pearl.\(face)")
            Thread.sleep(forTimeInterval: 1.5)
            tries += 1
        }
        XCTAssert(done(), "showing a face that does \(face == "match" ? "" : "not ")match had no effect", file: file, line: line)
    }

    func testFaceIDUnlocksOnceThePasswordWasKeptForIt() {
        post("com.apple.BiometricKit.enrollmentChanged", state: 1)
        let app = launchApp(vault: frozenVault)
        let keep = app.switches["remember-biometric"]
        XCTAssert(keep.waitForExistence(timeout: startTimeout), "Face ID is not offered: no face enrolled")
        keep.switches.firstMatch.exists ? keep.switches.firstMatch.tap() : keep.tap()
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        XCTAssertFalse(app.staticTexts["notice"].exists && app.staticTexts["notice"].label.contains("passcode"), app.staticTexts["notice"].label)
        turnOnAutoFill(in: app)
        app.buttons["lock"].tap()

        // Locked by the owner, nothing is asked: a matching face shown
        // meanwhile finds no prompt, and the vault stays locked.
        let useFace = app.buttons["unlock-biometric"]
        XCTAssert(useFace.waitForExistence(timeout: 15))
        for _ in 0..<3 {
            post("com.apple.BiometricKit_Sim.pearl.match")
            Thread.sleep(forTimeInterval: 1.5)
        }
        XCTAssertFalse(app.buttons["item:Bank"].exists)

        // A face that does not match leaves it locked, and the enrolled face
        // alone unlocks.
        capture("app-5-face-id")
        show("nomatch", in: app, after: useFace) { springboard.staticTexts["Face Not Recognized"].exists }
        XCTAssertFalse(app.buttons["item:Bank"].exists)
        // The alert stays up, waiting for the next face, after this.
        let again = springboard.buttons["Try Face ID Again"].firstMatch
        show("match", in: app, after: again) { app.buttons["item:Bank"].exists }

        // Left, the vault locks; back, Face ID is asked for at once.
        XCUIDevice.shared.press(.home)
        app.activate()
        show("match", in: app) { app.buttons["item:Bank"].exists }

        // The fill screen of another app asks at once too, and reaches the
        // same kept password.
        XCUIDevice.shared.press(.home)
        askToFill()
        XCTAssert(fixture.buttons["unlock-biometric"].waitForExistence(timeout: 30))
        show("match", in: fixture) { fixture.staticTexts["warning"].exists }
        fixture.buttons["cancel"].tap()
    }
}
