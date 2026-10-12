import XCTest

/// An item's history and the items deleted, through the app's screens over
/// the real shared code, on a copy of the frozen format 7 vault: Mail was
/// edited twice, and a note was deleted.
final class HistoryTests: UITestCase {
    private func unlocked() -> XCUIApplication {
        let app = launchApp(vault: frozenVault)
        unlock(in: app)
        XCTAssert(app.buttons["item:Bank"].waitForExistence(timeout: 30))
        return app
    }

    /// Scrolls until `element` is on the screen: a list makes its rows only
    /// as they come into view.
    @discardableResult
    private func scrollTo(_ element: XCUIElement, in app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        _ = element.waitForExistence(timeout: 5)
        var tries = 0
        while !(element.exists && element.isHittable) && tries < 8 {
            app.swipeUp()
            _ = element.waitForExistence(timeout: 1)
            tries += 1
        }
        XCTAssert(element.exists, "\(element) never appeared", file: file, line: line)
        return element
    }

    private func reveal(_ element: XCUIElement, in app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) {
        scrollTo(element, in: app, file: file, line: line).tap()
    }

    private func openHistory(_ title: String, in app: XCUIApplication) {
        app.buttons["item:\(title)"].waitAndTap(timeout: 30)
        reveal(app.buttons["history"], in: app)
        XCTAssert(app.staticTexts["said-0"].waitForExistence(timeout: 20))
    }

    func testAnEarlierVersionComesBackAsTheNewest() {
        let app = unlocked()
        openHistory("Mail", in: app)
        // Newest first, each saying what it changed.
        // The frozen vault's versions were saved before versions said when.
        XCTAssertEqual(app.staticTexts["said-0"].label, "Changed password, notes")
        XCTAssertEqual(app.staticTexts["time-0"].label, "Time not recorded")
        XCTAssertEqual(app.staticTexts["said-1"].label, "Changed password")
        XCTAssertEqual(app.staticTexts["time-1"].label, "Time not recorded")
        XCTAssertEqual(scrollTo(app.staticTexts["said-2"], in: app).label, "Made the item")
        XCTAssertEqual(app.staticTexts["time-2"].label, "Time not recorded")
        XCTAssertFalse(app.buttons["restore-0"].exists)
        capture("history-1")

        // Keep leaves it; Restore brings the first version back.
        reveal(app.buttons["restore-2"], in: app)
        app.alerts.buttons["Keep the current"].firstMatch.waitAndTap()
        reveal(app.buttons["restore-2"], in: app)
        capture("history-2-confirm")
        app.alerts.buttons["Restore"].firstMatch.waitAndTap()
        XCTAssert(app.buttons["copy-password"].waitForExistence(timeout: 20))
        reveal(app.buttons["history"], in: app)
        XCTAssert(app.staticTexts["said-0"].waitForLabel("Changed password, notes", timeout: 20))
        // The restore was saved here, and says when.
        let year = String(Calendar.current.component(.year, from: Date()))
        XCTAssert(app.staticTexts["time-0"].label.contains(year), app.staticTexts["time-0"].label)
        XCTAssertEqual(app.staticTexts["time-1"].label, "Time not recorded")
        // Four versions now: the oldest is still the one that made the item.
        XCTAssertEqual(scrollTo(app.staticTexts["said-3"], in: app).label, "Made the item")
    }

    func testADeletedNoteComesBackAsItWas() {
        let app = unlocked()
        reveal(app.buttons["recently-deleted"], in: app)
        XCTAssert(app.staticTexts["deleted:A note that was deleted"].waitForExistence(timeout: 20))
        capture("history-3-deleted")
        app.buttons["restore:A note that was deleted"].waitAndTap()
        XCTAssert(app.staticTexts["detail-notes"].waitForLabel("gone", timeout: 20))
        app.buttons["back"].waitAndTap()
        XCTAssert(app.buttons["item:A note that was deleted"].waitForExistence(timeout: 20))
        reveal(app.buttons["recently-deleted"], in: app)
        XCTAssert(app.staticTexts["deleted-hint"].waitForLabel("Nothing has been deleted.", timeout: 20))
    }

    func testAnItemInConflictIsRestoredOnAComputer() {
        let app = unlocked()
        openHistory("Shared, as this device has it", in: app)
        XCTAssert(app.staticTexts["restore-elsewhere"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["restore-1"].exists)
        XCTAssertFalse(app.buttons["restore-2"].exists)
    }
}
