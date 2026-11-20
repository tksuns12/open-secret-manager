import XCTest

let fixturePassword = "fixture password, not a secret"

/// The frozen format 7 vault, copied into the test bundle by prepare.sh.
let frozenVault = Bundle(for: AppTests.self).path(forResource: "format-7-vault", ofType: "sqlite3")!

let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

/// How long the first screen of a program just started may take: macOS may
/// hold the first start of a newly built program file for most of a minute
/// while it checks it, and the simulator's programs are such files.
let startTimeout: TimeInterval = 120

/// With OSM_TEST_SCREENS naming a folder, saves what the screen shows there,
/// for a person to look at; otherwise does nothing.
func capture(_ name: String) {
    guard let folder = ProcessInfo.processInfo.environment["OSM_TEST_SCREENS"] else { return }
    Thread.sleep(forTimeInterval: 0.7)
    try? XCUIScreen.main.screenshot().pngRepresentation.write(to: URL(fileURLWithPath: "\(folder)/\(name).png"))
}

/// Launches the app with `vault` (a vault file, or nil for none) where it
/// keeps its vault, and nothing kept for Face ID; with `scanned`, what its
/// camera reads when the owner scans an invitation.
func launchApp(vault: String?, scanned: String? = nil) -> XCUIApplication {
    let app = XCUIApplication()
    app.launchEnvironment["OSM_TEST_VAULT"] = vault ?? "none"
    app.launchEnvironment["OSM_TEST_BIOMETRICS"] = "off"
    if let scanned { app.launchEnvironment["OSM_TEST_SCANNED"] = scanned }
    app.launch()
    return app
}

/// Unlocks with the password in the app's or the fill screen's unlock.
func unlock(in app: XCUIApplication, password: String = fixturePassword, file: StaticString = #filePath, line: UInt = #line) {
    let field = app.secureTextFields["password"].firstMatch
    XCTAssert(field.waitForExistence(timeout: startTimeout), "no unlock screen", file: file, line: line)
    field.tap()
    field.typeText(password)
    app.buttons["unlock"].firstMatch.tap()
}

let fixture = XCUIApplication(bundleIdentifier: "org.opensecretmanager.loginfixture")

/// In the unlocked app's list: makes the app the AutoFill provider, if it
/// is not yet, through the system's own prompt, which is offered in the
/// settings. Leaves the app at its list again.
func turnOnAutoFill(in app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) {
    let settings = app.buttons["settings"]
    guard settings.waitForExistence(timeout: 10) else { return }
    settings.tap()
    defer { app.buttons["back"].firstMatch.waitAndTap() }
    let turnOn = app.buttons["turn-on-autofill"]
    guard turnOn.waitForExistence(timeout: 10) else { return }
    turnOn.tap()
    let inAlert = springboard.alerts.buttons["Turn On"]
    XCTAssert(inAlert.waitForExistence(timeout: 20), "no prompt to turn on AutoFill", file: file, line: line)
    capture("fill-0-turn-on")
    inAlert.settledTap(file: file, line: line) { !inAlert.exists }
    XCTAssert(turnOn.waitForNonExistence(timeout: 10), file: file, line: line)
}

/// Opens the stand-in app's form and chooses Open Secret Manager in the
/// keyboard's Passwords, as the owner would, until the fill screen shows.
func askToFill(file: StaticString = #filePath, line: UInt = #line) {
    fixture.launch()
    fixture.textFields["fixture-username"].waitAndTap(timeout: startTimeout, file: file, line: line)
    let ours = fixture.buttons["Open Secret Manager"]
    // iOS 27 at times shows the keyboard without its bar of suggestions,
    // and brings it with the focus moved away and back, as an owner would.
    if !fixture.buttons["Passwords"].waitForExistence(timeout: 10) {
        fixture.secureTextFields["fixture-password"].tap()
        fixture.textFields["fixture-username"].tap()
    }
    XCTAssert(fixture.buttons["Passwords"].waitForExistence(timeout: 20), "no Passwords key", file: file, line: line)
    capture("fill-1-keyboard")
    fixture.buttons["Passwords"].settledTap(file: file, line: line) {
        // The keyboard's tip about sliding to type, shown once over the
        // keyboard, takes the tap; scripts/test-mobile-ios.sh says it was
        // seen, and this sees it off if it shows all the same.
        let tip = fixture.buttons["Continue"]
        if tip.exists { tip.tap() }
        return ours.exists
    }
    capture("fill-2-providers")
    ours.settledTap(file: file, line: line) { !ours.exists }
    XCTAssert(fixture.staticTexts["asker"].waitForExistence(timeout: startTimeout), "no fill screen", file: file, line: line)
}

/// Opens the stand-in app's form and asks for text to insert into its
/// account field, as the owner would from iOS 18: the field's menu,
/// AutoFill, Passwords, then the keyboard's Passwords and Open Secret
/// Manager among the providers, until the screen to insert text shows.
/// That screen is shown by the system over the app, in its own tree: it
/// is returned, for the test to drive.
@discardableResult
func askToInsert(file: StaticString = #filePath, line: UInt = #line) -> XCUIApplication {
    fixture.launch()
    let field = fixture.textFields["fixture-username"]
    field.waitAndTap(timeout: startTimeout, file: file, line: line)
    let autofill = fixture.menuItems["AutoFill"]
    // A tap on the field that has the focus shows its menu.
    field.settledTap(file: file, line: line) { autofill.exists }
    capture("insert-1-menu")
    autofill.tap()
    // The menu's entries are known by their images: Passwords by its key.
    let passwords = fixture.cells.containing(.image, identifier: "key.dots").firstMatch
    passwords.waitAndTap(file: file, line: line)
    let ours = springboard.buttons["Open Secret Manager"]
    fixture.buttons["Passwords"].settledTap(file: file, line: line) { ours.exists }
    capture("insert-2-providers")
    ours.settledTap(file: file, line: line) { !ours.exists }
    let deadline = Date().addingTimeInterval(startTimeout)
    while Date() < deadline {
        for shown in [fixture, springboard] where shown.staticTexts["asker"].exists { return shown }
        Thread.sleep(forTimeInterval: 0.5)
    }
    XCTFail("no screen to insert text", file: file, line: line)
    return fixture
}

extension XCUIElement {
    func waitAndTap(timeout: TimeInterval = 20, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssert(waitForExistence(timeout: timeout), "\(self) never appeared", file: file, line: line)
        tap()
    }

    /// Taps once the element can be hit and has settled, and again while
    /// `took` says the tap had no effect: a tap on a sheet or a screen still
    /// moving in can be lost.
    func settledTap(timeout: TimeInterval = 30, file: StaticString = #filePath, line: UInt = #line, took: () -> Bool) {
        XCTAssert(waitForExistence(timeout: timeout), "\(self) never appeared", file: file, line: line)
        let deadline = Date().addingTimeInterval(timeout)
        while !took() && Date() < deadline {
            // A system alert's buttons can say they cannot be hit when they
            // can: after a moment, tap anyway.
            let hittable = Date().addingTimeInterval(2)
            while exists && !isHittable && Date() < hittable { Thread.sleep(forTimeInterval: 0.25) }
            Thread.sleep(forTimeInterval: 0.6)
            if exists { tap() }
            let settle = Date().addingTimeInterval(3)
            while !took() && Date() < settle { Thread.sleep(forTimeInterval: 0.25) }
        }
        XCTAssert(took(), "tapping \(self) had no effect", file: file, line: line)
    }

    /// Waits until the element's label is `expected`; false if it never is.
    func waitForLabel(_ expected: String, timeout: TimeInterval = 15) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if exists && label == expected { return true }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return false
    }
}

/// A UI test that, with OSM_TEST_FAILURES naming a folder, saves there what
/// the screen showed at each failure, and the trees of the apps involved.
class UITestCase: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    override func record(_ issue: XCTIssue) {
        if let folder = ProcessInfo.processInfo.environment["OSM_TEST_FAILURES"] {
            let file = "\(folder)/\(name.filter { $0.isLetter || $0.isNumber })-\(Int(Date().timeIntervalSince1970))"
            try? XCUIScreen.main.screenshot().pngRepresentation.write(to: URL(fileURLWithPath: file + ".png"))
            let trees = [XCUIApplication(), XCUIApplication(bundleIdentifier: "org.opensecretmanager.loginfixture"),
                         XCUIApplication(bundleIdentifier: "com.apple.mobilesafari"), springboard]
                .map(\.debugDescription).joined(separator: "\n\n")
            try? (issue.compactDescription + "\n\n" + trees).write(toFile: file + ".txt", atomically: true, encoding: .utf8)
        }
        super.record(issue)
    }
}
