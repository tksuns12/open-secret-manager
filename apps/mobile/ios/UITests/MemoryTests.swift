import XCTest

/// The app and its AutoFill extension unlocking a vault made at the real
/// password-hashing cost, for scripts/measure-ios-memory.sh, which samples
/// both processes' memory meanwhile. Skipped without OSM_TEST_MEMORY_VAULT
/// (the vault file) and OSM_TEST_MEMORY_PASSWORD.
final class MemoryTests: UITestCase {
    func testTheFillScreenUnlocksAVaultAtTheRealCost() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let vault = environment["OSM_TEST_MEMORY_VAULT"], let password = environment["OSM_TEST_MEMORY_PASSWORD"] else {
            throw XCTSkip("run by scripts/measure-ios-memory.sh")
        }
        let app = launchApp(vault: vault)
        unlock(in: app, password: password)
        XCTAssert(app.buttons["lock"].waitForExistence(timeout: 60))
        turnOnAutoFill(in: app)
        XCUIDevice.shared.press(.home)
        askToFill()
        unlock(in: fixture, password: password)
        XCTAssert(fixture.staticTexts["warning"].waitForExistence(timeout: 60))
        // For the sampler to see the extension after the unlock.
        Thread.sleep(forTimeInterval: 3)
        fixture.buttons["cancel"].tap()
    }
}
