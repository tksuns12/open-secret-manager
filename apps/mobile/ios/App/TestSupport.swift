#if DEBUG
import Foundation

/// Only in a debug build: what the UI tests ask for at launch, before the
/// device's folder is opened. `OSM_TEST_VAULT` empties the folder and, unless
/// it is `none`, puts the vault file it names there; `OSM_TEST_BIOMETRICS=off`
/// forgets a password kept for Face ID or Touch ID.
enum TestSupport {
    private static var prepared = false

    static func prepareOnce(_ folder: URL) {
        guard !prepared else { return }
        prepared = true
        let environment = ProcessInfo.processInfo.environment
        if environment["OSM_TEST_BIOMETRICS"] == "off" { BiometricUnlock().disable() }
        guard let vault = environment["OSM_TEST_VAULT"] else { return }
        let files = FileManager.default
        for name in (try? files.contentsOfDirectory(atPath: folder.path)) ?? [] {
            try? files.removeItem(at: folder.appendingPathComponent(name))
        }
        UserDefaults(suiteName: DeviceFolder.appGroup)?.removeObject(forKey: "app-logins")
        if vault != "none" {
            try? files.copyItem(at: URL(fileURLWithPath: vault), to: folder.appendingPathComponent("vault.sqlite3"))
        }
    }
}
#endif
