#if DEBUG
import Foundation

/// Only in a debug build: what the UI tests ask for at launch, before the
/// device's folder is opened. `OSM_TEST_VAULT` empties the folder and, unless
/// it is `none`, puts the vault file it names there; `OSM_TEST_BIOMETRICS=off`
/// forgets a password kept for Face ID or Touch ID. And
/// `OSM_TEST_CHANGE_WHILE_EDITING` (`<item id>|<notes>|<password>`) changes
/// that item's notes through a second device object on the folder as the
/// editor opens for it, as a sync could while the owner edits.
/// `OSM_TEST_SCANNED` is what the camera reads when the owner scans an
/// invitation, as the simulator has no camera.
enum TestSupport {
    private static var prepared = false

    static var scanned: String? { ProcessInfo.processInfo.environment["OSM_TEST_SCANNED"] }

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

    static func changeWhileEditing(_ id: String) {
        guard let asked = ProcessInfo.processInfo.environment["OSM_TEST_CHANGE_WHILE_EDITING"] else { return }
        let parts = asked.split(separator: "|", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[0] == id, let folder = try? DeviceFolder.url() else { return }
        guard let other = try? Device.open(folder: folder.path, keystore: KeychainKeystore.shared), (try? other.unlock(password: parts[2])) != nil,
              let item = try? other.item(id: id) else { return }
        try? other.updateItem(id: id, revision: item.revision, draft: ItemDraft(
            title: item.title, kind: item.kind, username: item.username, url: item.url,
            notes: parts[1], favorite: item.favorite, password: nil, oneTimeCodeSecret: nil
        ))
        other.lock()
    }
}
#endif
