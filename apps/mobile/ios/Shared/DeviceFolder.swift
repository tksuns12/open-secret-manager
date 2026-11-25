import Foundation

/// Where the device's files are kept: in the container the app shares with
/// its AutoFill extension, which opens the same vault to fill a login.
enum DeviceFolder {
    static let appGroup = "group.org.opensecretmanager.app"

    struct Unavailable: Error {}

    static func url() throws -> URL {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            throw Unavailable()
        }
        var folder = container.appendingPathComponent("vault", isDirectory: true)
        let protection: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: protection)
        try? FileManager.default.setAttributes(protection, ofItemAtPath: folder.path)
        // Upgrade any pre-existing vault files to complete file protection.
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: folder.path) {
            for name in entries {
                try? FileManager.default.setAttributes(protection, ofItemAtPath: folder.appendingPathComponent(name).path)
            }
        }
        // Not in backups: the vault and the device's keys stay on this
        // phone. A copy elsewhere would be a second device under this one's
        // identity.
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try folder.setResourceValues(values)
        return folder
    }
}
