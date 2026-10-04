import UIKit
import UniformTypeIdentifiers

/// The pasteboard, for what the owner copies: kept on this phone, not sent
/// to the owner's other Apple devices, and a secret removed after 30 seconds.
enum SecretPasteboard {
    static func copy(_ value: String, secret: Bool) {
        var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
        if secret { options[.expirationDate] = Date().addingTimeInterval(30) }
        UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: value]], options: options)
    }
}
