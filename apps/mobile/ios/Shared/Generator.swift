import Foundation

/// What the password generator makes on this phone, kept in the app group's
/// defaults beside the logins chosen for apps: the shared code's choice
/// until the owner changes it in the editor.
enum Generator {
    private static let key = "generator"
    /// The lengths offered.
    static let lengths: ClosedRange<UInt32> = 8...64

    /// The owner's choice, or the shared code's if none is kept, or one kept
    /// is not one it can be.
    static var options: PasswordOptions {
        get {
            let defaults = defaultPasswordOptions()
            guard let kept = UserDefaults(suiteName: DeviceFolder.appGroup)?.dictionary(forKey: key),
                  let length = kept["length"] as? Int, length >= 0,
                  let lowercase = kept["lowercase"] as? Bool, let uppercase = kept["uppercase"] as? Bool,
                  let digits = kept["digits"] as? Bool, let symbols = kept["symbols"] as? Bool,
                  let avoidLookAlike = kept["avoidLookAlike"] as? Bool
            else { return defaults }
            let options = PasswordOptions(
                length: UInt32(clamping: length), lowercase: lowercase, uppercase: uppercase,
                digits: digits, symbols: symbols, avoidLookAlike: avoidLookAlike
            )
            return allowed(options) ? options : defaults
        }
        set {
            guard allowed(newValue) else { return }
            UserDefaults(suiteName: DeviceFolder.appGroup)?.set([
                "length": Int(newValue.length), "lowercase": newValue.lowercase, "uppercase": newValue.uppercase,
                "digits": newValue.digits, "symbols": newValue.symbols, "avoidLookAlike": newValue.avoidLookAlike,
            ], forKey: key)
        }
    }

    /// Back to the shared code's choice: for tests.
    static func forget() {
        UserDefaults(suiteName: DeviceFolder.appGroup)?.removeObject(forKey: key)
    }

    private static func allowed(_ options: PasswordOptions) -> Bool {
        lengths.contains(options.length) && (options.lowercase || options.uppercase || options.digits || options.symbols)
    }
}
