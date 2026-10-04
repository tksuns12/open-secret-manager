import Foundation
import LocalAuthentication
import Security

/// Unlocking with Face ID or Touch ID: the device's password, kept in the
/// keychain on this phone only, readable after a biometric check, and lost
/// when the enrolled faces or fingers change. The app and its AutoFill
/// extension share it through their app group.
struct BiometricUnlock {
    private static let service = "org.opensecretmanager.device-password"

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: "device",
            kSecAttrAccessGroup as String: DeviceFolder.appGroup,
        ]
    }

    /// Whether the phone can check a face or a finger at all.
    var available: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    /// "Face ID" or "Touch ID", as the phone has it.
    var name: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType == .faceID ? "Face ID" : "Touch ID"
    }

    /// Whether a password is kept, without asking for a face or a finger.
    var enabled: Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        var lookup = query
        lookup[kSecUseAuthenticationContext as String] = context
        let status = SecItemCopyMatching(lookup as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Keeps `password` for the next unlock; false if the phone has no
    /// passcode, without which it keeps nothing behind a biometric check.
    @discardableResult
    func keep(_ password: String) -> Bool {
        disable()
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil
        ) else { return false }
        var item = query
        item[kSecValueData as String] = Data(password.utf8)
        item[kSecAttrAccessControl as String] = access
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
    }

    /// What asking for the kept password came to.
    enum Outcome {
        case password(String)
        /// The owner cancelled, or chose to type the password.
        case cancelled
        /// Why it did not work, as the owner reads it.
        case failed(String)
    }

    /// The kept password, after the phone checked a face or a finger. Blocks
    /// while the phone asks: call it off the main thread.
    func read(reason: String) -> Outcome {
        // The check first, and the item read with the context that passed
        // it: a phone's keychain requires the check for the item anyway, but
        // the simulator's does not, and this way it is asked there too.
        let context = LAContext()
        let checked = DispatchSemaphore(value: 0)
        var failure: Error?
        var passed = false
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            passed = success
            failure = error
            checked.signal()
        }
        checked.wait()
        guard passed else {
            switch (failure as? LAError)?.code {
            case .userCancel?, .userFallback?, .appCancel?: return .cancelled
            case .biometryLockout?: return .failed("\(name) is locked after too many tries · use the password")
            case .biometryNotEnrolled?, .biometryNotAvailable?: return .failed("\(name) is not set up on this phone · use the password")
            default: return .failed(failure?.localizedDescription ?? "\(name) did not unlock")
            }
        }
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecUseAuthenticationContext as String] = context
        var result: AnyObject?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let password = String(data: data, encoding: .utf8) else {
            if status == errSecUserCanceled { return .cancelled }
            // The check passed but the item is gone or unusable, as when the
            // enrolled faces or fingers changed: forget it, so that the next
            // unlock is with the password.
            if status != errSecInteractionNotAllowed { disable() }
            return .failed("Unlock with the password once: the enrolled faces or fingers changed")
        }
        return .password(password)
    }

    func disable() {
        SecItemDelete(query as CFDictionary)
    }
}
