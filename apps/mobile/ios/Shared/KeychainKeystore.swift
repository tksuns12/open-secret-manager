import CryptoKit
import Foundation
import Security

/// The iOS Keychain, which seals this device's network (TLS) key so that
/// the app's files alone do not give it away. Each sealing makes a 256-bit
/// key of its own, kept in the Keychain under a random name, on this phone
/// only and readable after the phone's first unlock, so that a sync in the
/// background can open the network key while the phone is locked. The
/// network key is sealed under it with AES-GCM. What is stored in the
/// device's folder is the name, the nonce, and the sealed key. The app and
/// its AutoFill extension share the Keychain's items through their app
/// group, as they share the folder.
final class KeychainKeystore: PhoneKeystore {
    static let shared = KeychainKeystore()

    private static let service = "org.opensecretmanager.transport-key"
    /// The form of what `seal` returns.
    private static let form: UInt8 = 1
    private static let nameLength = 16
    private static let nonceLength = 12

    private func query(_ name: Data) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: name.map { String(format: "%02x", $0) }.joined(),
            kSecAttrAccessGroup as String: DeviceFolder.appGroup,
        ]
    }

    /// What is bound to the sealed key besides the key: its form and its name.
    private func bound(_ name: Data) -> Data {
        Data("osm transport key".utf8) + [Self.form] + name
    }

    private func random(_ count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw KeystoreFailure.Unavailable }
        return bytes
    }

    func seal(key: Data) throws -> Data {
        let name = try random(Self.nameLength)
        let wrapping = SymmetricKey(size: .bits256)
        guard let box = try? AES.GCM.seal(key, using: wrapping, authenticating: bound(name)),
              box.nonce.withUnsafeBytes({ $0.count }) == Self.nonceLength
        else { throw KeystoreFailure.Unavailable }
        var item = query(name)
        item[kSecValueData as String] = wrapping.withUnsafeBytes { Data($0) }
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw KeystoreFailure.Unavailable
        }
        return Data([Self.form]) + name + Data(box.nonce) + box.ciphertext + box.tag
    }

    func open(sealed: Data) throws -> Data {
        let sealed = Data(sealed)
        // Not in this form, or cut short: nothing this keystore sealed.
        guard sealed.count >= 1 + Self.nameLength + Self.nonceLength + 16, sealed.first == Self.form else {
            throw KeystoreFailure.Lost
        }
        let name = sealed.subdata(in: 1 ..< 1 + Self.nameLength)
        let body = sealed.subdata(in: 1 + Self.nameLength ..< sealed.count)
        var lookup = query(name)
        lookup[kSecReturnData as String] = true
        var result: CFTypeRef?
        switch SecItemCopyMatching(lookup as CFDictionary, &result) {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            throw KeystoreFailure.Lost
        default:
            throw KeystoreFailure.Unavailable
        }
        guard let wrapping = result as? Data, wrapping.count == 32,
              let box = try? AES.GCM.SealedBox(combined: body),
              let key = try? AES.GCM.open(box, using: SymmetricKey(data: wrapping), authenticating: bound(name))
        else { throw KeystoreFailure.Lost }
        return key
    }

    /// Forgets every key this keystore made: for tests only.
    func forgetEverything() {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccessGroup as String: DeviceFolder.appGroup,
        ] as CFDictionary)
    }
}
