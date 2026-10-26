import Foundation
import Security

/// Stores whole `.conf` texts (which contain private keys) in the Keychain,
/// shared between the app and the tunnel extension (D11). The VPN profile only
/// keeps a persistent reference to the item.
public enum Keychain {
    /// Keychain access group shared by app and extension, read from the
    /// `WDKeychainAccessGroup` Info.plist key (set from the build settings).
    public static var accessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "WDKeychainAccessGroup") as? String
    }

    public enum Error: Swift.Error, LocalizedError {
        case status(OSStatus)
        public var errorDescription: String? {
            if case .status(let s) = self {
                return (SecCopyErrorMessageString(s, nil) as String?) ?? "Keychain error \(s)"
            }
            return nil
        }
    }

    /// Adds a new item and returns its persistent reference.
    public static func add(config: String, label: String) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "wireDetour",
            kSecAttrAccount as String: UUID().uuidString,
            kSecAttrLabel as String: "wireDetour: \(label)",
            kSecValueData as String: Data(config.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnPersistentRef as String: true,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup as String] = group }
        var result: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &result)
        guard status == errSecSuccess, let ref = result as? Data else { throw Error.status(status) }
        return ref
    }

    public static func load(reference: Data) throws -> String {
        let query: [String: Any] = [
            kSecValuePersistentRef as String: reference,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let text = String(data: data, encoding: .utf8) else {
            throw Error.status(status)
        }
        return text
    }

    public static func update(reference: Data, config: String) throws {
        let query: [String: Any] = [
            kSecValuePersistentRef as String: reference,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: Data(config.utf8)] as CFDictionary)
        guard status == errSecSuccess else { throw Error.status(status) }
    }

    public static func delete(reference: Data) {
        let query: [String: Any] = [
            kSecValuePersistentRef as String: reference,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
