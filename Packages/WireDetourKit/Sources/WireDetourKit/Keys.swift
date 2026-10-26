import CryptoKit
import Foundation

/// WireGuard Curve25519 keys in their base64 text form.
public enum WireGuardKey {
    public static func generatePrivateKey() -> String {
        Curve25519.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString()
    }

    /// Derives the public key for a base64 private key, or nil if invalid.
    public static func publicKey(forPrivateKey privateKey: String) -> String? {
        guard let raw = rawKey(privateKey),
              let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw) else { return nil }
        return key.publicKey.rawRepresentation.base64EncodedString()
    }

    public static func generatePresharedKey() -> String {
        SymmetricKey(size: .bits256).withUnsafeBytes { Data($0).base64EncodedString() }
    }

    public static func isValid(_ key: String) -> Bool { rawKey(key) != nil }

    /// 32 raw key bytes from base64, or nil.
    public static func rawKey(_ key: String) -> Data? {
        guard let d = Data(base64Encoded: key.trimmingCharacters(in: .whitespaces)), d.count == 32 else { return nil }
        return d
    }

    /// Lowercase hex, as the wireguard-go UAPI expects.
    public static func hex(_ key: String) -> String? {
        rawKey(key).map { $0.map { String(format: "%02x", $0) }.joined() }
    }
}
