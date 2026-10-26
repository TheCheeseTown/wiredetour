import Foundation
import Network

/// An IPv4 or IPv6 address with a prefix length, e.g. `10.0.0.0/24` or `fd00::1/128`.
public struct IPAddressRange: Hashable, Sendable, Codable, CustomStringConvertible {
    public enum Family: Sendable { case v4, v6 }

    /// Raw address bytes: 4 for IPv4, 16 for IPv6.
    public let bytes: Data
    public let prefixLength: UInt8

    public var family: Family { bytes.count == 4 ? .v4 : .v6 }
    public var maxPrefixLength: UInt8 { family == .v4 ? 32 : 128 }

    /// Parses `addr` or `addr/prefix`. A bare address gets a host prefix.
    public init?(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let addrPart = parts.first, !addrPart.isEmpty else { return nil }
        let addr = String(addrPart)
        if let v4 = IPv4Address(addr), !addr.contains(":") {
            bytes = v4.rawValue
        } else if let v6 = IPv6Address(addr) {
            bytes = v6.rawValue
        } else {
            return nil
        }
        let maxLen: UInt8 = bytes.count == 4 ? 32 : 128
        if parts.count == 2 {
            guard let len = UInt8(parts[1]), len <= maxLen else { return nil }
            prefixLength = len
        } else {
            prefixLength = maxLen
        }
    }

    public init(bytes: Data, prefixLength: UInt8) {
        self.bytes = bytes
        self.prefixLength = prefixLength
    }

    /// The address part in canonical text form.
    public var address: String {
        if family == .v4, let a = IPv4Address(bytes) { return "\(a)" }
        if let a = IPv6Address(bytes) { return "\(a)" }
        return ""
    }

    public var description: String { "\(address)/\(prefixLength)" }

    /// The network address with host bits cleared.
    public var masked: IPAddressRange {
        var out = bytes
        for i in 0..<out.count {
            let bitsBefore = i * 8
            let keep = max(0, min(8, Int(prefixLength) - bitsBefore))
            let mask: UInt8 = keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - keep))
            out[out.startIndex + i] &= mask
        }
        return IPAddressRange(bytes: out, prefixLength: prefixLength)
    }

    /// Dotted subnet mask for IPv4 (used by `NEIPv4Route`).
    public var subnetMask: String {
        precondition(family == .v4)
        let value: UInt32 = prefixLength == 0 ? 0 : UInt32.max << (32 - UInt32(prefixLength))
        return [24, 16, 8, 0].map { String((value >> $0) & 0xff) }.joined(separator: ".")
    }

    public func contains(_ other: IPAddressRange) -> Bool {
        guard other.family == family, other.prefixLength >= prefixLength else { return false }
        let narrowed = IPAddressRange(bytes: other.bytes, prefixLength: prefixLength).masked
        return narrowed.bytes == masked.bytes
    }

    public init(from decoder: Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        guard let r = IPAddressRange(s) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid address range \(s)"))
        }
        self = r
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(description)
    }
}

/// Whether `s` is a literal IPv4 or IPv6 address (no prefix).
public func isIPAddress(_ s: String) -> Bool {
    IPv4Address(s) != nil || IPv6Address(s) != nil
}
