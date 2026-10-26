import Foundation

/// One tunnel: a standard wg-quick configuration plus wireDetour's split-DNS
/// rules, which are stored in the same file as `#! SplitDNS.*` comment
/// directives so the file stays valid for every WireGuard tool (D9).
public struct TunnelConfiguration: Equatable, Sendable {
    public var name: String
    public var interface: InterfaceConfig
    public var peers: [PeerConfig]
    /// Suffix-matched domains whose DNS and traffic go through the tunnel (D5, D15).
    public var domains: [String]
    /// Static networks routed into the tunnel (D15).
    public var networks: [IPAddressRange]

    /// Comment lines before the first section, kept for round-trips.
    public var headerLines: [String] = []
    /// Directives with keys we don't know (from newer versions), kept verbatim.
    public var unknownDirectives: [String] = []

    public init(name: String, interface: InterfaceConfig, peers: [PeerConfig], domains: [String] = [], networks: [IPAddressRange] = []) {
        self.name = name
        self.interface = interface
        self.peers = peers
        self.domains = domains
        self.networks = networks
    }
}

public struct InterfaceConfig: Equatable, Sendable {
    public var privateKey: String
    public var addresses: [IPAddressRange] = []
    /// `DNS =` entries that are IP addresses: the upstream for matched domains (D6).
    public var dnsServers: [String] = []
    /// `DNS =` entries that are names (search domains in wg-quick). Preserved, unused.
    public var dnsSearch: [String] = []
    public var listenPort: UInt16?
    public var mtu: UInt16?
    /// Comments and wg-quick-only keys (PostUp, Table, …) kept verbatim.
    public var extraLines: [String] = []

    public init(privateKey: String) {
        self.privateKey = privateKey
    }
}

public struct PeerConfig: Equatable, Sendable {
    public var publicKey: String
    public var presharedKey: String?
    public var endpoint: Endpoint?
    /// The WireGuard peer filter only; never turned into OS routes (D10).
    public var allowedIPs: [IPAddressRange] = []
    public var persistentKeepalive: UInt16?
    public var extraLines: [String] = []

    public init(publicKey: String) {
        self.publicKey = publicKey
    }
}

public struct Endpoint: Equatable, Sendable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// Parses `host:port`, `1.2.3.4:port` or `[v6]:port`.
    public init?(_ string: String) {
        let s = string.trimmingCharacters(in: .whitespaces)
        let hostPart: Substring
        let portPart: Substring
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            hostPart = s[s.index(after: s.startIndex)..<close]
            let rest = s[s.index(after: close)...]
            guard rest.hasPrefix(":") else { return nil }
            portPart = rest.dropFirst()
        } else {
            guard let colon = s.lastIndex(of: ":") else { return nil }
            hostPart = s[..<colon]
            portPart = s[s.index(after: colon)...]
            if hostPart.contains(":") { return nil } // bare IPv6 needs brackets
        }
        guard !hostPart.isEmpty, let port = UInt16(portPart), port != 0 else { return nil }
        self.host = String(hostPart)
        self.port = port
    }

    public var description: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

// MARK: - Domains

public enum DomainRule {
    /// Normalizes user input into a rule domain: lowercased, no wildcard prefix,
    /// no trailing dot. Returns nil if it isn't a valid hostname suffix.
    public static func normalize(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("*.") { s.removeFirst(2) }
        if s.hasPrefix(".") { s.removeFirst() }
        if s.hasSuffix(".") { s.removeLast() }
        guard !s.isEmpty, s.count <= 253, !isIPAddress(s) else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-_")
        for label in s.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.count <= 63,
                  label.unicodeScalars.allSatisfy(allowed.contains),
                  !label.hasPrefix("-"), !label.hasSuffix("-") else { return nil }
        }
        return s
    }
}
