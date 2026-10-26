import Foundation

/// Messages the app sends to the running tunnel extension via
/// `NETunnelProviderSession.sendProviderMessage`.
public enum AppMessage: Codable, Sendable {
    case status
    case testDomain(String)

    public func encoded() -> Data { (try? JSONEncoder().encode(self)) ?? Data() }
    public static func decode(_ data: Data) -> AppMessage? { try? JSONDecoder().decode(AppMessage.self, from: data) }
}

/// Live status (D19), mirrors the JSON produced by core/bridge `wdGetStatus`.
public struct LiveStatus: Codable, Equatable, Sendable {
    public struct WireGuard: Codable, Equatable, Sendable {
        /// Seconds since the most recent handshake across peers; nil if none yet.
        public var lastHandshakeSecAgo: Int?
        public var rxBytes: UInt64
        public var txBytes: UInt64
    }
    public struct Domain: Codable, Equatable, Sendable, Identifiable {
        public var id: String { domain }
        public var domain: String
        public var ips: [String]?
        public var warnings: [String]?
        public var error: String?
        public var atUnix: Int64
    }
    public struct Route: Codable, Equatable, Sendable, Identifiable {
        public var id: String { prefix }
        public var prefix: String
        public var domains: [String]?
        public var expiresInSec: Int
        public var lastUsedSecAgo: Int
    }
    public struct Failure: Codable, Equatable, Sendable {
        public var domain: String
        public var reason: String
        public var atUnix: Int64
    }
    public struct Engine: Codable, Equatable, Sendable {
        public var domains: [Domain]?
        public var routes: [Route]?
        public var staticRoutes: [String]?
        public var failures: [Failure]?
        public var dynamicMode: Bool
    }

    public var wireguard: WireGuard
    public var engine: Engine
}

/// Result of "Test this rule" (D24), mirrors core/engine.TestResult.
public struct DomainTestResult: Codable, Equatable, Sendable {
    public struct Address: Codable, Equatable, Sendable, Identifiable {
        public var id: String { ip }
        public var ip: String
        public var viaTunnel: Bool
        public var inAllowedIPs: Bool
        public var lastUsedSecAgo: Int
    }
    public var domain: String
    public var matched: Bool
    public var rcode: String?
    public var error: String?
    public var ips: [Address]?
}
