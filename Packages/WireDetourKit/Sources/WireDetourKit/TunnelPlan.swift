import Foundation

/// Firefox disables its own DNS-over-HTTPS when this resolves to NXDOMAIN (D7).
public let canaryDomain = "use-application-dns.net"

/// Everything the packet tunnel needs, derived from a configuration (§3.3).
/// Pure data so it can be unit-tested without NetworkExtension.
public struct TunnelPlan: Equatable, Sendable {
    public var ipv4Addresses: [IPAddressRange]
    public var ipv6Addresses: [IPAddressRange]
    public var dnsServers: [String]
    /// Only these domains' queries reach the tunnel (D5).
    public var matchDomains: [String]
    /// Static routes: Networks plus the DNS servers as host routes (D10, D15).
    public var staticRoutes: [IPAddressRange]
    public var mtu: Int

    public init(_ c: TunnelConfiguration) {
        ipv4Addresses = c.interface.addresses.filter { $0.family == .v4 }
        ipv6Addresses = c.interface.addresses.filter { $0.family == .v6 }
        dnsServers = c.interface.dnsServers
        matchDomains = c.domains + [canaryDomain]
        var routes = c.networks.map(\.masked)
        for s in c.interface.dnsServers {
            if let r = IPAddressRange(s), !routes.contains(where: { $0.contains(r) }) {
                routes.append(r)
            }
        }
        staticRoutes = routes
        mtu = Int(c.interface.mtu ?? 1280)
    }

    /// Static routes plus the dynamic ones from the engine (D4).
    public func routes(adding dynamic: [IPAddressRange]) -> (v4: [IPAddressRange], v6: [IPAddressRange]) {
        let all = staticRoutes + dynamic
        return (all.filter { $0.family == .v4 }, all.filter { $0.family == .v6 })
    }
}

/// Configuration passed as JSON to the Go engine (core/engine.Config).
public struct EngineConfig: Codable, Equatable, Sendable {
    public var dnsServers: [String]
    public var domains: [String]
    public var staticRoutes: [String]
    public var allowedIPs: [String]
    public var interfaceAddrs: [String]
    public var dynamicRoutes: Bool

    public init(_ c: TunnelConfiguration, plan: TunnelPlan, dynamicRoutes: Bool = true) {
        dnsServers = c.interface.dnsServers
        domains = c.domains
        staticRoutes = plan.staticRoutes.map(\.description)
        allowedIPs = c.peers.flatMap(\.allowedIPs).map(\.description)
        interfaceAddrs = c.interface.addresses.map(\.address)
        self.dynamicRoutes = dynamicRoutes
    }
}

extension TunnelConfiguration {
    /// The wireguard-go UAPI configuration. `resolvedEndpoints[i]` is the
    /// numeric endpoint for peer i (hostnames must be resolved beforehand).
    public func uapiConfiguration(resolvedEndpoints: [Endpoint?]) -> String {
        var lines: [String] = []
        if let k = WireGuardKey.hex(interface.privateKey) { lines.append("private_key=\(k)") }
        if let p = interface.listenPort { lines.append("listen_port=\(p)") }
        lines.append("replace_peers=true")
        for (i, peer) in peers.enumerated() {
            guard let pk = WireGuardKey.hex(peer.publicKey) else { continue }
            lines.append("public_key=\(pk)")
            if let psk = peer.presharedKey.flatMap(WireGuardKey.hex) { lines.append("preshared_key=\(psk)") }
            if i < resolvedEndpoints.count, let e = resolvedEndpoints[i] { lines.append("endpoint=\(e)") }
            lines.append("persistent_keepalive_interval=\(peer.persistentKeepalive ?? 0)")
            lines.append("replace_allowed_ips=true")
            for ip in peer.allowedIPs { lines.append("allowed_ip=\(ip.masked)") }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
