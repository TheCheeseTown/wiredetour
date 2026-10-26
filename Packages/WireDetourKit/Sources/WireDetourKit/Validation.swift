import Foundation

public struct ValidationIssue: Equatable, Sendable, Identifiable {
    public var id: String { message }
    public let message: String
}

extension TunnelConfiguration {
    /// Problems that prevent the tunnel from starting. Empty means valid.
    public var validationIssues: [ValidationIssue] {
        var issues: [String] = []
        if name.trimmingCharacters(in: .whitespaces).isEmpty { issues.append("The tunnel needs a name.") }
        if !WireGuardKey.isValid(interface.privateKey) { issues.append("The private key is missing or invalid.") }
        if interface.addresses.isEmpty { issues.append("The interface needs at least one Address.") }
        if interface.dnsServers.isEmpty {
            // D6: matched domains are resolved by this server through the tunnel.
            issues.append("Add a DNS server (DNS = …). wireDetour resolves your domains with it through the tunnel.")
        }
        if peers.isEmpty { issues.append("Add at least one [Peer].") }
        for (i, peer) in peers.enumerated() {
            let label = peers.count > 1 ? "Peer \(i + 1)" : "The peer"
            if !WireGuardKey.isValid(peer.publicKey) { issues.append("\(label) has a missing or invalid public key.") }
            if let psk = peer.presharedKey, !WireGuardKey.isValid(psk) { issues.append("\(label) has an invalid preshared key.") }
            if peer.allowedIPs.isEmpty { issues.append("\(label) needs AllowedIPs.") }
        }
        if domains.isEmpty && networks.isEmpty {
            issues.append("Add at least one domain or network to send through the tunnel.")
        }
        return issues.map(ValidationIssue.init(message:))
    }

    /// Non-fatal hints shown in the editor.
    public var warnings: [ValidationIssue] {
        var out: [String] = []
        let allowed = peers.flatMap(\.allowedIPs)
        for net in networks where !allowed.contains(where: { $0.contains(net) }) {
            out.append("\(net) is outside every peer's AllowedIPs, so traffic to it will be dropped.")
        }
        if !peers.contains(where: { $0.endpoint != nil }) {
            out.append("No peer has an Endpoint, so this device can't start the connection.")
        }
        return out.map(ValidationIssue.init(message:))
    }
}
