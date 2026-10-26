import Foundation

/// Reads and writes the wg-quick `.conf` format, including wireDetour's
/// `#! SplitDNS.Domain = …` / `#! SplitDNS.Route = …` directives (D9).
public enum WgQuickFormat {
    public static let directivePrefix = "#!"
    public static let directiveNamespace = "SplitDNS."

    public struct ParseError: Error, Equatable, LocalizedError {
        public let line: Int
        public let message: String
        public var errorDescription: String? { "Line \(line): \(message)" }
    }

    /// wg-quick keys the Apple tunnel can't use but which we keep on round-trip.
    static let wgQuickOnlyInterfaceKeys: Set<String> = ["table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark"]

    private enum Section { case none, interface, peer }

    public static func parse(_ text: String, name: String) throws(ParseError) -> TunnelConfiguration {
        var section = Section.none
        var sawInterface = false
        var iface = InterfaceConfig(privateKey: "")
        var peers: [PeerConfig] = []
        var domains: [String] = []
        var networks: [IPAddressRange] = []
        var header: [String] = []
        var unknownDirectives: [String] = []
        var seenKeys: Set<String> = []

        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false)
        for (index, rawLine) in lines.enumerated() {
            let lineNo = index + 1
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }

            if line.hasPrefix(directivePrefix) {
                let body = line.dropFirst(directivePrefix.count).trimmingCharacters(in: .whitespaces)
                if body.hasPrefix(directiveNamespace) {
                    guard let (key, value) = splitKeyValue(String(body.dropFirst(directiveNamespace.count))) else {
                        throw ParseError(line: lineNo, message: "Malformed SplitDNS directive")
                    }
                    switch key.lowercased() {
                    case "domain":
                        guard let d = DomainRule.normalize(value) else {
                            throw ParseError(line: lineNo, message: "Invalid domain “\(value)”")
                        }
                        if !domains.contains(d) { domains.append(d) }
                    case "route":
                        guard let r = IPAddressRange(value) else {
                            throw ParseError(line: lineNo, message: "Invalid network “\(value)”")
                        }
                        if !networks.contains(r) { networks.append(r) }
                    default:
                        unknownDirectives.append(line)
                    }
                    continue
                }
            }

            if line.hasPrefix("#") {
                switch section {
                case .none: header.append(line)
                case .interface: iface.extraLines.append(line)
                case .peer: peers[peers.count - 1].extraLines.append(line)
                }
                continue
            }

            if line.hasPrefix("[") {
                switch line.lowercased() {
                case "[interface]":
                    if sawInterface { throw ParseError(line: lineNo, message: "Only one [Interface] section is allowed") }
                    sawInterface = true
                    section = .interface
                case "[peer]":
                    section = .peer
                    peers.append(PeerConfig(publicKey: ""))
                default:
                    throw ParseError(line: lineNo, message: "Unknown section \(line)")
                }
                seenKeys = []
                continue
            }

            // Strip a trailing inline comment.
            let content = line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? line
            guard let (key, value) = splitKeyValue(content) else {
                throw ParseError(line: lineNo, message: "Expected “Key = Value”")
            }
            let k = key.lowercased()
            let repeatable: Set<String> = ["address", "dns", "allowedips"]
            if !repeatable.contains(k) && !wgQuickOnlyInterfaceKeys.contains(k) {
                if seenKeys.contains(k) { throw ParseError(line: lineNo, message: "Duplicate key \(key)") }
                seenKeys.insert(k)
            }

            switch section {
            case .none:
                throw ParseError(line: lineNo, message: "Key outside of a section")
            case .interface:
                switch k {
                case "privatekey": iface.privateKey = value
                case "address":
                    for item in commaList(value) {
                        guard let r = IPAddressRange(item) else { throw ParseError(line: lineNo, message: "Invalid address “\(item)”") }
                        iface.addresses.append(r)
                    }
                case "dns":
                    for item in commaList(value) {
                        if isIPAddress(item) { iface.dnsServers.append(item) } else { iface.dnsSearch.append(item) }
                    }
                case "listenport":
                    guard let p = UInt16(value) else { throw ParseError(line: lineNo, message: "Invalid ListenPort") }
                    iface.listenPort = p
                case "mtu":
                    guard let m = UInt16(value), m >= 576 else { throw ParseError(line: lineNo, message: "Invalid MTU") }
                    iface.mtu = m
                default:
                    if wgQuickOnlyInterfaceKeys.contains(k) {
                        iface.extraLines.append(line)
                    } else {
                        throw ParseError(line: lineNo, message: "Unknown key \(key) in [Interface]")
                    }
                }
            case .peer:
                let i = peers.count - 1
                switch k {
                case "publickey": peers[i].publicKey = value
                case "presharedkey": peers[i].presharedKey = value
                case "endpoint":
                    guard let e = Endpoint(value) else { throw ParseError(line: lineNo, message: "Invalid Endpoint “\(value)”") }
                    peers[i].endpoint = e
                case "allowedips":
                    for item in commaList(value) {
                        guard let r = IPAddressRange(item) else { throw ParseError(line: lineNo, message: "Invalid AllowedIPs entry “\(item)”") }
                        peers[i].allowedIPs.append(r)
                    }
                case "persistentkeepalive":
                    if value.lowercased() == "off" { peers[i].persistentKeepalive = nil; break }
                    guard let v = UInt16(value) else { throw ParseError(line: lineNo, message: "Invalid PersistentKeepalive") }
                    peers[i].persistentKeepalive = v == 0 ? nil : v
                default:
                    throw ParseError(line: lineNo, message: "Unknown key \(key) in [Peer]")
                }
            }
        }

        guard sawInterface else { throw ParseError(line: max(1, lines.count), message: "Missing [Interface] section") }
        var config = TunnelConfiguration(name: name, interface: iface, peers: peers, domains: domains, networks: networks)
        config.headerLines = header
        config.unknownDirectives = unknownDirectives
        return config
    }

    /// Serializes a configuration. When `includeSecrets` is false, keys are
    /// replaced by placeholders (for display).
    public static func serialize(_ c: TunnelConfiguration, includeSecrets: Bool = true) -> String {
        var out: [String] = c.headerLines
        out.append("[Interface]")
        out.append("PrivateKey = \(includeSecrets ? c.interface.privateKey : "(hidden)")")
        if !c.interface.addresses.isEmpty {
            out.append("Address = \(c.interface.addresses.map(\.description).joined(separator: ", "))")
        }
        if let p = c.interface.listenPort { out.append("ListenPort = \(p)") }
        let dns = c.interface.dnsServers + c.interface.dnsSearch
        if !dns.isEmpty { out.append("DNS = \(dns.joined(separator: ", "))") }
        if let m = c.interface.mtu { out.append("MTU = \(m)") }
        out.append(contentsOf: c.interface.extraLines)
        if !c.domains.isEmpty || !c.networks.isEmpty || !c.unknownDirectives.isEmpty {
            out.append("")
            out.append(contentsOf: c.domains.map { "\(directivePrefix) \(directiveNamespace)Domain = \($0)" })
            out.append(contentsOf: c.networks.map { "\(directivePrefix) \(directiveNamespace)Route = \($0)" })
            out.append(contentsOf: c.unknownDirectives)
        }
        for peer in c.peers {
            out.append("")
            out.append("[Peer]")
            out.append("PublicKey = \(peer.publicKey)")
            if let psk = peer.presharedKey { out.append("PresharedKey = \(includeSecrets ? psk : "(hidden)")") }
            if !peer.allowedIPs.isEmpty {
                out.append("AllowedIPs = \(peer.allowedIPs.map(\.description).joined(separator: ", "))")
            }
            if let e = peer.endpoint { out.append("Endpoint = \(e)") }
            if let k = peer.persistentKeepalive { out.append("PersistentKeepalive = \(k)") }
            out.append(contentsOf: peer.extraLines)
        }
        return out.joined(separator: "\n") + "\n"
    }

    private static func splitKeyValue(_ s: String) -> (String, String)? {
        guard let eq = s.firstIndex(of: "=") else { return nil }
        let key = s[..<eq].trimmingCharacters(in: .whitespaces)
        let value = s[s.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { return nil }
        return (key, value)
    }

    private static func commaList(_ s: String) -> [String] {
        s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}
