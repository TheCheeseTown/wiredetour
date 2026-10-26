import Foundation
import Testing
@testable import WireDetourKit

let privateKey = WireGuardKey.generatePrivateKey()
let peerKey = WireGuardKey.publicKey(forPrivateKey: WireGuardKey.generatePrivateKey())!

let sample = """
# Provider: Example VPN
[Interface]
PrivateKey = \(privateKey)
Address = 10.8.0.2/32, fd00:8::2/128
DNS = 10.8.0.1, corp.example
PostUp = echo hi

#! SplitDNS.Domain = *.Example.com.
#! SplitDNS.Domain = home.lan
#! SplitDNS.Route = 10.0.0.7/24
#!SplitDNS.Future = something

[Peer]
PublicKey = \(peerKey)
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.net:51820 # inline comment
PersistentKeepalive = 25
"""

@Suite struct ParserTests {
    @Test func parsesDirectivesAndKeys() throws {
        let c = try WgQuickFormat.parse(sample, name: "test")
        #expect(c.domains == ["example.com", "home.lan"])
        #expect(c.networks.map(\.description) == ["10.0.0.7/24"])
        #expect(c.interface.dnsServers == ["10.8.0.1"])
        #expect(c.interface.dnsSearch == ["corp.example"])
        #expect(c.interface.addresses.count == 2)
        #expect(c.peers.count == 1)
        #expect(c.peers[0].endpoint == Endpoint(host: "vpn.example.net", port: 51820))
        #expect(c.peers[0].persistentKeepalive == 25)
        #expect(c.unknownDirectives == ["#!SplitDNS.Future = something"])
        #expect(c.interface.extraLines == ["PostUp = echo hi"])
        #expect(c.headerLines == ["# Provider: Example VPN"])
        #expect(c.validationIssues.isEmpty)
    }

    @Test func roundTripIsStable() throws {
        let c = try WgQuickFormat.parse(sample, name: "test")
        let text = WgQuickFormat.serialize(c)
        let again = try WgQuickFormat.parse(text, name: "test")
        #expect(again == c)
        #expect(WgQuickFormat.serialize(again) == text)
        // Directives are plain comments to every other WireGuard tool.
        for line in text.split(separator: "\n") where line.contains("SplitDNS") {
            #expect(line.hasPrefix("#"))
        }
    }

    @Test func rejectsUnknownSectionsAndKeys() {
        #expect(throws: WgQuickFormat.ParseError.self) {
            try WgQuickFormat.parse("[Interface]\nPrivateKey = x\n[SplitDNS]\n", name: "t")
        }
        #expect(throws: WgQuickFormat.ParseError.self) {
            try WgQuickFormat.parse("[Interface]\nBogus = 1\n", name: "t")
        }
        #expect(throws: WgQuickFormat.ParseError.self) {
            try WgQuickFormat.parse("[Interface]\n#! SplitDNS.Domain = not a domain\n", name: "t")
        }
    }

    @Test func missingDNSIsAValidationIssue() throws {
        var c = try WgQuickFormat.parse(sample, name: "test")
        c.interface.dnsServers = []
        #expect(c.validationIssues.contains { $0.message.contains("DNS") })
    }

    @Test func endpointForms() {
        #expect(Endpoint("[2001:db8::1]:51820") == Endpoint(host: "2001:db8::1", port: 51820))
        #expect(Endpoint("1.2.3.4:1") == Endpoint(host: "1.2.3.4", port: 1))
        #expect(Endpoint("2001:db8::1:51820") == nil)
        #expect(Endpoint("host:0") == nil)
        #expect(Endpoint(host: "2001:db8::1", port: 5).description == "[2001:db8::1]:5")
    }
}

@Suite struct DomainTests {
    @Test(arguments: [
        ("Example.COM", "example.com"), ("*.example.com", "example.com"),
        (".example.com.", "example.com"), ("lan", "lan"), ("my_host.lan", "my_host.lan"),
    ])
    func normalizes(input: String, expected: String) {
        #expect(DomainRule.normalize(input) == expected)
    }

    @Test(arguments: ["", "exa mple.com", "-bad.com", "a..b", "10.0.0.1", "*.", "http://x.com"])
    func rejects(input: String) {
        #expect(DomainRule.normalize(input) == nil)
    }
}

@Suite struct AddressTests {
    @Test func parsesAndMasks() throws {
        let r = try #require(IPAddressRange("10.0.0.7/24"))
        #expect(r.masked.description == "10.0.0.0/24")
        #expect(r.subnetMask == "255.255.255.0")
        #expect(IPAddressRange("10.0.0.1")?.prefixLength == 32)
        #expect(IPAddressRange("fd00::1/64")?.masked.description == "fd00::/64")
        #expect(IPAddressRange("10.0.0.0/33") == nil)
        #expect(IPAddressRange("nope") == nil)
    }

    @Test func contains() throws {
        let net = try #require(IPAddressRange("10.0.0.0/8"))
        #expect(net.contains(IPAddressRange("10.1.2.3")!))
        #expect(!net.contains(IPAddressRange("11.0.0.1")!))
        #expect(!net.contains(IPAddressRange("fd00::1")!))
        #expect(IPAddressRange("0.0.0.0/0")!.contains(net))
    }
}

@Suite struct KeyTests {
    @Test func publicKeyDerivation() {
        // RFC 7748 test vector (Alice).
        let priv = Data([0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                         0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a]).base64EncodedString()
        let pub = Data([0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
                        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a]).base64EncodedString()
        #expect(WireGuardKey.publicKey(forPrivateKey: priv) == pub)
        #expect(WireGuardKey.hex(priv)?.hasPrefix("77076d0a") == true)
        #expect(!WireGuardKey.isValid("short"))
    }
}

@Suite struct PlanTests {
    @Test func staticPlan() throws {
        let c = try WgQuickFormat.parse(sample, name: "test")
        let plan = TunnelPlan(c)
        #expect(plan.matchDomains == ["example.com", "home.lan", canaryDomain])
        #expect(plan.staticRoutes.map(\.description) == ["10.0.0.0/24", "10.8.0.1/32"])
        #expect(plan.ipv6Addresses.count == 1)
        let routes = plan.routes(adding: [IPAddressRange("93.184.216.0/24")!, IPAddressRange("2606::/64")!])
        #expect(routes.v4.count == 3)
        #expect(routes.v6.count == 1)
    }

    @Test func engineConfigJSON() throws {
        let c = try WgQuickFormat.parse(sample, name: "test")
        let ec = EngineConfig(c, plan: TunnelPlan(c))
        let json = try #require(String(data: JSONEncoder().encode(ec), encoding: .utf8))
        #expect(json.contains("\"interfaceAddrs\":[\"10.8.0.2\",\"fd00:8::2\"]"))
        #expect(ec.allowedIPs == ["0.0.0.0/0", "::/0"])
    }

    @Test func uapi() throws {
        let c = try WgQuickFormat.parse(sample, name: "test")
        let uapi = c.uapiConfiguration(resolvedEndpoints: [Endpoint(host: "203.0.113.5", port: 51820)])
        #expect(uapi.contains("endpoint=203.0.113.5:51820\n"))
        #expect(uapi.contains("allowed_ip=0.0.0.0/0\n"))
        #expect(uapi.contains("persistent_keepalive_interval=25\n"))
        #expect(uapi.hasPrefix("private_key="))
    }

    @Test func deviceSettingsRoundTrip() {
        var s = DeviceSettings()
        s.connectAutomatically = true
        s.trustedSSIDs = ["Home"]
        var dict: [String: Any] = [:]
        s.write(into: &dict)
        #expect(DeviceSettings(providerConfiguration: dict) == s)
    }
}
