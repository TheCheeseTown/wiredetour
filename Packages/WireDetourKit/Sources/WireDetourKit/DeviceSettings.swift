import Foundation

/// Per-device tunnel settings. Stored in the VPN profile's
/// `providerConfiguration`, never in the `.conf` (§3.2).
public struct DeviceSettings: Codable, Equatable, Sendable {
    /// Keep the tunnel up via an on-demand connect rule (D12).
    public var connectAutomatically = false
    /// Wi-Fi networks where the tunnel should stay off (D24).
    public var trustedSSIDs: [String] = []

    public init() {}

    static let key = "deviceSettings"

    public init(providerConfiguration: [String: Any]?) {
        guard let data = providerConfiguration?[Self.key] as? Data,
              let s = try? JSONDecoder().decode(DeviceSettings.self, from: data) else { return }
        self = s
    }

    public func write(into providerConfiguration: inout [String: Any]) {
        providerConfiguration[Self.key] = try? JSONEncoder().encode(self)
    }
}
