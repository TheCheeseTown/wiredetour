import Foundation
import NetworkExtension
import Observation
import WireDetourKit

/// One tunnel as the UI sees it: its VPN profile plus the parsed configuration.
@Observable
final class TunnelItem: Identifiable {
    let manager: NETunnelProviderManager
    var config: TunnelConfiguration
    var deviceSettings: DeviceSettings
    var status: NEVPNStatus
    /// Set if the stored configuration couldn't be read.
    var loadError: String?

    var id: ObjectIdentifier { ObjectIdentifier(manager) }
    var name: String { config.name }
    var isActive: Bool { status != .disconnected && status != .invalid }

    init(manager: NETunnelProviderManager, config: TunnelConfiguration, deviceSettings: DeviceSettings) {
        self.manager = manager
        self.config = config
        self.deviceSettings = deviceSettings
        self.status = manager.connection.status
    }
}

enum TunnelsError: LocalizedError {
    case duplicateName(String)
    case invalid(String)
    case notConnected

    var errorDescription: String? {
        switch self {
        case .duplicateName(let n): "A tunnel named “\(n)” already exists."
        case .invalid(let m): m
        case .notConnected: "The tunnel isn't connected."
        }
    }
}

@Observable
final class TunnelsManager {
    private(set) var tunnels: [TunnelItem] = []
    private(set) var isLoaded = false
    var lastError: String?

    private var statusObserver: NSObjectProtocol?

    var activeTunnel: TunnelItem? { tunnels.first(where: \.isActive) }

    static var tunnelBundleIdentifier: String {
        Bundle.main.object(forInfoDictionaryKey: "WDTunnelBundleIdentifier") as? String ?? ""
    }

    // MARK: Loading

    func load() async {
        guard !isLoaded else { return }
        isLoaded = true
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.refreshStatuses() }
        }
        await reload()
    }

    func reload() async {
        do {
            // Only our own profiles; other VPN apps' profiles can be visible too.
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.tunnelBundleIdentifier
            }
            tunnels = managers.map(Self.item(for:)).sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private static func item(for manager: NETunnelProviderManager) -> TunnelItem {
        let proto = manager.protocolConfiguration as? NETunnelProviderProtocol
        let name = proto?.providerConfiguration?["name"] as? String ?? manager.localizedDescription ?? "Tunnel"
        let settings = DeviceSettings(providerConfiguration: proto?.providerConfiguration)
        do {
            guard let ref = proto?.passwordReference else { throw TunnelsError.invalid("No stored configuration.") }
            let config = try WgQuickFormat.parse(try Keychain.load(reference: ref), name: name)
            return TunnelItem(manager: manager, config: config, deviceSettings: settings)
        } catch {
            let item = TunnelItem(manager: manager,
                                  config: TunnelConfiguration(name: name, interface: InterfaceConfig(privateKey: ""), peers: []),
                                  deviceSettings: settings)
            item.loadError = error.localizedDescription
            return item
        }
    }

    private func refreshStatuses() {
        for t in tunnels where t.status != t.manager.connection.status {
            t.status = t.manager.connection.status
        }
    }

    // MARK: Editing

    func add(_ config: TunnelConfiguration) async throws {
        try checkName(config.name, excluding: nil)
        let manager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleIdentifier
        proto.passwordReference = try Keychain.add(config: WgQuickFormat.serialize(config), label: config.name)
        manager.protocolConfiguration = proto
        apply(config: config, settings: DeviceSettings(), to: manager)
        do {
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        } catch {
            if let ref = proto.passwordReference { Keychain.delete(reference: ref) }
            throw error
        }
        let item = TunnelItem(manager: manager, config: config, deviceSettings: DeviceSettings())
        tunnels.append(item)
        tunnels.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// Saves a changed configuration. A running tunnel is restarted so the
    /// new rules take effect.
    func update(_ item: TunnelItem, config: TunnelConfiguration) async throws {
        try checkName(config.name, excluding: item)
        guard let proto = item.manager.protocolConfiguration as? NETunnelProviderProtocol,
              let ref = proto.passwordReference else { throw TunnelsError.invalid("No stored configuration.") }
        try Keychain.update(reference: ref, config: WgQuickFormat.serialize(config))
        apply(config: config, settings: item.deviceSettings, to: item.manager)
        try await item.manager.saveToPreferences()
        item.config = config
        item.loadError = nil
        if item.isActive { await restart(item) }
    }

    func updateDeviceSettings(_ item: TunnelItem, _ settings: DeviceSettings) async throws {
        apply(config: item.config, settings: settings, to: item.manager)
        if item.isActive { item.manager.isOnDemandEnabled = settings.connectAutomatically }
        try await item.manager.saveToPreferences()
        item.deviceSettings = settings
    }

    func remove(_ item: TunnelItem) async throws {
        if item.isActive { item.manager.connection.stopVPNTunnel() }
        let ref = (item.manager.protocolConfiguration as? NETunnelProviderProtocol)?.passwordReference
        try await item.manager.removeFromPreferences()
        if let ref { Keychain.delete(reference: ref) }
        tunnels.removeAll { $0 === item }
    }

    private func checkName(_ name: String, excluding: TunnelItem?) throws {
        if tunnels.contains(where: { $0 !== excluding && $0.name == name }) {
            throw TunnelsError.duplicateName(name)
        }
    }

    private func apply(config: TunnelConfiguration, settings: DeviceSettings, to manager: NETunnelProviderManager) {
        manager.localizedDescription = config.name
        manager.isEnabled = true
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            proto.serverAddress = config.peers.compactMap(\.endpoint).first?.description ?? "wireDetour"
            var pc = proto.providerConfiguration ?? [:]
            pc["name"] = config.name
            settings.write(into: &pc)
            proto.providerConfiguration = pc
        }
        manager.onDemandRules = Self.onDemandRules(settings)
    }

    /// D12 + D24: stay off on trusted Wi-Fi, otherwise always connect.
    static func onDemandRules(_ settings: DeviceSettings) -> [NEOnDemandRule] {
        var rules: [NEOnDemandRule] = []
        if !settings.trustedSSIDs.isEmpty {
            let trusted = NEOnDemandRuleDisconnect()
            trusted.interfaceTypeMatch = .wiFi
            trusted.ssidMatch = settings.trustedSSIDs
            rules.append(trusted)
        }
        let connect = NEOnDemandRuleConnect()
        connect.interfaceTypeMatch = .any
        rules.append(connect)
        return rules
    }

    // MARK: Connecting

    func setActive(_ item: TunnelItem, _ on: Bool) async {
        do {
            if on {
                if let issue = item.config.validationIssues.first { throw TunnelsError.invalid(issue.message) }
                // One active tunnel at a time (D13).
                for other in tunnels where other !== item && (other.isActive || other.manager.isOnDemandEnabled) {
                    other.manager.isOnDemandEnabled = false
                    try await other.manager.saveToPreferences()
                    other.manager.connection.stopVPNTunnel()
                }
                item.manager.isEnabled = true
                item.manager.isOnDemandEnabled = item.deviceSettings.connectAutomatically
                try await item.manager.saveToPreferences()
                try await item.manager.loadFromPreferences()
                try item.manager.connection.startVPNTunnel()
            } else {
                // Turning off by hand must also stop on-demand from reconnecting.
                if item.manager.isOnDemandEnabled {
                    item.manager.isOnDemandEnabled = false
                    try await item.manager.saveToPreferences()
                }
                item.manager.connection.stopVPNTunnel()
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func restart(_ item: TunnelItem) async {
        item.manager.connection.stopVPNTunnel()
        for _ in 0..<50 where item.manager.connection.status != .disconnected {
            try? await Task.sleep(for: .milliseconds(100))
        }
        await setActive(item, true)
    }

    // MARK: Talking to the extension

    func liveStatus(_ item: TunnelItem) async -> LiveStatus? {
        guard let data = await send(.status, to: item) else { return nil }
        return try? JSONDecoder().decode(LiveStatus.self, from: data)
    }

    func test(domain: String, in item: TunnelItem) async throws -> DomainTestResult {
        guard item.status == .connected else { throw TunnelsError.notConnected }
        guard let data = await send(.testDomain(domain), to: item),
              let result = try? JSONDecoder().decode(DomainTestResult.self, from: data) else {
            throw TunnelsError.invalid("The tunnel didn't answer.")
        }
        return result
    }

    private func send(_ message: AppMessage, to item: TunnelItem) async -> Data? {
        guard let session = item.manager.connection as? NETunnelProviderSession, item.status == .connected else { return nil }
        let payload = message.encoded()
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(payload) { continuation.resume(returning: $0) }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .connected: "Connected"
        case .connecting: "Connecting…"
        case .disconnecting: "Disconnecting…"
        case .reasserting: "Reconnecting…"
        case .disconnected: "Off"
        case .invalid: "Invalid"
        @unknown default: "Unknown"
        }
    }
}
