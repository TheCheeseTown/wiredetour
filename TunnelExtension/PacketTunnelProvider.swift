import Foundation
import Network
import NetworkExtension
import WireDetourCore
import WireDetourKit
import os

private let log = Logger(subsystem: "wireDetour", category: "tunnel")

enum TunnelError: LocalizedError {
    case noConfiguration
    case invalid(String)
    case noTunnelDescriptor
    case coreFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .noConfiguration: "The tunnel configuration is missing."
        case .invalid(let m): m
        case .noTunnelDescriptor: "Could not find the tunnel interface."
        case .coreFailed(let c): "The WireGuard engine failed to start (\(c))."
        }
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    // All mutable state is confined to `queue`, except `handle` which is
    // written once on start and read afterwards.
    private let queue = DispatchQueue(label: "wireDetour.tunnel")
    private let pathQueue = DispatchQueue(label: "wireDetour.path")
    private var handle: Int32 = 0
    private var plan: TunnelPlan?
    private var remoteAddress = "127.0.0.1"
    private var pathMonitor: NWPathMonitor?
    private var lastPath: NWPath?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        let config: TunnelConfiguration
        do {
            guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
                  let ref = proto.passwordReference else { throw TunnelError.noConfiguration }
            let text = try Keychain.load(reference: ref)
            config = try WgQuickFormat.parse(text, name: proto.providerConfiguration?["name"] as? String ?? "tunnel")
            if let issue = config.validationIssues.first { throw TunnelError.invalid(issue.message) }
        } catch {
            log.error("Start failed: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
            return
        }

        let plan = TunnelPlan(config)
        let endpoints = config.peers.map { $0.endpoint.flatMap(EndpointResolver.resolve) }
        queue.sync {
            self.plan = plan
            self.remoteAddress = endpoints.compactMap { $0?.host }.first ?? "127.0.0.1"
        }

        setTunnelNetworkSettings(makeSettings(dynamic: [])) { [self] error in
            if let error {
                log.error("Applying network settings failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }
            guard let fd = TunnelDescriptor.find() else {
                completionHandler(TunnelError.noTunnelDescriptor)
                return
            }
            wdSetLogger(nil, coreLogCallback)
            let engineJSON = String(data: (try? JSONEncoder().encode(EngineConfig(config, plan: plan))) ?? Data(), encoding: .utf8) ?? "{}"
            let uapi = config.uapiConfiguration(resolvedEndpoints: endpoints)
            let ctx = Unmanaged.passUnretained(self).toOpaque()
            let h = wdTurnOn(uapi, engineJSON, fd, ctx, routeCallback)
            guard h > 0 else {
                completionHandler(TunnelError.coreFailed(h))
                return
            }
            queue.sync { self.handle = h }
            startPathMonitor()
            log.info("Tunnel started")
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        let h: Int32 = queue.sync {
            pathMonitor?.cancel()
            pathMonitor = nil
            defer { handle = 0 }
            return handle
        }
        if h > 0 { wdTurnOff(h) }
        log.info("Tunnel stopped (reason \(reason.rawValue, privacy: .public))")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: (@Sendable (Data?) -> Void)?) {
        guard let message = AppMessage.decode(messageData) else {
            completionHandler?(nil)
            return
        }
        let h = queue.sync { handle }
        guard h > 0 else {
            completionHandler?(nil)
            return
        }
        // TestDomain can block for a few seconds; never on the provider's queue.
        DispatchQueue.global(qos: .userInitiated).async {
            let cString: UnsafeMutablePointer<CChar>?
            switch message {
            case .status: cString = wdGetStatus(h)
            case .testDomain(let name): cString = wdTestDomain(h, name)
            }
            guard let cString else {
                completionHandler?(nil)
                return
            }
            let data = Data(String(cString: cString).utf8)
            free(cString)
            completionHandler?(data)
        }
    }

    // MARK: - Network settings

    private func makeSettings(dynamic: [IPAddressRange]) -> NEPacketTunnelNetworkSettings {
        let (plan, remote) = queue.sync { (self.plan!, remoteAddress) }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)
        let routes = plan.routes(adding: dynamic)

        if !plan.ipv4Addresses.isEmpty {
            let v4 = NEIPv4Settings(addresses: plan.ipv4Addresses.map(\.address),
                                    subnetMasks: plan.ipv4Addresses.map(\.subnetMask))
            v4.includedRoutes = routes.v4.map {
                NEIPv4Route(destinationAddress: $0.masked.address, subnetMask: $0.subnetMask)
            }
            settings.ipv4Settings = v4
        }
        if !plan.ipv6Addresses.isEmpty {
            let v6 = NEIPv6Settings(addresses: plan.ipv6Addresses.map(\.address),
                                    networkPrefixLengths: plan.ipv6Addresses.map { NSNumber(value: $0.prefixLength) })
            v6.includedRoutes = routes.v6.map {
                NEIPv6Route(destinationAddress: $0.masked.address, networkPrefixLength: NSNumber(value: $0.prefixLength))
            }
            settings.ipv6Settings = v6
        }

        // Only matched domains' queries reach the tunnel (D5).
        let dns = NEDNSSettings(servers: plan.dnsServers)
        dns.matchDomains = plan.matchDomains
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: plan.mtu)
        return settings
    }

    /// Called by the Go engine on its own thread. Blocks until the OS has
    /// applied the routes so the DNS answer can be released (D4).
    fileprivate func applyDynamicRoutes(json: String) -> Bool {
        guard let strings = try? JSONDecoder().decode([String].self, from: Data(json.utf8)) else { return false }
        let ranges = strings.compactMap(IPAddressRange.init)
        let semaphore = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: false)
        setTunnelNetworkSettings(makeSettings(dynamic: ranges)) { error in
            if let error {
                log.error("Route update failed: \(error.localizedDescription, privacy: .public)")
            }
            result.withLock { $0 = error == nil }
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 4) == .success else { return false }
        return result.withLock { $0 }
    }

    // MARK: - Network changes

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let changed: Bool = self.queue.sync {
                defer { self.lastPath = path }
                guard let last = self.lastPath else { return false }
                return path.status == .satisfied && (last.status != .satisfied || last.availableInterfaces.first != path.availableInterfaces.first)
            }
            let h = self.queue.sync { self.handle }
            if changed && h > 0 {
                log.info("Network changed, rebinding sockets")
                wdBumpSockets(h)
            }
        }
        queue.sync { pathMonitor = monitor }
        monitor.start(queue: pathQueue)
    }
}

private let routeCallback: wd_route_fn = { context, json in
    guard let context, let json else { return 1 }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
    return provider.applyDynamicRoutes(json: String(cString: json)) ? 0 : 1
}

private let coreLogCallback: wd_log_fn = { _, level, message in
    guard let message else { return }
    let text = String(cString: message)
    if level > 0 {
        log.error("core: \(text, privacy: .public)")
    } else {
        log.debug("core: \(text, privacy: .public)")
    }
}
