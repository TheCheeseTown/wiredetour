import Darwin
import WireDetourKit

/// Resolves peer endpoint hostnames to numeric addresses for wireguard-go.
enum EndpointResolver {
    static func resolve(_ endpoint: Endpoint) -> Endpoint? {
        if isIPAddress(endpoint.host) { return endpoint }
        var hints = addrinfo()
        hints.ai_flags = AI_ADDRCONFIG
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(endpoint.host, String(endpoint.port), &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(first) }

        // Prefer IPv4: it works on more networks than IPv6.
        var candidates: [String] = []
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let ai = node {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                if ai.pointee.ai_family == AF_INET { candidates.insert(s, at: 0) } else { candidates.append(s) }
            }
            node = ai.pointee.ai_next
        }
        return candidates.first.map { Endpoint(host: $0, port: endpoint.port) }
    }
}
