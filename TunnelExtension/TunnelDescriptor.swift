import Darwin

/// Finds the utun file descriptor NetworkExtension created for this provider,
/// so wireguard-go can read and write packets on it directly (R12).
enum TunnelDescriptor {
    private static let sysprotoControl: Int32 = 2 // SYSPROTO_CONTROL
    private static let utunOptIfname: Int32 = 2   // UTUN_OPT_IFNAME

    static func find() -> Int32? {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var length = socklen_t(name.count)
            guard getsockopt(fd, sysprotoControl, utunOptIfname, &name, &length) == 0 else { continue }
            let ifname = name.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
            if ifname.hasPrefix("utun") { return fd }
        }
        return nil
    }
}
