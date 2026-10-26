import SwiftUI
import WireDetourKit

/// D19: live status polled from the extension while visible. Nothing is stored.
struct LiveStatusSection: View {
    @Environment(TunnelsManager.self) private var tunnels
    let item: TunnelItem

    @State private var status: LiveStatus?

    var body: some View {
        Section("Live") {
            if let status {
                LabeledContent("Last handshake", value: handshake(status.wireguard.lastHandshakeSecAgo))
                LabeledContent("Received", value: status.wireguard.rxBytes.formatted(.byteCount(style: .file)))
                LabeledContent("Sent", value: status.wireguard.txBytes.formatted(.byteCount(style: .file)))

                ForEach(status.engine.failures?.prefix(3) ?? [], id: \.atUnix) { f in
                    Label("\(f.domain): \(f.reason)", systemImage: "xmark.octagon")
                        .foregroundStyle(.red)
                        .font(.callout)
                }

                DisclosureGroup("Matched domains (\(status.engine.domains?.count ?? 0))") {
                    ForEach(status.engine.domains ?? []) { d in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(d.domain).font(.callout.bold())
                            if let ips = d.ips, !ips.isEmpty {
                                Text(ips.joined(separator: ", ")).font(.caption.monospaced())
                            }
                            if let e = d.error {
                                Text(e).font(.caption).foregroundStyle(.red)
                            }
                            ForEach(d.warnings ?? [], id: \.self) { w in
                                Text(w).font(.caption).foregroundStyle(.orange)
                            }
                        }
                    }
                }

                if status.engine.dynamicMode {
                    DisclosureGroup("Routes added (\(status.engine.routes?.count ?? 0))") {
                        ForEach(status.engine.routes ?? []) { r in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(r.prefix).font(.callout.monospaced())
                                Text(routeDetail(r)).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } else {
                ProgressView()
            }
        }
        .task(id: item.id) {
            while !Task.isCancelled {
                status = await tunnels.liveStatus(item)
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func handshake(_ ago: Int?) -> String {
        guard let ago else { return "Not yet" }
        if ago < 2 { return "Just now" }
        return Duration.seconds(ago).formatted(.units(allowed: [.hours, .minutes, .seconds], width: .abbreviated)) + " ago"
    }

    private func routeDetail(_ r: LiveStatus.Route) -> String {
        let who = (r.domains ?? []).joined(separator: ", ")
        let used = r.lastUsedSecAgo < 0 ? "unused" : "used \(r.lastUsedSecAgo)s ago"
        return "\(who) · \(used)"
    }
}
