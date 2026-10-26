import SwiftUI

/// In-app help (D7, D20, F4.4).
struct HelpView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("How wireDetour works") {
                    Text("Only the domains and networks you list take the detour through WireGuard. Everything else on this device uses your normal connection, exactly as if wireDetour weren't installed.")
                    Text("**Domains** include all subdomains: adding example.com also covers www.example.com. Their DNS lookups go to the DNS server in your configuration, through the tunnel, and the addresses they return are routed into the tunnel automatically.")
                    Text("**Networks** are fixed address ranges, such as a home or office LAN, that always use the tunnel.")
                }
                Section("When a domain doesn't work") {
                    Text("If the tunnel can't reach its DNS server or the peer is down, listed domains stop loading instead of silently using your normal connection. The Live section of the tunnel shows why.")
                    Text("Use **Test This Rule** on a connected tunnel to check where a domain's traffic goes.")
                }
                Section("Browsers with their own DNS") {
                    Text("Some browsers can bypass the system's DNS with “secure DNS” (DNS over HTTPS). Then wireDetour never sees the lookup and the site uses your normal connection.")
                    Text("**Firefox** turns its automatic secure DNS off by itself when wireDetour is connected.")
                    Text("**Chrome**: open Settings → Privacy and security → Security, and turn off “Use secure DNS”, or choose “With your current service provider”.")
                }
                Section("Your configuration file") {
                    Text("Rules are stored in your .conf file as comment lines starting with “#! SplitDNS.”. Other WireGuard apps ignore them, so the same file still works everywhere.")
                }
                Section("Privacy") {
                    Text("wireDetour has no servers and collects nothing. The list of matched domains in the Live section exists only in memory while the tunnel is connected.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Help")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .frame(minWidth: 420, minHeight: 520)
    }
}
