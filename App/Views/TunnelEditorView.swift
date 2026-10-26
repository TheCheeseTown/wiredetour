import SwiftUI
import WireDetourKit

/// Create a tunnel from scratch or edit an existing one (D14), as a form or
/// as raw `.conf` text.
struct TunnelEditorView: View {
    enum Mode {
        case create
        case edit(TunnelItem)
    }

    private enum Tab: Hashable { case form, raw }

    @Environment(TunnelsManager.self) private var tunnels
    @Environment(\.dismiss) private var dismiss

    let mode: Mode
    @State private var base: TunnelConfiguration
    @State private var draft: Draft
    @State private var raw: String
    @State private var tab = Tab.form
    @State private var error: String?
    @State private var saving = false

    init(mode: Mode) {
        self.mode = mode
        let config: TunnelConfiguration
        switch mode {
        case .edit(let item):
            config = item.config
        case .create:
            var iface = InterfaceConfig(privateKey: WireGuardKey.generatePrivateKey())
            iface.addresses = []
            var peer = PeerConfig(publicKey: "")
            peer.allowedIPs = [IPAddressRange("0.0.0.0/0")!, IPAddressRange("::/0")!]
            peer.persistentKeepalive = 25
            config = TunnelConfiguration(name: "", interface: iface, peers: [peer])
        }
        _base = State(initialValue: config)
        _draft = State(initialValue: Draft(config))
        _raw = State(initialValue: WgQuickFormat.serialize(config))
    }

    private var isCreate: Bool { if case .create = mode { true } else { false } }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("Editor", selection: $tab) {
                    Text("Form").tag(Tab.form)
                    Text("Text").tag(Tab.raw)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding()
                .onChange(of: tab) { old, new in switchTab(from: old, to: new) }

                if let error {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                        .font(.callout)
                        .padding(.horizontal)
                }

                switch tab {
                case .form: form
                case .raw: rawEditor
                }
            }
            .navigationTitle(isCreate ? "New Tunnel" : "Edit \(base.name)")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save).disabled(saving)
                }
            }
        }
        .frame(minWidth: 480, minHeight: 600)
    }

    // MARK: Form

    private var form: some View {
        Form {
            Section("Name") {
                TextField("Name", text: $draft.name, prompt: Text("Home"))
            }
            Section {
                HStack {
                    SecureField("Private key", text: $draft.privateKey)
                        .monospaced()
                    Button("Generate") { draft.privateKey = WireGuardKey.generatePrivateKey() }
                        .buttonStyle(.borderless)
                }
                LabeledContent("Public key") {
                    let pub = WireGuardKey.publicKey(forPrivateKey: draft.privateKey) ?? "—"
                    Text(pub).monospaced().textSelection(.enabled).font(.caption)
                }
                field("Addresses", $draft.addresses, prompt: "10.8.0.2/32")
                field("DNS servers", $draft.dns, prompt: "10.8.0.1")
                field("Listen port", $draft.listenPort, prompt: "Automatic")
                field("MTU", $draft.mtu, prompt: "Automatic")
            } header: {
                Text("Interface")
            } footer: {
                Text("Add this device's public key to your server's peer list. The DNS server answers your domains through the tunnel.")
            }

            ForEach($draft.peers) { $peer in
                Section {
                    field("Public key", $peer.publicKey, prompt: "Server's public key")
                    HStack {
                        SecureField("Preshared key", text: $peer.presharedKey, prompt: Text("Optional"))
                            .monospaced()
                        Button("Generate") { peer.presharedKey = WireGuardKey.generatePresharedKey() }
                            .buttonStyle(.borderless)
                    }
                    field("Endpoint", $peer.endpoint, prompt: "vpn.example.com:51820")
                    field("Allowed IPs", $peer.allowedIPs, prompt: "0.0.0.0/0, ::/0")
                    field("Keepalive", $peer.keepalive, prompt: "Off")
                    if draft.peers.count > 1 {
                        Button("Remove Peer", role: .destructive) {
                            draft.peers.removeAll { $0.id == peer.id }
                        }
                    }
                } header: {
                    Text("Peer")
                } footer: {
                    Text("Allowed IPs only filter what this peer may carry. wireDetour routes just your listed domains and networks into the tunnel.")
                }
            }
            Section {
                Button("Add Peer", systemImage: "plus") { draft.peers.append(Draft.Peer()) }
            }
        }
        .formStyle(.grouped)
    }

    private func field(_ label: String, _ text: Binding<String>, prompt: String) -> some View {
        TextField(label, text: text, prompt: Text(prompt))
            .autocorrectionDisabled()
            #if os(iOS)
            .textInputAutocapitalization(.never)
            #endif
    }

    private var rawEditor: some View {
        TextEditor(text: $raw)
            .font(.body.monospaced())
            .autocorrectionDisabled()
            #if os(iOS)
            .textInputAutocapitalization(.never)
            #endif
            .padding(.horizontal)
    }

    // MARK: Actions

    private func switchTab(from old: Tab, to new: Tab) {
        do {
            if old == .form {
                raw = WgQuickFormat.serialize(try draft.apply(to: base))
            } else {
                let parsed = try WgQuickFormat.parse(raw, name: draft.name)
                base = parsed
                draft = Draft(parsed)
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
            tab = old
        }
    }

    private func save() {
        let config: TunnelConfiguration
        do {
            if tab == .form {
                config = try draft.apply(to: base)
            } else {
                config = try WgQuickFormat.parse(raw, name: draft.name)
            }
            guard !config.name.trimmingCharacters(in: .whitespaces).isEmpty else {
                throw TunnelsError.invalid("Give the tunnel a name.")
            }
        } catch {
            self.error = error.localizedDescription
            return
        }
        saving = true
        Task {
            defer { saving = false }
            do {
                switch mode {
                case .create: try await tunnels.add(config)
                case .edit(let item): try await tunnels.update(item, config: config)
                }
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

/// String-backed copy of a configuration for the form.
private struct Draft {
    struct Peer: Identifiable {
        let id = UUID()
        var publicKey = ""
        var presharedKey = ""
        var endpoint = ""
        var allowedIPs = "0.0.0.0/0, ::/0"
        var keepalive = "25"
    }

    var name: String
    var privateKey: String
    var addresses: String
    var dns: String
    var listenPort: String
    var mtu: String
    var peers: [Peer]

    init(_ c: TunnelConfiguration) {
        name = c.name
        privateKey = c.interface.privateKey
        addresses = c.interface.addresses.map(\.description).joined(separator: ", ")
        dns = (c.interface.dnsServers + c.interface.dnsSearch).joined(separator: ", ")
        listenPort = c.interface.listenPort.map(String.init) ?? ""
        mtu = c.interface.mtu.map(String.init) ?? ""
        peers = c.peers.map { p in
            Peer(publicKey: p.publicKey,
                 presharedKey: p.presharedKey ?? "",
                 endpoint: p.endpoint?.description ?? "",
                 allowedIPs: p.allowedIPs.map(\.description).joined(separator: ", "),
                 keepalive: p.persistentKeepalive.map(String.init) ?? "")
        }
    }

    /// Applies the form onto `base`, keeping rules, comments and extra keys.
    func apply(to base: TunnelConfiguration) throws -> TunnelConfiguration {
        var c = base
        c.name = name.trimmingCharacters(in: .whitespaces)
        c.interface.privateKey = privateKey.trimmingCharacters(in: .whitespaces)
        c.interface.addresses = try list(addresses).map { s in
            guard let r = IPAddressRange(s) else { throw TunnelsError.invalid("“\(s)” isn't a valid address.") }
            return r
        }
        let dnsItems = list(dns)
        c.interface.dnsServers = dnsItems.filter(isIPAddress)
        c.interface.dnsSearch = dnsItems.filter { !isIPAddress($0) }
        c.interface.listenPort = try optionalNumber(listenPort, "Listen port")
        c.interface.mtu = try optionalNumber(mtu, "MTU")

        let oldPeers = base.peers
        c.peers = try peers.enumerated().map { i, p in
            var peer = i < oldPeers.count ? oldPeers[i] : PeerConfig(publicKey: "")
            peer.publicKey = p.publicKey.trimmingCharacters(in: .whitespaces)
            let psk = p.presharedKey.trimmingCharacters(in: .whitespaces)
            peer.presharedKey = psk.isEmpty ? nil : psk
            let ep = p.endpoint.trimmingCharacters(in: .whitespaces)
            if ep.isEmpty {
                peer.endpoint = nil
            } else {
                guard let e = Endpoint(ep) else { throw TunnelsError.invalid("“\(ep)” isn't a valid endpoint (host:port).") }
                peer.endpoint = e
            }
            peer.allowedIPs = try list(p.allowedIPs).map { s in
                guard let r = IPAddressRange(s) else { throw TunnelsError.invalid("“\(s)” isn't a valid Allowed IPs entry.") }
                return r
            }
            let ka: UInt16? = try optionalNumber(p.keepalive, "Keepalive")
            peer.persistentKeepalive = ka == 0 ? nil : ka
            return peer
        }
        return c
    }

    private func list(_ s: String) -> [String] {
        s.split(whereSeparator: { ", \n".contains($0) }).map(String.init)
    }

    private func optionalNumber(_ s: String, _ label: String) throws -> UInt16? {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return nil }
        guard let v = UInt16(t) else { throw TunnelsError.invalid("\(label) must be a number.") }
        return v
    }
}
