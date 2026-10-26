import SwiftUI
import WireDetourKit

struct TunnelDetailView: View {
    @Environment(TunnelsManager.self) private var tunnels
    let item: TunnelItem

    @State private var showingEditor = false
    @State private var showingQR = false
    @State private var confirmingDelete = false

    var body: some View {
        Form {
            if let error = item.loadError {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            Section {
                TunnelToggle(item: item)
                LabeledContent("Status", value: item.status.label)
            }

            if item.status == .connected {
                LiveStatusSection(item: item)
            }

            Section {
                RuleListEditor(
                    title: "Domains",
                    placeholder: "example.com",
                    items: item.config.domains,
                    normalize: DomainRule.normalize,
                    invalidMessage: "Enter a domain like example.com. Subdomains are included automatically."
                ) { domains in
                    save { $0.domains = domains }
                }
            } header: {
                Text("Domains")
            } footer: {
                Text("These domains and all their subdomains are resolved and routed through the tunnel. Everything else uses your normal connection.")
            }

            Section {
                RuleListEditor(
                    title: "Networks",
                    placeholder: "10.0.0.0/24",
                    items: item.config.networks.map(\.description),
                    normalize: { IPAddressRange($0)?.masked.description },
                    invalidMessage: "Enter a network like 10.0.0.0/24 or a single address."
                ) { networks in
                    save { $0.networks = networks.compactMap(IPAddressRange.init) }
                }
            } header: {
                Text("Networks")
            } footer: {
                Text("Optional. Addresses in these networks always use the tunnel, even when reached by IP.")
            }

            let issues = item.config.validationIssues + item.config.warnings
            if !issues.isEmpty && item.loadError == nil {
                Section("Check") {
                    ForEach(issues) { issue in
                        Label(issue.message, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
            }

            TestRuleSection(item: item)

            AutomationSection(item: item)

            Section("Configuration") {
                Button("Edit Configuration…", systemImage: "square.and.pencil") { showingEditor = true }
                ShareLink(item: ExportedConfig(config: item.config),
                          preview: SharePreview("\(item.name).conf")) {
                    Label("Export .conf…", systemImage: "square.and.arrow.up")
                }
                Button("Show QR Code", systemImage: "qrcode") { showingQR = true }
                Button("Delete Tunnel", systemImage: "trash", role: .destructive) { confirmingDelete = true }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(item.name)
        .sheet(isPresented: $showingEditor) {
            TunnelEditorView(mode: .edit(item))
        }
        .sheet(isPresented: $showingQR) {
            QRCodeSheet(title: item.name, text: WgQuickFormat.serialize(item.config))
        }
        .confirmationDialog("Delete “\(item.name)”?", isPresented: $confirmingDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                Task {
                    do { try await tunnels.remove(item) } catch { tunnels.lastError = error.localizedDescription }
                }
            }
        } message: {
            Text("The configuration and its private key are removed from this device.")
        }
    }

    private func save(_ change: (inout TunnelConfiguration) -> Void) {
        var config = item.config
        change(&config)
        Task {
            do { try await tunnels.update(item, config: config) } catch { tunnels.lastError = error.localizedDescription }
        }
    }
}

/// An editable list of strings with an add field (D15).
struct RuleListEditor: View {
    let title: String
    let placeholder: String
    let items: [String]
    let normalize: (String) -> String?
    let invalidMessage: String
    /// Characters that split a paste into several entries.
    var separators = ", \n\t"
    let onChange: ([String]) -> Void

    @State private var draft = ""
    @State private var invalid = false

    var body: some View {
        ForEach(items, id: \.self) { value in
            HStack {
                Text(value).textSelection(.enabled)
                Spacer()
                Button("Remove \(value)", systemImage: "minus.circle.fill") {
                    onChange(items.filter { $0 != value })
                }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .foregroundStyle(.red)
            }
        }
        .onDelete { offsets in
            var copy = items
            copy.remove(atOffsets: offsets)
            onChange(copy)
        }
        HStack {
            TextField("Add \(title.lowercased().dropLast())", text: $draft, prompt: Text(placeholder))
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                #endif
                .onSubmit(add)
            Button("Add", systemImage: "plus.circle.fill", action: add)
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .disabled(draft.isEmpty)
        }
        if invalid {
            Text(invalidMessage)
                .font(.caption)
                .foregroundStyle(.red)
        }
    }

    private func add() {
        // Allow pasting several entries separated by commas, spaces or newlines.
        let parts = draft.split(whereSeparator: { separators.contains($0) }).map(String.init)
        let normalized = parts.map(normalize)
        guard !parts.isEmpty, normalized.allSatisfy({ $0 != nil }) else {
            invalid = true
            return
        }
        invalid = false
        var copy = items
        for value in normalized.compactMap({ $0 }) where !copy.contains(value) {
            copy.append(value)
        }
        draft = ""
        onChange(copy)
    }
}

/// D12 + D24: connect automatically, except on trusted Wi-Fi.
struct AutomationSection: View {
    @Environment(TunnelsManager.self) private var tunnels
    let item: TunnelItem

    var body: some View {
        Section {
            Toggle("Connect Automatically", isOn: Binding(
                get: { item.deviceSettings.connectAutomatically },
                set: { on in update { $0.connectAutomatically = on } }
            ))
            if item.deviceSettings.connectAutomatically {
                RuleListEditor(
                    title: "Trusted Wi-Fi",
                    placeholder: "Wi-Fi name (SSID)",
                    items: item.deviceSettings.trustedSSIDs,
                    normalize: { s in
                        let t = s.trimmingCharacters(in: .whitespaces)
                        return t.isEmpty || t.utf8.count > 32 ? nil : t
                    },
                    invalidMessage: "Wi-Fi names are 1–32 bytes.",
                    separators: "\n"
                ) { ssids in
                    update { $0.trustedSSIDs = ssids }
                }
            }
        } header: {
            Text("Automation")
        } footer: {
            Text(item.deviceSettings.connectAutomatically
                 ? "The tunnel stays on and reconnects after network changes, except on the trusted Wi-Fi networks listed above."
                 : "Keep the tunnel on and reconnect it after network changes and restarts.")
        }
    }

    private func update(_ change: (inout DeviceSettings) -> Void) {
        var s = item.deviceSettings
        change(&s)
        Task {
            do { try await tunnels.updateDeviceSettings(item, s) } catch { tunnels.lastError = error.localizedDescription }
        }
    }
}

/// D24: does a domain actually go through the tunnel?
struct TestRuleSection: View {
    @Environment(TunnelsManager.self) private var tunnels
    let item: TunnelItem

    @State private var domain = ""
    @State private var running = false
    @State private var result: DomainTestResult?
    @State private var error: String?

    var body: some View {
        Section {
            HStack {
                TextField("Domain to test", text: $domain, prompt: Text(item.config.domains.first ?? "example.com"))
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    #endif
                    .onSubmit(run)
                if running {
                    ProgressView().controlSize(.small)
                } else {
                    Button("Test", action: run)
                        .disabled(item.status != .connected)
                }
            }
            if let error {
                Label(error, systemImage: "xmark.octagon").foregroundStyle(.red)
            }
            if let result {
                TestResultView(result: result)
            }
        } header: {
            Text("Test This Rule")
        } footer: {
            Text(item.status == .connected
                 ? "Resolves the domain through the tunnel and shows whether its addresses are routed into it."
                 : "Connect the tunnel to test a domain.")
        }
    }

    private func run() {
        let name = domain.isEmpty ? (item.config.domains.first ?? "") : domain
        guard let normalized = DomainRule.normalize(name) else {
            error = "Enter a domain like example.com."
            return
        }
        running = true
        error = nil
        result = nil
        Task {
            defer { running = false }
            do { result = try await tunnels.test(domain: normalized, in: item) } catch { self.error = error.localizedDescription }
        }
    }
}

struct TestResultView: View {
    let result: DomainTestResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let error = result.error {
                Label(error, systemImage: result.matched ? "xmark.octagon" : "info.circle")
                    .foregroundStyle(result.matched ? .red : .secondary)
            }
            let ips = result.ips ?? []
            if ips.isEmpty && result.error == nil {
                Text("No addresses returned (\(result.rcode ?? "no answer")).").foregroundStyle(.secondary)
            }
            ForEach(ips) { addr in
                HStack(alignment: .firstTextBaseline) {
                    Image(systemName: addr.viaTunnel && addr.inAllowedIPs ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(addr.viaTunnel && addr.inAllowedIPs ? .green : .orange)
                    VStack(alignment: .leading) {
                        Text(addr.ip).monospaced()
                        Text(describe(addr)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func describe(_ a: DomainTestResult.Address) -> String {
        if !a.viaTunnel { return "Not routed into the tunnel — uses your normal connection." }
        if !a.inAllowedIPs { return "Routed into the tunnel but outside the peer's AllowedIPs, so it's dropped." }
        if a.lastUsedSecAgo >= 0 { return "Through the tunnel · traffic seen \(a.lastUsedSecAgo)s ago" }
        return "Through the tunnel · no traffic seen yet"
    }
}
