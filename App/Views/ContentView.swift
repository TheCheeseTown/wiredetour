import SwiftUI
import UniformTypeIdentifiers
import WireDetourKit

extension UTType {
    nonisolated static let wireGuardConfig = UTType(importedAs: "com.wireguard.config", conformingTo: .text)
}

struct ContentView: View {
    @Environment(TunnelsManager.self) private var tunnels
    @State private var selection: TunnelItem.ID?
    @State private var showingImporter = false
    @State private var showingScanner = false
    @State private var showingCreate = false
    @State private var showingHelp = false
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

    private var isEmpty: Bool { tunnels.isLoaded && tunnels.tunnels.isEmpty }

    var body: some View {
        NavigationSplitView {
            TunnelListView(selection: $selection)
                .navigationTitle("wireDetour")
                .toolbar {
                    ToolbarItem(placement: .primaryAction) { addMenu }
                    ToolbarItem(placement: .automatic) {
                        Button("Help", systemImage: "questionmark.circle") { showingHelp = true }
                    }
                }
                .navigationSplitViewColumnWidth(min: 220, ideal: 260)
                #if os(iOS)
                .overlay {
                    // A compact width shows only the sidebar, so the empty state goes there.
                    if isEmpty && sizeClass == .compact { emptyState }
                }
                #endif
        } detail: {
            if let item = tunnels.tunnels.first(where: { $0.id == selection }) {
                TunnelDetailView(item: item)
            } else if isEmpty {
                emptyState
            } else {
                Text("Select a tunnel")
                    .foregroundStyle(.secondary)
            }
        }
        .fileImporter(isPresented: $showingImporter, allowedContentTypes: [.wireGuardConfig, .plainText, .text], allowsMultipleSelection: true) { result in
            if case .success(let urls) = result { importFiles(urls) }
        }
        .onOpenURL { url in importFiles([url]) }
        .dropDestination(for: URL.self) { urls, _ in
            importFiles(urls)
            return true
        }
        .sheet(isPresented: $showingCreate) {
            TunnelEditorView(mode: .create)
        }
        .sheet(isPresented: $showingHelp) {
            HelpView()
        }
        #if os(iOS)
        .fullScreenCover(isPresented: $showingScanner) {
            QRScannerSheet { text in
                importText(text, suggestedName: "Scanned")
            }
        }
        #endif
        .alert("Something went wrong", isPresented: Binding(get: { tunnels.lastError != nil }, set: { if !$0 { tunnels.lastError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(tunnels.lastError ?? "")
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Tunnels", systemImage: "arrow.triangle.branch")
        } description: {
            Text("Import a WireGuard configuration, then choose which domains take the detour through it.")
        } actions: {
            Button("Import from File") { showingImporter = true }
                .buttonStyle(.borderedProminent)
            Button("Create from Scratch") { showingCreate = true }
        }
    }

    private var addMenu: some View {
        Menu {
            Button("Import from File…", systemImage: "doc") { showingImporter = true }
            #if os(iOS)
            if QRScannerSheet.isSupported {
                Button("Scan QR Code", systemImage: "qrcode.viewfinder") { showingScanner = true }
            }
            #endif
            Button("Create from Scratch", systemImage: "square.and.pencil") { showingCreate = true }
        } label: {
            Label("Add Tunnel", systemImage: "plus")
        }
    }

    private func importFiles(_ urls: [URL]) {
        Task {
            for url in urls {
                do {
                    var config = try TunnelImporter.config(from: url)
                    config.name = TunnelImporter.uniqueName(config.name, existing: tunnels.tunnels.map(\.name))
                    try await tunnels.add(config)
                    selection = tunnels.tunnels.first { $0.name == config.name }?.id
                } catch {
                    tunnels.lastError = "\(url.lastPathComponent): \(error.localizedDescription)"
                }
            }
        }
    }

    private func importText(_ text: String, suggestedName: String) {
        Task {
            do {
                var config = try TunnelImporter.config(fromText: text, suggestedName: suggestedName)
                config.name = TunnelImporter.uniqueName(config.name, existing: tunnels.tunnels.map(\.name))
                try await tunnels.add(config)
                selection = tunnels.tunnels.first { $0.name == config.name }?.id
            } catch {
                tunnels.lastError = error.localizedDescription
            }
        }
    }
}

struct TunnelListView: View {
    @Environment(TunnelsManager.self) private var tunnels
    @Binding var selection: TunnelItem.ID?

    var body: some View {
        List(selection: $selection) {
            ForEach(tunnels.tunnels) { item in
                NavigationLink(value: item.id) {
                    TunnelRow(item: item)
                }
            }
        }
    }
}

struct TunnelRow: View {
    @Environment(TunnelsManager.self) private var tunnels
    let item: TunnelItem

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).font(.headline)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            TunnelToggle(item: item)
                .labelsHidden()
        }
    }

    private var subtitle: String {
        if item.loadError != nil { return "Can't read configuration" }
        let n = item.config.domains.count
        let rules = n == 1 ? "1 domain" : "\(n) domains"
        return "\(item.status.label) · \(rules)"
    }
}

/// The one switch per tunnel (D12, D13).
struct TunnelToggle: View {
    @Environment(TunnelsManager.self) private var tunnels
    let item: TunnelItem

    var body: some View {
        Toggle(item.name, isOn: Binding(
            get: { item.isActive },
            set: { on in Task { await tunnels.setActive(item, on) } }
        ))
        .toggleStyle(.switch)
        .disabled(item.loadError != nil || item.status == .connecting || item.status == .disconnecting)
    }
}
