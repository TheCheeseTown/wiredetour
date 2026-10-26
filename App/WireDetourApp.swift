import SwiftUI
import WireDetourKit

@main
struct WireDetourApp: App {
    @State private var tunnels = TunnelsManager()

    var body: some Scene {
        mainWindow
        #if os(macOS)
        // D22: status and toggles live in the menu bar; editing in the window.
        MenuBarExtra {
            MenuBarContent()
                .environment(tunnels)
                .task { await tunnels.load() }
        } label: {
            Image(systemName: tunnels.activeTunnel?.status == .connected ? "arrow.triangle.branch" : "arrow.triangle.pull")
        }
        #endif
    }

    #if os(macOS)
    /// D28: menu-bar-only on macOS (LSUIElement), so the single window opens
    /// from the menu bar instead of at launch.
    private var mainWindow: some Scene {
        Window("wireDetour", id: "main") {
            ContentView()
                .environment(tunnels)
                .frame(minWidth: 640, minHeight: 420)
                .task { await tunnels.load() }
        }
        .defaultSize(width: 900, height: 620)
        .defaultLaunchBehavior(.suppressed)
    }
    #else
    private var mainWindow: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environment(tunnels)
                .task { await tunnels.load() }
        }
    }
    #endif
}

/// Turns imported files and scanned text into configurations (D14).
enum TunnelImporter {
    static func config(from url: URL) throws -> TunnelConfiguration {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let text = try String(contentsOf: url, encoding: .utf8)
        return try config(fromText: text, suggestedName: url.deletingPathExtension().lastPathComponent)
    }

    static func config(fromText text: String, suggestedName: String) throws -> TunnelConfiguration {
        try WgQuickFormat.parse(text, name: sanitize(suggestedName))
    }

    static func sanitize(_ name: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Tunnel" : String(trimmed.prefix(40))
    }

    /// A name not yet used by another tunnel: "Home", "Home 2", …
    static func uniqueName(_ base: String, existing: [String]) -> String {
        guard existing.contains(base) else { return base }
        var n = 2
        while existing.contains("\(base) \(n)") { n += 1 }
        return "\(base) \(n)"
    }
}
