#if os(macOS)
import SwiftUI

/// D22: the menu bar extra — status, one toggle per tunnel, open the window.
struct MenuBarContent: View {
    @Environment(TunnelsManager.self) private var tunnels
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if tunnels.tunnels.isEmpty {
            Text("No tunnels")
        }
        ForEach(tunnels.tunnels) { item in
            Toggle(isOn: Binding(
                get: { item.isActive },
                set: { on in Task { await tunnels.setActive(item, on) } }
            )) {
                Text("\(item.name) — \(item.status.label)")
            }
            .disabled(item.loadError != nil)
        }
        Divider()
        Button("Open wireDetour…") {
            openWindow(id: "main")
            NSApp.activate()
        }
        .keyboardShortcut("o")
        Divider()
        Button("Quit wireDetour") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}
#endif
