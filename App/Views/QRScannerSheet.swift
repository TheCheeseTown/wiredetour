#if os(iOS)
import SwiftUI
import VisionKit

/// Scans a WireGuard configuration QR code (D14).
struct QRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onScan: (String) -> Void

    static var isSupported: Bool { DataScannerViewController.isSupported }

    var body: some View {
        NavigationStack {
            Group {
                if DataScannerViewController.isAvailable {
                    Scanner { text in
                        onScan(text)
                        dismiss()
                    }
                    .ignoresSafeArea()
                } else {
                    ContentUnavailableView("Camera Unavailable",
                                           systemImage: "camera",
                                           description: Text("Allow camera access for wireDetour in Settings to scan QR codes."))
                }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
    }

    private struct Scanner: UIViewControllerRepresentable {
        let onScan: (String) -> Void

        func makeUIViewController(context: Context) -> DataScannerViewController {
            let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                               qualityLevel: .balanced,
                                               isHighlightingEnabled: true)
            vc.delegate = context.coordinator
            try? vc.startScanning()
            return vc
        }

        func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

        func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

        final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            let onScan: (String) -> Void
            private var done = false

            init(onScan: @escaping (String) -> Void) { self.onScan = onScan }

            func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
                guard !done else { return }
                for item in items {
                    if case .barcode(let code) = item, let text = code.payloadStringValue, text.contains("[Interface]") {
                        done = true
                        scanner.stopScanning()
                        onScan(text)
                        return
                    }
                }
            }
        }
    }
}
#endif
