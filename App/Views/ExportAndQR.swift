import CoreImage.CIFilterBuiltins
import SwiftUI
import UniformTypeIdentifiers
import WireDetourKit

/// A `.conf` file for the share sheet (D24). Rules travel inside it as
/// comment directives, so the file also imports into other WireGuard apps.
nonisolated struct ExportedConfig: Transferable {
    let config: TunnelConfiguration

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .wireGuardConfig) { exported in
            let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let url = dir.appending(path: "\(exported.config.name).conf")
            try WgQuickFormat.serialize(exported.config).write(to: url, atomically: true, encoding: .utf8)
            return SentTransferredFile(url)
        }
    }
}

struct QRCodeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let title: String
    let text: String

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                if let image = Self.qrImage(text) {
                    image
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 360)
                        .padding()
                        .background(.white, in: .rect(cornerRadius: 12))
                } else {
                    Text("This configuration is too large for a QR code.")
                }
                Text("This code contains the private key. Only show it to devices you own.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .frame(minWidth: 360, minHeight: 460)
    }

    static func qrImage(_ text: String) -> Image? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return Image(decorative: cg, scale: 1)
    }
}
