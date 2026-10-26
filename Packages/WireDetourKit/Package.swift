// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "WireDetourKit",
    platforms: [.iOS(.v26), .macOS(.v26)],
    products: [
        .library(name: "WireDetourKit", targets: ["WireDetourKit"]),
    ],
    targets: [
        .target(name: "WireDetourKit"),
        .testTarget(name: "WireDetourKitTests", dependencies: ["WireDetourKit"]),
    ]
)
