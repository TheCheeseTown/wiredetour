<p align="center"><img src="assets/logo/wiredetour-logo.svg" width="128" alt="wireDetour logo"></p>

# wireDetour

Send **only the domains you choose** through a WireGuard® tunnel. Everything else on your Mac, iPad or iPhone keeps using your normal connection.

- Import a `.conf` file (or scan a QR code, or create one), list your domains, and turn the tunnel on.
- Domains include their subdomains. Their DNS lookups go to the configuration's DNS server through the tunnel, and the addresses they return are routed into the tunnel before the app gets its answer.
- If the tunnel can't carry a listed domain, that domain fails visibly instead of silently leaking outside.
- Rules live in the `.conf` file as comment lines, so the same file still works in every other WireGuard app:

```ini
#! SplitDNS.Domain = example.com
#! SplitDNS.Route = 192.168.50.0/24
```

No servers, no accounts, no logs. See [BUILD_PLAN.md](BUILD_PLAN.md) for the design decisions.

## Building

Requirements: Xcode 26, Go 1.24+, [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`).

```sh
xcodegen generate            # creates wireDetour.xcodeproj from project.yml
scripts/build-core.sh        # optional: Xcode runs this automatically
open wireDetour.xcodeproj
```

Before running on a device, create `Config/Local.xcconfig` (untracked) containing `DEVELOPMENT_TEAM = <your team ID>`. Forks should also change `BUNDLE_ID_PREFIX` in `Config/Base.xcconfig`. A paid Apple Developer account is needed for the Network Extension capability, and the tunnel doesn't run in the iOS Simulator.

Tests:

```sh
(cd core && go test -race ./...)
(cd Packages/WireDetourKit && swift test)
```

## Layout

| Path | What |
|---|---|
| `core/engine` | Go split-DNS engine: DNS interception, route hold, status |
| `core/bridge` | C interface (`include/wiredetour.h`) built into `WireDetourCore.xcframework` |
| `Packages/WireDetourKit` | Swift: `.conf` parser, keys, Keychain, tunnel plan, IPC types |
| `App` | SwiftUI app for iOS, iPadOS and macOS (menu bar on Mac) |
| `TunnelExtension` | Packet tunnel provider |

## License

MIT. wireDetour uses [wireguard-go](https://git.zx2c4.com/wireguard-go) (MIT). "WireGuard" is a registered trademark of Jason A. Donenfeld; wireDetour is not affiliated with or endorsed by the WireGuard project.
