# wireDetour — Build Plan & Living Document

> A WireGuard-protocol app for macOS, iPadOS and iOS that sends **only chosen domains (and networks)** through a WireGuard tunnel and leaves everything else on the device untouched.
> **Anti-goals:** full-device VPN, traffic logging, accounts/servers, settings sprawl.
> **Deadline:** none — milestone-driven (D23).
> **Document status:** LIVING DOCUMENT. Coding models: read §0 first.

---

## 0. How to Work With This Document

This is your working agreement. Follow it every session.

### Startup ritual
1. Read §1 (vision + compass), §2 (Decisions Log) and §5 (Tracker) **before touching code**, every session — including the `*Notes:*` lines of the features you are about to work on and the ones they depend on.
2. Check §8 Changelog for anything changed since you last worked here.
3. Identify the next feature by ID (e.g. F2.3). Work on one feature at a time.

### Exploration discipline
- Read files fully before editing them. Do not edit from a grep snippet.
- Follow the notes trail: tracker notes name files, functions and gotchas left by previous sessions. Use them.
- §3 Data Model is the map. If the code has drifted from it, flag the drift in the tracker notes and update §3 — do not silently code around it.

### Change discipline
- Small, verifiable steps. Each step should build and, where possible, be tested on a real device (the Network Extension does **not** work properly in the iOS Simulator).
- Match existing patterns in the codebase (naming, file layout, error handling, comment density).
- **New dependencies require asking the user first.** Approved so far: wireguard-go (and its netstack package), WireGuardKit (as reference or vendored), Go toolchain.
- No opportunistic refactoring. If you see something worth fixing, add a `TODO:` note in the tracker instead.
- Update this document **in the same session** as the code: tick the checkbox, fill the `*Notes:*` line, add changelog entries for substantial changes. **A code change without a tracker note is an incomplete change.**

### Question protocol
- **Ask** on product decisions. **Decide** on implementation details.
- When you ask, batch your questions and give each 2–3 labeled options plus your recommendation (same format as the design interview).
- On minor ambiguities: state your assumption in the tracker notes and proceed. **Never** state-and-proceed on anything touching a D-decision, the config/data shape (§3), routing/DNS leak behavior, or privacy.
- Never ask what this document already answers.
- If blocked, mark the feature `[!]` and write the precise unblock condition (e.g. "`[!]` needs paid Apple Developer account with Network Extension capability").
- Report progress by feature ID ("F3.2 done, F3.3 in progress — see notes").

---

## 1. Product Vision

**Compass sentence:** *The tunnel is a detour, not the road — only the domains you name take it; everything else never knows wireDetour exists.*

**Promise to the user**
- Import a WireGuard config (or create one), type a few domains, flip one switch. Done.
- Everything not on your list behaves exactly as if the app weren't installed.
- If the tunnel can't carry a listed domain, that domain fails visibly — it never silently leaks outside (D20).
- Nothing you browse is stored (D19). The code is public so you can verify that (D17).

**Anti-goals**
- Not a full-device VPN. Not a VPN provider. No accounts, no backend, no analytics.
- No regex/keyword rule engines or traffic logs (D5, D19).
- No settings screens beyond what the core job needs.

**Platforms:** macOS 26, iPadOS 26, iOS 26 for v1 (D21). Android, Windows, Linux later (v2+), reusing the Go core (D3).

**Deadline:** none. Dogfood target is end of M2 (see §5).

---

## 2. Decisions Log

**Contested-change protocol:** decisions are never silently reversed. If implementation reality conflicts with a decision, mark it `⚠️ CONTESTED` in this table, explain why in the affected feature's tracker notes, and get the user's sign-off before changing course. Reversed decisions are struck through with a dated reason, never deleted.

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Support both **static** rules (fixed subnets) and **dynamic** rules (domains resolved on the fly, routes added at runtime). Ship static first, dynamic second; config format supports both from day one. | Covers private networks *and* public domains. Static is robust and gets to a dogfoodable app fast; designing the format up front avoids a migration. |
| D2 | Distribute via **App Store on all three platforms**. Packet Tunnel is an **app extension** (not a macOS system extension); one multiplatform app target. | Easiest install/update; a single extension flavor. Requires paid Apple Developer account. |
| D3 | Engine is a **Go shared core**: wireguard-go + our DNS proxy + rule matcher, bridged to Swift via a C bridge (WireGuardKit-style). | Same core reused later on Android (gomobile), Windows (wintun) and Linux. wireguard-go fits within the iOS extension memory limit. |
| D4 | Dynamic routing = **dynamic OS routes + hold**: proxy resolves a matched domain, adds its IPs to the tunnel's routes, and only then releases the DNS answer. Aggregate to /24 (IPv4) and /64 (IPv6), expire by TTL. | Real IPs everywhere, simple mental model. Holding the answer prevents the first connection leaking. Fake-IP rejected: packet rewriting + stale fake IPs after disconnect. Accepted cost: shared CDN IPs pull co-hosted sites into the tunnel. |
| D5 | Intercept **only matched domains** via OS split DNS (`NEDNSSettings.matchDomains`). Rules are **suffix matches** (`example.com` ⇒ `*.example.com`). All other DNS untouched. | True to "everything else as normal"; the app can't break the device's general DNS. Accepted cost: no regex/keyword rules. |
| D6 | Matched queries go to the **`DNS =` server from the .conf, through the tunnel**. If the .conf has no DNS line, the user must supply one before the tunnel can be enabled. | Answers reflect the far side's location/network (CDNs, private names) and are invisible to the local network. |
| D7 | DoH bypass: add Firefox canary **`use-application-dns.net`** to matchDomains and answer **NXDOMAIN**; in-app help note about disabling Chrome "Secure DNS". *(Amended by D24: the "test this rule" detector is now in v1.)* | Cheap; covers the most common silent-bypass case. Hardcoded-IP apps are out of scope. |
| D8 | **IPv6 adaptive**: if the tunnel `Address` has an IPv6 address, route AAAA results through the tunnel; otherwise return an **empty AAAA** answer for matched domains. | No IPv6 leak path in either case. |
| D9 | Rules live **per tunnel, inside the .conf, as comment directives**: `#! SplitDNS.Domain = …`, `#! SplitDNS.Route = …`. | A single portable file that remains valid for wg-quick and the official apps (they ignore comments). A custom `[SplitDNS]` section was rejected: wg-quick and the official apps throw on unknown lines. |
| D10 | `AllowedIPs` is **only the WireGuard peer filter**. OS routes come solely from Route directives + dynamic domain IPs (+ the DNS server /32). If a resolved IP falls outside AllowedIPs, show a warning on that rule. | Provider configs with `AllowedIPs = 0.0.0.0/0` work out of the box without tunneling everything. |
| D11 | **No sync in v1.** Private keys in the local Keychain. Configs move via file import, QR, AirDrop/Share, and export (D24). | No sync bugs; each device should have its own WireGuard key anyway (shared keys fight over the peer endpoint). |
| D12 | Lifecycle: **manual toggle + "Connect automatically"** (on-demand always-connect rule). *(Amended by D24: Wi-Fi SSID rules are in v1.)* | Split tunnel is cheap to leave on; set and forget. |
| D13 | **One active tunnel at a time.** Multiple simultaneous tunnels in one extension → v2. | Maps directly onto Apple's one-active-VPN model. Multi-peer within one .conf still works. |
| D14 | Adding tunnels: **.conf import** (Files, AirDrop, Mac drag-drop), **QR scan** (iOS/iPadOS), **editor** (raw text + friendly lists), and **create from scratch** (keypair generation + peer form). | Covers VPN providers and self-hosters. |
| D15 | Rule editor = **two plain lists: Domains and Networks**. No per-rule type picker; the engine decides static vs dynamic (a resolved IP already inside a Network adds no route). | Simplest possible UI; users don't need to understand routing. |
| D16 | **Free.** No StoreKit, no paywall, no accounts. | Fastest ship, easiest review; personal-tool spirit. Tip jar parked. |
| D17 | **Open source, MIT license**, public repo. | Trust for a VPN tool; compatible with wireguard-go/WireGuardKit (MIT). |
| D18 | App name **wireDetour**. Must never include "WireGuard" (registered trademark). Bundle IDs stay generic. | Name chosen by user; descriptive ("some domains take a detour"). |
| D19 | Diagnostics: **live status in RAM only** — handshake, bytes, matched domains → IPs → routes, D10 warnings. Cleared on disconnect. **No on-disk log.** | Debuggable without accumulating a browsing history. |
| D20 | **Fail closed**: if the tunnel can't serve a matched domain (peer down, upstream DNS timeout, route update failed), answer **SERVFAIL** and show the reason in status. | Matched traffic never leaks outside the tunnel. |
| D21 | Minimum OS: **iOS 26, iPadOS 26, macOS 26.** | Newest SwiftUI/design language, one code path. Accepted cost: excludes devices that can't update. |
| D22 | macOS: **menu bar extra** (status + per-tunnel toggles + "Open wireDetour…") **plus main window** sharing SwiftUI views with iPad. | Set-and-forget like the official app; editing still has room. |
| D23 | **No deadline.** Order: dogfood static (M2) → dynamic engine (M3) → App Store. | Quality bar decides shipping. |
| D24 | Scope check: keep all of v1; **promote into v1**: "Test this rule" button, Wi-Fi SSID rules, export/share config (.conf + QR display). Control Center toggle stays parked. | User's final scope call. |
| D25 | **DNS interception design** (resolves R7/F3.0): the `.conf` DNS addresses themselves are the resolver addresses given to the OS (no virtual IP). The engine wraps wireguard-go's tun device, consumes UDP/53 packets to those addresses, and injects its own upstream queries straight into wireguard-go; replies are matched by source port. TCP/53 to those addresses is dropped and TC is cleared on answers. | No address collisions to manage, no netstack dependency, small code. TCP drop keeps the route hold watertight (D4, D20); clearing TC means clients never need TCP. |
| D26 | **XcodeGen** (`project.yml`) generates the Xcode project; the `.xcodeproj` isn't committed. Go core is built by `scripts/build-core.sh` from an aggregate target. | Approved by user 2026-10-25. Reviewable diffs instead of pbxproj churn. |
| D27 | **Logo**: an original two-headed dragon (white head = normal road, orange head = detour) on a navy/teal background. Explicitly **not** derived from the WireGuard dragon. | User asked for a WireGuard-dragon look-alike; declined because of the trademark (R10, D18) and App Store risk. Source: `assets/logo/*.svg`. |
| D28 | macOS is **menu-bar-only**: no Dock icon (LSUIElement), single `Window` that opens from "Open wireDetour…", not at launch. Refines D22. | User request 2026-10-26: set-and-forget belongs in the menu bar; a Dock icon adds nothing. |

---


## 3. Data Model (reference)

### 3.1 Config file format (the source of truth for a tunnel — D9)

```ini
[Interface]
PrivateKey = <base64>
Address = 10.8.0.2/32, fd00:8::2/128
DNS = 10.8.0.1

#! SplitDNS.Domain = example.com
#! SplitDNS.Domain = home.lan
#! SplitDNS.Route = 10.0.0.0/24
#! SplitDNS.Route = 192.168.50.0/24

[Peer]
PublicKey = <base64>
PresharedKey = <base64>        # optional
Endpoint = vpn.example.net:51820
AllowedIPs = 0.0.0.0/0, ::/0   # peer filter only (D10)
PersistentKeepalive = 25
```

Grammar notes:
- Directive prefix is exactly `#!` followed by optional whitespace and `SplitDNS.<Key> = <value>`. Keys: `Domain`, `Route`. One value per line. Unknown `SplitDNS.*` keys are preserved on round-trip and ignored.
- Directives may appear anywhere but the serializer writes them in `[Interface]` after `DNS`.
- `Domain` values: lowercased, trailing dot stripped, no wildcards (suffix semantics are implicit, D5). Validate as a hostname.
- `Route` values: IPv4 or IPv6 CIDR.
- Round-trip must preserve all other comments and unknown lines as far as practical (users will hand-edit).

### 3.2 Swift app model (sketch)

```swift
struct TunnelConfig: Identifiable, Codable {
    let id: UUID
    var name: String
    var interface: InterfaceConfig        // privateKey ref (Keychain), addresses, dns, listenPort?, mtu?
    var peers: [PeerConfig]               // publicKey, presharedKey ref?, endpoint, allowedIPs, keepalive
    var domains: [String]                 // D15 "Domains"
    var networks: [IPAddressRange]        // D15 "Networks"
    var rawExtras: [String]               // preserved unknown lines/comments
}

struct DeviceTunnelSettings: Codable {    // per-device, NOT in .conf
    var connectAutomatically: Bool        // D12
    var ssidRules: SSIDRules?             // D24: e.g. disconnect on trusted SSIDs
}
```

- Private and preshared keys live in the Keychain (shared access group with the extension), referenced by ID — never in UserDefaults or plain files.
- Tunnels are persisted as `NETunnelProviderManager` configurations; the full .conf text (keys redacted → Keychain ref) is stored in `providerConfiguration`, same approach as WireGuardKit.
- SSID rules and "connect automatically" map to `NEOnDemandRule`s on the manager. They are device-specific and intentionally **not** stored in the .conf.

### 3.3 Extension network settings (derived)

| Setting | Static (M2) | + Dynamic (M3) |
|---|---|---|
| `NEDNSSettings.servers` | tunnel DNS (D6) — or the virtual resolver IP (see §4 R7) | virtual resolver IP |
| `NEDNSSettings.matchDomains` | `domains` + `use-application-dns.net` (D7) | same |
| `includedRoutes` (v4/v6) | `networks` + DNS server /32 | + dynamic routes |
| `excludedRoutes` | none | none |

### 3.4 Go engine state (sketch)

```go
type DynamicRoute struct {
    Prefix    netip.Prefix   // aggregated: /24 v4, /64 v6 (D4)
    Domains   []string       // which matched names produced it (for status, D19)
    ExpiresAt time.Time      // max TTL of contributing answers, floor 60s
}

type Engine struct {
    staticRoutes  []netip.Prefix
    dynamic       map[netip.Prefix]*DynamicRoute
    allowedIPs    []netip.Prefix      // for D10 warnings
    hasIPv6       bool                // D8
    applyRoutes   func([]netip.Prefix) error  // Swift callback → setTunnelNetworkSettings; blocks until applied (D4 hold)
}
```

Swift ↔ Go bridge surface (C ABI, keep it small): `wdTurnOn(settings, tunFd)`, `wdTurnOff`, `wdSetRouteCallback`, `wdGetStatus() -> JSON`, `wdTestDomain(name) -> JSON` (D24), `wdBumpSockets` (network change).

---

## 4. Research Notes (carry forward)

Facts gathered during the interview. Items marked *(verify)* were stated from memory and must be confirmed before relying on them.

- **R1 — Official app's DNS behavior:** wireguard-apple sets `matchDomains = [""]`, which captures *all* DNS through the tunnel. Our core difference is setting real match domains. *(verify in wireguard-apple `PacketTunnelSettingsGenerator`)*
- **R2 — Unknown .conf sections are rejected:** `wg-quick` passes non-`[Interface]` lines to `wg setconf`, which fails on unknown lines; wireguard-apple's parser throws `invalidLine`. Hence the comment-directive format (D9).
- **R3 — Route updates at runtime:** `NEPacketTunnelProvider.setTunnelNetworkSettings` can be called again while connected to change routes. Expect a short stall (~50–200 ms) per call; batch/coalesce updates. *(verify latency on real devices in M3 spike)*
- **R4 — Extension memory limit:** packet tunnel extensions on iOS are limited to ~50 MB. wireguard-go fits but watch Go GC (`GOMEMLIMIT`), DNS caches and route maps. *(verify current limit for iOS 26)*
- **R5 — Firefox canary:** Firefox disables its default DoH when `use-application-dns.net` returns NXDOMAIN/no answer from the system resolver.
- **R6 — Chrome Secure DNS:** Chrome may auto-upgrade to DoH when the system resolver is a known DoH provider; users can disable it in Settings → Privacy → Use secure DNS. Help text only (D7).
- **R7 — Where the DNS proxy listens:** the proxy must receive packets for matched queries from utun. Plan: advertise a virtual resolver IP in `NEDNSSettings.servers`, route it into the tunnel, intercept UDP/TCP :53 to that IP in the Go packet path before WireGuard encryption, and forward upstream to the .conf `DNS` via the tunnel (wireguard-go `tun/netstack` or a crafted-packet path). Choose a virtual IP that won't collide with user networks. *(M3 spike — decide and record as a new D-number)*
- **R8 — Simulator:** Network Extensions don't run properly in the iOS Simulator; test on device or on the Mac.
- **R9 — Entitlements:** Network Extension (packet-tunnel-provider) capability + App Groups + Keychain sharing on app and extension. Requires paid Apple Developer Program membership.
- **R10 — Trademark:** "WireGuard" is a registered trademark of Jason A. Donenfeld; it may not appear in the app name. The description may state compatibility with the WireGuard® protocol. Also do a name search for "wireDetour" before submission ("Wire" is a messenger brand; low risk). *(verify current trademark policy wording)*
- **R11 — One active VPN:** Apple platforms allow one active VPN configuration at a time; activating another deactivates the current one (basis for D13).
- **R12 — wireguard-apple tun fd:** WireGuardKit locates the utun file descriptor and hands it to wireguard-go; reuse that technique rather than `packetFlow` read/write loops for performance.

---

## 5. Implementation Tracker — LIVING SECTION

Statuses: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked (state unblock condition).
Every feature gets its `*Notes:*` filled when touched: files, decisions made, gotchas.

### M0 — Skeleton
- [x] **F0.1** Repo init: MIT `LICENSE`, `README.md`, `.gitignore`, this document at root (D17).
  *Notes:* 2026-10-25. MIT LICENSE, README, .gitignore (generated `wireDetour.xcodeproj/` and `build/` are ignored; `project.yml` is the source per D26).
- [x] **F0.2** Xcode multiplatform app target (iOS/iPadOS/macOS 26) + Packet Tunnel app-extension target; generic bundle IDs (D2, D18, D21).
  *Notes:* 2026-10-25. XcodeGen `project.yml`: multiplatform targets `wireDetour` (app) and `WireDetourTunnel` (app extension) via `supportedDestinations`. Identity in `Config/Base.xcconfig` (`BUNDLE_ID_PREFIX = io.github.thecheesetown`, set 2026-10-26). App icon from `assets/logo` (D27).
- [~] **F0.3** Entitlements: Network Extension, App Group, Keychain sharing on both targets (R9).
  *Notes:* Entitlement files in `Config/` (iOS + separate macOS ones with sandbox). Keychain group `$(AppIdentifierPrefix)$(BUNDLE_ID_PREFIX).shared` passed via Info.plist `WDKeychainAccessGroup`. `[!]` Runtime unverified: needs `DEVELOPMENT_TEAM` + paid account with Network Extension capability. Unsigned simulator run fails at Keychain add with "A required entitlement isn't present" — expected.
- [x] **F0.4** Go core module (`core/`) with wireguard-go; build script producing an xcframework for iOS device, iOS simulator (compile-only) and macOS; Xcode build phase invokes it (D3).
  *Notes:* 2026-10-25. `scripts/build-core.sh` cross-compiles `core/bridge` (c-archive) for ios-arm64, ios-sim arm64+x86_64, macOS arm64+x86_64 → `build/WireDetourCore.xcframework` (~70 s cold, skipped when no .go/.h changed). Runs from aggregate target `WireDetourCore`, which the extension depends on. Headers + `module.modulemap` (module `WireDetourCore`) in `core/bridge/include`.
- [x] **F0.5** Minimal C bridge: `wdTurnOn`/`wdTurnOff`/`wdGetStatus` callable from the extension (§3.4).
  *Notes:* 2026-10-25. `core/bridge/main.go` + hand-written `wiredetour.h`: wdTurnOn/Off, wdGetStatus, wdTestDomain, wdBumpSockets, wdSetLogger, wdVersion. Route callback is a C function pointer + context (D4 hold).

### M1 — Config & UI basics
- [x] **F1.1** .conf parser/serializer incl. `#! SplitDNS.*` directives, round-trip of unknown lines, validation (§3.1, D9). Unit-tested.
  *Notes:* 2026-10-25. `WgQuickFormat` in WireDetourKit. Unknown sections/keys are errors (wg-quick parity); wg-quick-only keys (PostUp, Table…) and comments preserved; unknown `SplitDNS.*` directives preserved. Domains normalized (`*.`/trailing dot stripped). Tests: `swift test` (14 tests).
- [~] **F1.2** Keychain storage of private/preshared keys, shared with extension (§3.2, D11).
  *Notes:* `Keychain` stores the whole .conf (data-protection keychain, AfterFirstUnlockThisDeviceOnly); profile holds only `passwordReference`. Built for iOS/iPadOS/macOS; untested on device (needs signing, see F0.3).
- [~] **F1.3** Tunnel persistence via `NETunnelProviderManager` (load/save/delete) (§3.2).
  *Notes:* `TunnelsManager` (App/TunnelsManager.swift). Filters `loadAllFromPreferences` by our providerBundleIdentifier — found in the simulator that other apps' VPN profiles are otherwise listed. Built for iOS/iPadOS/macOS; untested on device (needs signing, see F0.3).
- [x] **F1.4** Tunnel list screen (shared iPhone/iPad/Mac window) with toggle per tunnel.
  *Notes:* 2026-10-25. NavigationSplitView list with per-row toggle, empty-state onboarding. Verified rendering in iOS 26.5 simulator.
- [~] **F1.5** Import: Files picker, AirDrop/"Open in", Mac drag-drop (D14).
  *Notes:* fileImporter, `.onOpenURL`, `.dropDestination`. Simulator: opening a .conf parses it and reaches save (fails only on missing entitlement). Duplicate names get " 2" suffix.
- [~] **F1.6** QR scan import on iOS/iPadOS (D14).
  *Notes:* VisionKit `DataScannerViewController`, accepts only payloads containing "[Interface]". Camera usage string set. Untested (needs device).
- [~] **F1.7** Editor: friendly Domains + Networks lists (D15) and raw .conf text view; require DNS if missing (D6).
  *Notes:* Domains/Networks lists in detail view (`RuleListEditor`, paste of several entries supported). Editor sheet has Form and raw Text tabs; Form edits are applied onto the parsed config so rules/comments survive. Saving a running tunnel restarts it. Built for iOS/iPadOS/macOS; untested on device (needs signing, see F0.3).
- [~] **F1.8** Create from scratch: keypair generation, interface/peer form, show public key to copy (D14).
  *Notes:* Create mode: CryptoKit Curve25519 keypair, public key shown for copying, PSK generator. Saving with validation issues is allowed (they show under "Check"); starting is blocked.
- [~] **F1.9** Export/share: .conf with directives via share sheet; display QR on screen (D24).
  *Notes:* `ExportedConfig` Transferable writes `<name>.conf` for ShareLink; `QRCodeSheet` via CoreImage, with a private-key warning.

### M2 — Static tunnel  ★ DOGFOOD TARGET
*At the end of M2 the app is genuinely usable for private domains/networks on your own devices.*
- [~] **F2.1** Extension brings up wireguard-go on the utun fd (R12).
  *Notes:* `TunnelDescriptor.find()` scans fds with getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME) — avoids the ctl_info structs missing from the iOS SDK. Endpoint hostnames resolved in Swift (`EndpointResolver`, prefers IPv4). Built for iOS/iPadOS/macOS; untested on device (needs signing, see F0.3).
- [~] **F2.2** Network settings per §3.3 static column: matchDomains = Domains + canary, includedRoutes = Networks + DNS /32; AllowedIPs used only as peer filter (D5, D7, D10).
  *Notes:* `TunnelPlan` (tested) → `makeSettings`: matchDomains + canary, `matchDomainsNoSearch`, includedRoutes = Networks + DNS host routes + dynamic. Interface addresses use their own masks; no implicit routes added. Built for iOS/iPadOS/macOS; untested on device (needs signing, see F0.3).
- [x] **F2.3** Canary handling for `use-application-dns.net` → NXDOMAIN (D7). (In M2 this may require the minimal resolver from F3.1 — if so, note it and pull F3.1 forward.)
  *Notes:* 2026-10-25. Pulled the resolver forward (F3.1), as anticipated: the engine answers the canary with NXDOMAIN locally. Go test `TestCanaryIsNXDOMAIN`.
- [~] **F2.4** One active tunnel at a time (D13).
  *Notes:* `setActive` turns off on-demand and stops every other tunnel before starting (D13).
- [~] **F2.5** "Connect automatically" on-demand rule (D12).
  *Notes:* `DeviceSettings` in providerConfiguration; on-demand rules = [Disconnect on trusted SSIDs, Connect any]. Manual off disables on-demand so it doesn't reconnect.
- [~] **F2.6** Basic status: connected state, last handshake, bytes in/out.
  *Notes:* Handshake/bytes parsed from wireguard-go IpcGet in the bridge; shown in Live section, polled every 1 s while visible.
- [~] **F2.7** macOS menu bar extra: status icon, tunnel toggles, "Open wireDetour…" (D22).
  *Notes:* `MenuBarExtra` with per-tunnel toggles, "Open wireDetour…", Quit. Builds on macOS; not yet run.
- [~] **F2.8** Network-change handling (Wi-Fi ↔ cellular, sleep/wake): socket rebinding, tunnel survives.
  *Notes:* NWPathMonitor → `wdBumpSockets` (BindUpdate + keepalives, retried). TODO: re-resolve hostname endpoints after network changes (WireGuardKit does this for DNS64).

### M3 — Dynamic engine
- [~] **F3.0** Spike: virtual resolver IP + packet interception approach (R7) and measure `setTunnelNetworkSettings` latency (R3). Record outcome as a new D-number.
  *Notes:* Interception approach decided and implemented (D25). Still to do on device: measure setTunnelNetworkSettings latency (R3) and confirm re-applying settings mid-session doesn't disturb open connections.
- [x] **F3.1** In-extension DNS server for matched domains; upstream = .conf DNS via tunnel (D6). UDP + TCP.
  *Notes:* 2026-10-25. `core/engine`: tun wrapper intercepts UDP/53 to the .conf DNS IPs; upstream queries injected into wireguard-go as crafted IPv4/IPv6 UDP packets from the tunnel address; replies matched by source port. TCP/53 to the DNS IPs is dropped (fail closed) and TC is cleared on answers. Tested with a fake OS tun + fake peer.
- [x] **F3.2** Hold-then-answer: on A/AAAA answer, compute needed prefixes, apply routes via Swift callback, release answer only after success (D4).
  *Notes:* 2026-10-25. `router.ensure` blocks until the Swift callback returns from setTunnelNetworkSettings (4 s timeout) → answer released. Test `TestMatchedDomainAddsRouteBeforeAnswer`.
- [x] **F3.3** Route aggregation (/24, /64), TTL-based expiry with floor, coalesced updates, skip IPs already inside Networks (D4, D15).
  *Notes:* 2026-10-25. /24 and /64 aggregation, 10 ms coalescing, TTL floor 60 s, removal only after TTL AND 5 min idle (per-packet lock-free usage tracking), cap 2048 routes. Tests in routes_test.go.
- [x] **F3.4** IPv6 adaptive: route AAAA if tunnel has v6 address, else empty AAAA (D8).
  *Notes:* 2026-10-25. AAAA for matched names answered empty locally when the tunnel has no IPv6 address; AAAA results filtered otherwise.
- [x] **F3.5** Fail closed: SERVFAIL on upstream timeout / peer down / route failure; reason recorded for status (D20).
  *Notes:* 2026-10-25. SERVFAIL on upstream timeout (2 × 2 s) and on route-apply failure; last 20 failures in status.
- [x] **F3.6** AllowedIPs warning when a resolved IP is outside the peer's AllowedIPs (D10).
  *Notes:* 2026-10-25. Per-domain warnings in status; also warns in editor when a Network is outside all AllowedIPs. Static-only engine mode (dynamicRoutes=false) warns when an IP is outside Networks — currently unused, the app always enables dynamic routes.
- [!] **F3.7** Memory budget check under load (many domains, CDN-heavy sites) against extension limit (R4).
  *Notes:* Needs a device. Unblock: signed build on an iPhone, run CDN-heavy sites, watch extension memory in Instruments (R4).

### M4 — Visibility & control
- [~] **F4.1** Live status view: matched domains → IPs → routes, warnings, failure reasons; RAM only, cleared on disconnect (D19).
  *Notes:* `LiveStatusSection`: handshake, bytes, recent failures, matched domains → IPs/warnings, dynamic routes with domains + last use. Nothing persisted (D19); os_log never gets domain names.
- [~] **F4.2** "Test this rule" button: resolves the domain via the engine and reports whether traffic would/did go through the tunnel (D24, D7).
  *Notes:* Engine `TestDomain` (tested) resolves A (+AAAA with IPv6) through the normal path, so it installs routes like a real lookup, then reports viaTunnel / inAllowedIPs / last traffic per address. UI in `TestRuleSection`.
- [~] **F4.3** Wi-Fi SSID rules (e.g. don't connect on trusted SSIDs) via on-demand rules; per-device setting (D24, §3.2).
  *Notes:* Trusted Wi-Fi list (one SSID per entry, spaces allowed) shown when Connect Automatically is on → NEOnDemandRuleDisconnect(ssidMatch).
- [x] **F4.4** In-app help: Chrome Secure DNS note, what Domains/Networks mean, fail-closed explanation (D7, D20).
  *Notes:* 2026-10-25. `HelpView`: how it works, fail-closed, Chrome Secure DNS steps, directive format, privacy.

### M5 — Ship v1
- [ ] **F5.1** Privacy policy (no data collected; nothing leaves the device except tunnel traffic).
  *Notes:*
- [ ] **F5.2** App Store metadata, screenshots, App Review notes (explain split tunnel + provide a test config) (D2).
  *Notes:*
- [ ] **F5.3** Trademark/name check, "uses the WireGuard® protocol" wording, third-party license notices (R10, D17).
  *Notes:*
- [ ] **F5.4** TestFlight beta on all three platforms; fix-list.
  *Notes:*
- [ ] **F5.5** Public repo release, README with build instructions.
  *Notes:*

### v1.5 (planned, not started)
- [ ] **F6.1** Control Center / Shortcuts toggle via App Intents (parked at D24).
  *Notes:*
- [ ] **F6.2** Rules-only iCloud sync (parked at D11).
  *Notes:*
- [ ] **F6.3** Tip jar (parked at D16).
  *Notes:*
- [ ] **F6.4** Re-resolve hostname endpoints after network changes / DNS64 (found while building F2.8).
  *Notes:*
- [ ] **F6.5** Unit tests for the app layer (TunnelsManager with a fake NE layer) and a Go test for the bridge's status JSON shape vs. Swift `LiveStatus`.
  *Notes:*

---

## 6. Document Conventions

- **Never delete.** Strike through obsolete content with a dated reason: `~~old text~~ (2026-11-03: replaced by D27 because …)`.
- Every completed feature gets a filled `*Notes:*` line.
- Deviations from a decision follow the contested-change protocol in §2.
- New decisions get the next D-number (next: **D29**). Never renumber.
- New features get the next ID within their milestone. Never renumber.
- Date-stamp substantial edits in §8.
- New sections go after existing ones or as subsections; never renumber §0–§8.

---

## 7. Parking Lot (v2 / v3 / someday)

- **Multiple simultaneous tunnels** in one extension (D13) — v2. Open issues: rule conflicts, per-tunnel DNS, route ownership.
- **Android** (VpnService + gomobile Go core), **Windows** (wintun + Go core), **Linux** (likely thin: systemd-resolved `resolvectl domain wg0 ~example.com` + routes; dynamic engine via Go core) — v2+. Constraint: must read the same .conf directive format (D9).
- **Control Center toggle** — v1.5 (F6.1).
- **Rules-only iCloud sync** — v1.5 (F6.2). Constraint: keys never sync.
- **Tip jar** — v1.5 (F6.3). Constraint: app stays fully free (D16).
- **Fake-IP engine** — only if dynamic routes prove inadequate (CDN collateral, latency). Would be a contested change to D4.
- **Regex/keyword rules / capture-all DNS** — rejected for v1 (D5); revisit only with strong user demand.
- **Hardcoded-IP app handling** — out of scope (D7).

---

## 8. Changelog

- **2026-10-25** — Document created from design interview (D1–D24). No code yet.
- **2026-10-25** — M0–M4 implemented. Go engine + bridge (`go test -race` green), WireDetourKit (`swift test` green), app + extension build for macOS, iOS and iOS Simulator. Nothing verified on a device yet: needs `DEVELOPMENT_TEAM`. Added D25 (DNS interception), D26 (XcodeGen), D27 (original logo). Status `[~]` = built, awaiting on-device verification. M2/M3 effectively merged: the dynamic engine is always on.
- **2026-10-26** — Signed macOS build runs (team ID kept in untracked `Config/Local.xcconfig`). Fixed the macOS layout: wider sidebar (min 220), the empty state moved to the detail pane (sidebar only on compact iOS), and a minimum window size. First real tunnel on macOS works: import → Keychain → connect; the only unscoped default route stays on the physical interface; the DNS host route and a dynamic /24 are added via utun; the extension uses about 16 MB RSS with no errors logged. iOS is still untested on a device. Added D28 (menu-bar-only on macOS).
