#!/bin/bash
# Builds the Go core (core/bridge) into build/WireDetourCore.xcframework for
# iOS devices, the iOS simulator and macOS. Skips work if nothing changed.
# Usage: scripts/build-core.sh [--force]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$ROOT/core"
OUT="$ROOT/build/core"
XCF="$ROOT/build/WireDetourCore.xcframework"
MIN_OS=26.0

# Xcode run-script phases get a minimal PATH.
export PATH="/usr/local/go/bin:/usr/local/bin:/opt/homebrew/bin:$HOME/go/bin:$PATH"
command -v go >/dev/null || { echo "error: Go toolchain not found (install from go.dev)"; exit 1; }

if [[ "${1:-}" != "--force" && -d "$XCF" ]]; then
    if [[ -z "$(find "$CORE" "$0" \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name '*.h' -o -name '*.modulemap' -o -name 'build-core.sh' \) -newer "$XCF/Info.plist" -print -quit)" ]]; then
        echo "WireDetourCore is up to date"
        exit 0
    fi
fi

# Xcode exports its own build settings (SDKROOT, ARCHS, …) which would confuse
# the nested clang invocations below.
unset SDKROOT ARCHS PLATFORM_NAME IPHONEOS_DEPLOYMENT_TARGET MACOSX_DEPLOYMENT_TARGET

build_slice() { # goos goarch sdk clang-target output-dir
    local goos=$1 goarch=$2 sdk=$3 target=$4 dir=$5
    local sdkpath clang
    sdkpath="$(xcrun --sdk "$sdk" --show-sdk-path)"
    clang="$(xcrun --sdk "$sdk" -f clang)"
    mkdir -p "$dir"
    echo "Building $goos/$goarch ($sdk)"
    (cd "$CORE" && \
        CGO_ENABLED=1 GOOS=$goos GOARCH=$goarch \
        CC="$clang" \
        CGO_CFLAGS="-isysroot $sdkpath -target $target -O2" \
        CGO_LDFLAGS="-isysroot $sdkpath -target $target" \
        go build -buildmode=c-archive -trimpath -ldflags="-s -w" \
            -o "$dir/libwiredetour.a" ./bridge)
    rm -f "$dir/libwiredetour.h"
}

rm -rf "$OUT" "$XCF"
build_slice ios       arm64 iphoneos        "arm64-apple-ios$MIN_OS"            "$OUT/ios/arm64"
build_slice ios       arm64 iphonesimulator "arm64-apple-ios$MIN_OS-simulator"  "$OUT/sim/arm64"
build_slice ios       amd64 iphonesimulator "x86_64-apple-ios$MIN_OS-simulator" "$OUT/sim/amd64"
build_slice darwin    arm64 macosx          "arm64-apple-macos$MIN_OS"          "$OUT/mac/arm64"
build_slice darwin    amd64 macosx          "x86_64-apple-macos$MIN_OS"         "$OUT/mac/amd64"

mkdir -p "$OUT/sim/fat" "$OUT/mac/fat"
lipo -create "$OUT/sim/arm64/libwiredetour.a" "$OUT/sim/amd64/libwiredetour.a" -output "$OUT/sim/fat/libwiredetour.a"
lipo -create "$OUT/mac/arm64/libwiredetour.a" "$OUT/mac/amd64/libwiredetour.a" -output "$OUT/mac/fat/libwiredetour.a"

HEADERS="$CORE/bridge/include"
xcodebuild -create-xcframework \
    -library "$OUT/ios/arm64/libwiredetour.a" -headers "$HEADERS" \
    -library "$OUT/sim/fat/libwiredetour.a"   -headers "$HEADERS" \
    -library "$OUT/mac/fat/libwiredetour.a"   -headers "$HEADERS" \
    -output "$XCF" >/dev/null
echo "Built $XCF"
