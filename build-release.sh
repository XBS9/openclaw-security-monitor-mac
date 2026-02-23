#!/usr/bin/env bash
# build-release.sh — Builds OpenClaw Security Monitor for both macOS architectures.
#
# Output:
#   publish/x64/OpenClawSecurityMonitorMac   (Intel — 2019 and older)
#   publish/arm64/OpenClawSecurityMonitorMac (Apple Silicon — M1/M2/M3)
#
# Usage:
#   chmod +x build-release.sh
#   ./build-release.sh
#
# Requirements: .NET 8 SDK  (https://dotnet.microsoft.com/download)

set -euo pipefail

PROJECT="OpenClawSecurityMonitorMac.csproj"
OUT_BASE="$(pwd)/publish"

build_arch() {
    local arch="$1"
    local out="$OUT_BASE/$arch"
    echo ""
    echo "==> Building osx-$arch ..."
    dotnet publish "$PROJECT" \
        -c Release \
        -r "osx-$arch" \
        --self-contained true \
        -p:PublishSingleFile=true \
        -p:EnableCompressionInSingleFile=true \
        -p:DebugType=none \
        -o "$out"

    # Remove Avalonia dylibs that were embedded — single-file build on macOS
    # still drops them alongside the binary (Avalonia limitation).
    # They must ship with the binary.
    echo "    Output: $out"
    ls -lh "$out/OpenClawSecurityMonitorMac" 2>/dev/null || true
}

echo "OpenClaw Security Monitor — Release Build"
echo "========================================="
dotnet --version

build_arch "x64"
build_arch "arm64"

echo ""
echo "==> Build complete."
echo ""
echo "  Intel (x64):         publish/x64/OpenClawSecurityMonitorMac"
echo "  Apple Silicon (arm64): publish/arm64/OpenClawSecurityMonitorMac"
echo ""
echo "  To remove Gatekeeper quarantine on target Mac:"
echo "    xattr -d com.apple.quarantine OpenClawSecurityMonitorMac"
echo "    xattr -d com.apple.quarantine *.dylib"
echo ""
echo "  To run:"
echo "    chmod +x OpenClawSecurityMonitorMac"
echo "    ./OpenClawSecurityMonitorMac"
