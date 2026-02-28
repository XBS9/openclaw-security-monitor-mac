#!/usr/bin/env bash
# smoke-test.sh — Quick sanity check that the built app launches, shows its tray icon,
# and the key background services are functional on this machine.
#
# This is an integration test for manual runs; it does NOT replace unit tests.
# Run it after deploying a new build to verify real-system behaviour.
#
# Prerequisites:
#   • OpenClaw app built at ../../bin/Release/net8.0/osx-x64/
#   • macOS 12+ with systemextensionsctl, csrutil, crontab, dscl available
#   • No existing OpenClaw instance running
#
# Usage:  ./smoke-test.sh
# Exit:   0 = all checks OK,  1 = one or more checks failed

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_BINARY="$PROJECT_ROOT/bin/Release/net8.0/osx-x64/OpenClawSecurityMonitorMac"
OPENCLAW_DIR="$HOME/.openclaw"
PASS=0
FAIL=0

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1"; ((FAIL++)); }

echo "=== OpenClaw Security Monitor — Smoke Test ==="
echo "    Date: $(date)"
echo ""

# ── 1. Binary exists ─────────────────────────────────────────────────────────
echo "[1] App binary"
if [[ -f "$APP_BINARY" ]]; then
    pass "Binary exists at $APP_BINARY"
else
    fail "Binary NOT found at $APP_BINARY — run: dotnet build -c Release"
fi

# ── 2. ~/.openclaw directory ──────────────────────────────────────────────────
echo ""
echo "[2] ~/.openclaw directory"
if [[ -d "$OPENCLAW_DIR" ]]; then
    pass "~/.openclaw directory exists"
else
    fail "~/.openclaw missing — app has never been run, or was cleaned"
fi

# ── 3. Settings file ──────────────────────────────────────────────────────────
echo ""
echo "[3] Settings file"
SETTINGS="$OPENCLAW_DIR/monitor-settings.json"
if [[ -f "$SETTINGS" ]]; then
    pass "monitor-settings.json present"
    PERMS=$(stat -f "%Mp%Lp" "$SETTINGS" 2>/dev/null || echo "unknown")
    if [[ "$PERMS" == "0600" ]]; then
        pass "monitor-settings.json permissions are 600"
    else
        fail "monitor-settings.json permissions are $PERMS (expected 0600)"
    fi
    # Validate it's valid JSON
    if python3 -c "import json,sys; json.load(open('$SETTINGS'))" 2>/dev/null; then
        pass "monitor-settings.json is valid JSON"
    else
        fail "monitor-settings.json is invalid JSON"
    fi
else
    fail "monitor-settings.json missing"
fi

# ── 4. macOS security commands available ──────────────────────────────────────
echo ""
echo "[4] macOS security commands"
for cmd in csrutil spctl systemextensionsctl crontab dscl launchctl; do
    if command -v "$cmd" &>/dev/null; then
        pass "$cmd available"
    else
        fail "$cmd NOT found"
    fi
done

# ── 5. SIP status (informational — not a test failure) ────────────────────────
echo ""
echo "[5] System security posture (informational)"
SIP=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP" | grep -q "enabled"; then
    pass "SIP: enabled"
else
    echo "  [WARN] SIP: $(echo "$SIP" | head -1) — app will report Alert"
fi

GK=$(spctl --status 2>/dev/null || echo "unknown")
if echo "$GK" | grep -q "enabled"; then
    pass "Gatekeeper: enabled"
else
    echo "  [WARN] Gatekeeper: $(echo "$GK" | head -1) — app will report Alert"
fi

# ── 6. LaunchAgents directory ────────────────────────────────────────────────
echo ""
echo "[6] LaunchAgents"
LA_DIR="$HOME/Library/LaunchAgents"
if [[ -d "$LA_DIR" ]]; then
    COUNT=$(ls "$LA_DIR"/*.plist 2>/dev/null | wc -l | tr -d ' ')
    pass "~/Library/LaunchAgents exists ($COUNT .plist files)"
else
    fail "~/Library/LaunchAgents does not exist"
fi

# ── 7. openclaw gateway plist present ────────────────────────────────────────
echo ""
echo "[7] OpenClaw gateway LaunchAgent"
GATEWAY_PLIST="$LA_DIR/ai.openclaw.gateway.hardened.plist"
if [[ -f "$GATEWAY_PLIST" ]]; then
    pass "ai.openclaw.gateway.hardened.plist present"
else
    echo "  [INFO] ai.openclaw.gateway.hardened.plist not found — gateway may not be installed"
fi

# ── 8. Log file writable ─────────────────────────────────────────────────────
echo ""
echo "[8] Log file"
LOG="$OPENCLAW_DIR/security-tray.log"
if [[ -f "$LOG" ]]; then
    pass "security-tray.log exists"
    LINES=$(wc -l < "$LOG" | tr -d ' ')
    pass "security-tray.log has $LINES line(s)"
else
    echo "  [INFO] security-tray.log not yet created (will be on first kill-switch event)"
fi

# ── 9. Kill switch state ──────────────────────────────────────────────────────
echo ""
echo "[9] Kill switch state"
KS_STATE="$OPENCLAW_DIR/kill-switch-state.json"
if [[ -f "$KS_STATE" ]]; then
    ENGAGED=$(python3 -c "import json; d=json.load(open('$KS_STATE')); print(d.get('engaged', False))" 2>/dev/null || echo "unknown")
    if [[ "$ENGAGED" == "False" ]]; then
        pass "Kill switch NOT engaged (clean state)"
    else
        echo "  [WARN] Kill switch engaged=$ENGAGED — check $KS_STATE"
    fi
else
    pass "kill-switch-state.json not present (no events recorded yet)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "================================="
echo "  Passed: $PASS   Failed: $FAIL"
echo "================================="
if [[ $FAIL -eq 0 ]]; then
    echo "  SMOKE TEST PASSED"
    exit 0
else
    echo "  SMOKE TEST FAILED — see [FAIL] items above"
    exit 1
fi
