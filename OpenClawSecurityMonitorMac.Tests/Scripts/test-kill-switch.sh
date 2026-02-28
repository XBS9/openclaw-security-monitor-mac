#!/usr/bin/env bash
# test-kill-switch.sh — Manual integration test for the kill-switch end-to-end path.
#
# This test verifies that adding a new .plist to ~/Library/LaunchAgents
# causes the app to fire the kill switch within the poll interval.
#
# WARNING: This test adds and removes a fake .plist file. Run only on dev machines.
# The app must be running before you start this test.
#
# Usage:  ./test-kill-switch.sh
# Exit:   0 = kill switch fired as expected, 1 = did not fire within timeout

set -euo pipefail

LA_DIR="$HOME/Library/LaunchAgents"
TEST_PLIST="$LA_DIR/com.openclaw.smoke-test-fake.plist"
KS_STATE="$HOME/.openclaw/kill-switch-state.json"
POLL_TIMEOUT=120    # seconds to wait for kill switch to fire
POLL_INTERVAL=2

echo "=== OpenClaw — Kill Switch Integration Test ==="
echo ""
echo "PREREQUISITES:"
echo "  1. OpenClaw Security Monitor app is running"
echo "  2. LaunchAgent monitor is active (check Dashboard)"
echo "  3. This is a dev machine (we'll create/delete a fake plist)"
echo ""
read -r -p "Press Enter to continue, or Ctrl+C to abort..."
echo ""

# Capture baseline event count
BASELINE_EVENTS=0
if [[ -f "$KS_STATE" ]]; then
    BASELINE_EVENTS=$(python3 -c "import json; d=json.load(open('$KS_STATE')); print(len(d.get('events', [])))" 2>/dev/null || echo 0)
fi
echo "Baseline kill-switch events: $BASELINE_EVENTS"

# Write fake plist
cat > "$TEST_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openclaw.smoke-test-fake</string>
    <key>ProgramArguments</key>
    <array><string>/bin/echo</string><string>smoke-test</string></array>
</dict>
</plist>
PLIST

echo "Created: $TEST_PLIST"
echo "Waiting up to ${POLL_TIMEOUT}s for kill switch to fire..."
echo ""

ELAPSED=0
FIRED=false
while [[ $ELAPSED -lt $POLL_TIMEOUT ]]; do
    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))

    if [[ ! -f "$KS_STATE" ]]; then
        printf "  %3ds — no state file yet\n" $ELAPSED
        continue
    fi

    CURRENT_EVENTS=$(python3 -c "import json; d=json.load(open('$KS_STATE')); print(len(d.get('events', [])))" 2>/dev/null || echo 0)
    ENGAGED=$(python3 -c "import json; d=json.load(open('$KS_STATE')); print(d.get('engaged', False))" 2>/dev/null || echo False)

    printf "  %3ds — events=%s engaged=%s\n" $ELAPSED "$CURRENT_EVENTS" "$ENGAGED"

    if [[ "$CURRENT_EVENTS" -gt "$BASELINE_EVENTS" ]]; then
        FIRED=true
        break
    fi
done

# Clean up fake plist
rm -f "$TEST_PLIST"
echo ""
echo "Removed: $TEST_PLIST"
echo ""

if $FIRED; then
    echo "[PASS] Kill switch fired within ${ELAPSED}s."
    echo "       Check the Dashboard for the alert, then use 'Disengage Kill Switch' to reset."
    exit 0
else
    echo "[FAIL] Kill switch did NOT fire within ${POLL_TIMEOUT}s."
    echo "       Possible causes:"
    echo "         • App is not running"
    echo "         • LaunchAgent monitor is paused"
    echo "         • LaunchAgentCheckInterval is > ${POLL_TIMEOUT}s"
    exit 1
fi
