# OpenClaw Security Monitor — Test Plan

## Overview

Testing is split into three layers:

| Layer | Tool | When to run |
|-------|------|-------------|
| Unit tests | xUnit (.NET) | Every code change (automated) |
| Smoke tests | Bash | After every new build / deploy |
| Integration tests | Bash (interactive) | Before a major release |

---

## 1. Unit Tests

**Location:** `OpenClawSecurityMonitorMac.Tests/`
**Run:** `dotnet test OpenClawSecurityMonitorMac.Tests/OpenClawSecurityMonitorMac.Tests.csproj -c Release`
**Or:** `./Scripts/run-unit-tests.sh`

### Design

All unit tests run entirely **in-process** with no real processes, files, or network calls. Two fakes are used:

- **`MockCommandService`** — returns pre-queued `(exitCode, stdout, stderr)` tuples; records every command string for inspection.
- **`MockGatewayService`** — implements `IGatewayService`; records `LockCalled`, `UnlockCalled`, `LockCallCount`; has configurable `LockResult`.

All monitors accept a very short `CheckInterval = 1s` in tests so the startup delay is also 1s (via `Math.Min(hardcoded, interval)`). Tests use `WaitForStateAsync` to poll the `MonitorHub` with a 5–10 second `CancellationToken` timeout rather than sleeping blindly.

Kill-switch state is isolated per test by setting `TrayLogPath` to a unique temp directory, which also redirects the state JSON (`kill-switch-state.json` is co-located with the log file).

### Test Files

#### `TraySettingsTests.cs` — 13 tests

| Test | Verifies |
|------|----------|
| `Defaults_AreReasonable` | All critical defaults present (port, intervals, paths) |
| `Validate_ClampsIntervals` | Negative / out-of-range intervals are clamped |
| `Validate_ClampsGatewayPort` | Port clamped to [1024, 65535] |
| `Validate_ClampsSmtpPort` | SMTP port clamped to [1, 65535] |
| `Validate_RejectsBadPath` | Shell-injection chars in paths → reset to default |
| `Validate_RejectsDotDot` | `..` in path → reset to default |
| `Validate_GoodPath_Kept` | Valid path passes through unchanged |
| `Validate_BadGatewayLabel` | Label with spaces → reset |
| `Validate_GoodLabel_Kept` | Valid label passes through |
| `MonitoredFiles_DefaultsIncludeEtcHosts` | `/etc/hosts` in default FIM list |
| `MonitoredFiles_DefaultsIncludeSSHKeys` | SSH keys in default FIM list |
| `KillSwitchDisabledMonitors_DefaultsEmpty` | Bypass list starts empty |
| `EmailAlertsDisabled_ByDefault` | Email alerts off by default |

#### `MonitorHubTests.cs` — 7 tests

| Test | Verifies |
|------|----------|
| `Constructor_RegistersAll16Monitors` | All 16 monitors registered |
| `Constructor_AllMonitors_StartInStartingState` | Initial state = Starting |
| `Report_UpdatesStateAndDetail` | State + detail updated correctly |
| `Report_UpdatedEventFires` | `Updated` event fires on Report |
| `Report_UnknownMonitorName_DoesNotThrow` | Unknown names are silently ignored |
| `Report_MultipleReports_LastValueWins` | Last Report wins |
| `GetAll_ReturnsSnapshot_NotLiveReference` | Snapshot is a deep copy; post-snapshot changes not visible |
| `AllMonitorNameConstants_AreRegistered` | Every public constant is in the hub |

#### `KillSwitchTests.cs` — 18 tests

| Test | Verifies |
|------|----------|
| `FireAsync_Normal_EngagesKillSwitch` | `IsEngaged` = true after fire |
| `FireAsync_Normal_LocksGateway` | `LockAsync` called on gateway |
| `FireAsync_Normal_RecordsEvent` | Event added to `Events` list |
| `FireAsync_Normal_EventActionIsKillSwitch` | Action contains "KILL_SWITCH" |
| `FireAsync_Normal_IncrementsUnreviewedCount` | `UnreviewedCount` increments per fire |
| `FireAsync_LockFails_RetriesOnce` | 2 lock attempts on failure |
| `FireAsync_TriggeredEvent_Fires` | `Triggered` event fires with correct monitor |
| `FireAsync_BypassedMonitor_DoesNotEngage` | `IsEngaged` stays false |
| `FireAsync_BypassedMonitor_DoesNotLockGateway` | `LockAsync` NOT called |
| `FireAsync_BypassedMonitor_StillRecordsEvent` | Event is still recorded |
| `FireAsync_BypassedMonitor_EventActionContainsBypassed` | Action contains "bypassed" |
| `FireAsync_BypassedMonitor_DoesNotIncrementUnreviewed` | `UnreviewedCount` stays 0 |
| `FireAsync_BypassCheck_IsCaseInsensitive` | "cron jobs" matches "Cron Jobs" |
| `FireAsync_NonBypassed_StillLocksWhenOtherBypassesExist` | Other bypasses don't affect non-bypassed monitor |
| `Disengage_SetsEngagedFalse` | `Disengage()` clears engaged |
| `ClearAlerts_ResetsUnreviewedCount` | `UnreviewedCount` → 0 |
| `ClearAlerts_DoesNotRemoveEvents` | Audit events are never cleared |

#### `MonitorBehaviorTests.cs` — 15 tests

Tests each monitor's command parsing and state-reporting logic by driving `Start()` with a 1s interval and waiting on `MonitorHub` state changes.

**LaunchAgentScanMonitor (3 tests)**

| Test | Verifies |
|------|----------|
| `LaunchAgent_FirstCheck_SetsBaseline_ReportsOk` | First scan = Ok + "Baseline set" |
| `LaunchAgent_NewPlist_TriggersKillSwitch` | New plist → Alert + gateway locked (kill switch fires before hub reports Alert) |
| `LaunchAgent_RemovedPlist_ReportsWarning` | Missing plist → Warning, no gateway lock |

**SystemExtensionMonitor (3 tests)**

| Test | Verifies |
|------|----------|
| `SystemExtension_FirstCheck_SetsBaseline` | First scan = Ok + "Baseline set" |
| `SystemExtension_NewExtension_ReportsAlert` | New bundle ID → Alert, detail contains ID |
| `SystemExtension_ParsesOutputCorrectly_MultipleBundleIds` | 2 extensions parsed; non-bundle lines ignored; count in detail |

**CronJobMonitor (3 tests)**

| Test | Verifies |
|------|----------|
| `CronJob_NoEntries_ReportsOk` | 0 entries on first scan → "No cron jobs" |
| `CronJob_NewEntryAfterBaseline_ReportsWarning` | New cron entry → Warning + "New" in detail |
| `CronJob_CommentLines_NotCounted` | Comment lines are filtered; 0 real entries → "No cron jobs" |

**SystemPostureMonitor (6 tests)**

| Test | Verifies |
|------|----------|
| `SystemPosture_SipEnabled_GkEnabled_ReportsOk` | All green → Ok |
| `SystemPosture_SipDisabled_ReportsAlert` | SIP off → Alert + "SIP disabled" |
| `SystemPosture_GatekeeperDisabled_ReportsAlert` | GK off → Alert + "Gatekeeper disabled" |
| `SystemPosture_AutoLoginEnabled_ReportsWarning` | Auto-login user set → Warning + "Auto-login" |
| `SystemPosture_AppFirewallOff_ReportsWarning` | ALF state=0 → Warning + "App Firewall off" |
| `SystemPosture_RemoteAccessOn_ReportsWarning` | SSH on → Warning + "SSH on" |

---

## 2. Smoke Tests

**Location:** `Scripts/smoke-test.sh`
**Run after:** Every new build deployed to OneDrive / Desktop

```
cd OpenClawSecurityMonitorMac.Tests/Scripts
./smoke-test.sh
```

Checks (no app launch required, reads filesystem only):

1. Binary exists at `bin/Release/net8.0/osx-x64/OpenClawSecurityMonitorMac`
2. `~/.openclaw/` directory exists
3. `monitor-settings.json` present, valid JSON, permissions 600
4. Required macOS commands available (`csrutil`, `spctl`, `systemextensionsctl`, etc.)
5. SIP / Gatekeeper status (informational — alerts if disabled but doesn't fail)
6. `~/Library/LaunchAgents` exists
7. OpenClaw gateway plist present
8. Log file exists / is writable
9. Kill switch state (not engaged)

---

## 3. Integration Tests — Kill Switch End-to-End

**Location:** `Scripts/test-kill-switch.sh`
**Run:** Before major releases. Requires app running on a dev machine.

```
cd OpenClawSecurityMonitorMac.Tests/Scripts
./test-kill-switch.sh
```

What it does:

1. Records baseline kill-switch event count from `~/.openclaw/kill-switch-state.json`
2. Drops a fake `.plist` into `~/Library/LaunchAgents/`
3. Polls for up to 120s until the kill switch fires (new event recorded)
4. Removes the fake plist
5. Pass / fail based on whether the kill switch fired

After the test, **manually** verify in the app Dashboard that:
- Launch Agents row shows Alert
- Tray icon changed to red
- "Disengage Kill Switch" button works

---

## 4. Manual Verification Checklist

Run through this checklist before shipping a release.

### Dashboard
- [ ] All 16 monitor rows visible
- [ ] Security score updates every poll cycle
- [ ] Score sparkline (`▁▂▃▄▅▆▇█`) updates as score changes
- [ ] Each row shows correct state color (green/yellow/red)
- [ ] "Pause All Monitors" button pauses polling; "Resume" restarts

### Settings
- [ ] All 16 monitor intervals displayed (not just first 13)
- [ ] Email SMTP fields save/load correctly
- [ ] Kill Switch Bypass text field saves comma-separated list
- [ ] "Reset to Defaults" clears custom intervals and email settings
- [ ] Settings file written with permissions 600 after Save

### Kill Switch Behavior
- [ ] Adding a new plist to `~/Library/LaunchAgents` fires kill switch
- [ ] Adding a new admin user fires kill switch (test in VM only)
- [ ] Monitors on bypass list raise Alert but do NOT lock gateway
- [ ] "Disengage Kill Switch" restores normal operation
- [ ] Kill switch state survives app restart (persisted to JSON)

### Email Alerts
- [ ] With valid SMTP config, email sent on kill switch fire
- [ ] `EmailAlertsEnabled = false` → no email sent
- [ ] Invalid SMTP host → error swallowed, no crash

### Update Checker
- [ ] "Check for Updates" tray item opens GitHub releases page in browser
- [ ] If GitHub is unreachable, no crash

### macOS Integration
- [ ] App appears in menu bar (not Dock)
- [ ] Tray icon right-click menu shows all items
- [ ] App does NOT appear in App Switcher (Cmd+Tab)
- [ ] Quit prompts for sudo if kill switch is engaged

---

## 5. Known Limitations

| Limitation | Impact |
|-----------|--------|
| Binary integrity (SHA-256) baseline is in-memory | Reset on restart; no persistent tamper detection between sessions |
| Admin account baseline is in-memory | New admin added before first check won't be detected |
| CronJob / Extension baselines are in-memory | Same |
| Email SMTP password stored in plain JSON (chmod 600) | Not encrypted at rest on macOS (no DPAPI equivalent) |
| Kill switch retry delay is 2s (hardcoded) | Adds 2s to kill switch fire time on failure |
| `systemextensionsctl` requires SIP disabled to list extensions in some macOS versions | May report 0 extensions on locked-down systems |

---

## 6. Running the Full Test Suite

```bash
# 1. Unit tests (automated, no app required)
dotnet test OpenClawSecurityMonitorMac.Tests/OpenClawSecurityMonitorMac.Tests.csproj -c Release

# 2. Smoke test (after build)
./OpenClawSecurityMonitorMac.Tests/Scripts/smoke-test.sh

# 3. Integration test (with app running)
./OpenClawSecurityMonitorMac.Tests/Scripts/test-kill-switch.sh

# 4. Manual checklist (see Section 4 above)
```

Expected results after a clean build:
- Unit tests: **53 passed, 0 failed**
- Smoke test: all PASS (warnings for SSH/SIP if they are on/off on your machine)
- Integration test: PASS within ~30s (default LaunchAgent check interval is 5 min in production — reduce to 10s in settings for testing)
