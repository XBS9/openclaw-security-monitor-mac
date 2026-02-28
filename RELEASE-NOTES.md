# OpenClaw Security Monitor — Release Notes
**Platform:** macOS | **Stack:** .NET 8 + Avalonia 11.2.3 | **Arch:** Self-contained single binary (osx-x64)
**Repo:** https://github.com/XBS9/openclaw-security-monitor-mac

---

## Build Summary — February 2026

This build adds **7 new monitors**, **2 alert channels**, a **kill switch bypass rules** system, a **score sparkline**, and several quality-of-life improvements on top of the original 9-monitor foundation.

Total monitors: **16**

---

## Monitors

| Monitor | What it watches | Trigger |
|---|---|---|
| Gateway Health | openclaw gateway process + mode | — |
| File Integrity | SHA-256 + permissions on critical config/key files | Kill switch |
| Alert Log | security-alerts.log for new entries | Kill switch |
| Egress Rules | pf firewall anchor + Tailscale Funnel exposure | Kill switch |
| Auth Patches | openclaw patched-file count vs expected | Warning |
| Namespace Isolation | openclaw namespace isolation config | Kill switch |
| Config Permissions | chmod on sensitive files | Warning |
| Network Exposure | gateway bind address + Tailscale Funnel | Warning |
| Token Age | openclaw gateway JWT age vs max-age threshold | Warning |
| **Launch Agents** | ~/Library/LaunchAgents for unknown .plist files | **Kill switch** |
| **Binary Integrity** | SHA-256 of the openclaw CLI binary | Alert |
| **TCC Permissions** | macOS TCC.db for new Screen/Accessibility/FDA grants | Alert |
| **Sudo Activity** | system log for unexpected sudo callers | Alert |
| **System Posture** | SIP · Gatekeeper · auto-login · App Firewall · admin accounts · remote access | Kill switch (new admin) / Alert / Warning |
| **Cron Jobs** | user crontab · /etc/cron.d · /etc/periodic | Warning |
| **System Extensions** | systemextensionsctl — loaded kernel extensions | Alert |

---

## Features Added This Build

### New Monitors

#### Launch Agent Scan Monitor
- Scans `~/Library/LaunchAgents/` for `.plist` files not present at startup
- In-memory baseline established on first check (30-second delay)
- **New plist → Kill Switch** (persistence vector — most common malware technique on macOS)
- Removed known plist → Warning (possible tampering with openclaw itself)
- Absorbed into baseline after firing to avoid repeated alerts for same file

#### Binary Integrity Monitor
- SHA-256 hashes the openclaw CLI binary at startup and on every interval
- Checks `/opt/homebrew/bin/openclaw`, `/usr/local/bin/openclaw`, and the configured npm global path
- Hash change → Alert (not kill switch — npm updates also change the binary)
- Updates baseline after change to avoid alert storm on legitimate update

#### TCC Permission Monitor
- Reads `~/Library/Application Support/com.apple.TCC/TCC.db` via sqlite3
- Tracks grants for: Screen Capture, Accessibility, Full Disk Access
- New grant → Alert; degrades gracefully to "Needs Full Disk Access" if sqlite3 blocked
- In-memory baseline, 60-second initial delay

#### Sudo Activity Monitor
- Reads macOS unified log: `log show --predicate 'senderImagePath ENDSWITH "sudo"'`
- Filters known-safe callers (bash, zsh, osascript, installer, etc.)
- Unexpected process calling sudo → Alert

#### System Posture Monitor
- **SIP** (`csrutil status`) — disabled → Alert
- **Gatekeeper** (`spctl --status`) — disabled → Alert
- **Auto-login** (`/Library/Preferences/com.apple.loginwindow`) — enabled → Warning
- **App Firewall** (`/Library/Preferences/com.apple.alf globalstate`) — off → Warning
- **Admin group audit** (`dscl . -read /Groups/admin`) — new admin account → **Kill Switch**
- **Remote access**: SSH (`systemsetup`), Screen Sharing (`com.apple.screensharing`), Remote Management (`com.apple.RemoteDesktopAgent`) — each on → Warning

#### Cron Job Monitor
- Sources: user crontab (`crontab -l`), `/etc/cron.d/`, `/etc/periodic/`
- In-memory baseline; new entry → Warning
- Not a kill-switch trigger (legitimate software also uses cron)

#### System Extension Monitor
- Runs `systemextensionsctl list` and parses bundle IDs
- New extension → Alert (system extensions have deep OS access — network interception, keylogging)
- Removed extension → Warning
- Not a kill-switch trigger (software updates add extensions legitimately)

---

### Alerting

#### Webhook Alerts
- HTTP POST JSON payload to any URL (n8n, Slack, custom endpoint) when kill switch fires
- Payload: `source`, `host`, `username`, `trigger`, `monitor`, `details`, `action`, `timestamp`
- Configurable URL in Settings → ALERTING
- **Test Webhook button** — fires a test event from Settings without needing a real alert
- Fire-and-forget; never blocks the kill-switch flow

#### Email Alerts *(new)*
- SMTP email via `System.Net.Mail` on kill switch fire
- Configurable: host, port, SSL/TLS, username, password, from address, recipient
- Credentials stored in `~/.openclaw/monitor-settings.json` (chmod 600, SHA-256 integrity sidecar)
- Fire-and-forget; 15-second send timeout

---

### Kill Switch Improvements

#### Configurable Bypass List
- `KillSwitchDisabledMonitors` — comma-separated list of monitor names in Settings → KILL SWITCH RULES
- Monitors on the bypass list still fire alerts, send webhook/email, and log the event — but do **not** lock the gateway
- Useful for monitors that generate alerts in normal operation (e.g. "Cron Jobs", "Binary Integrity")
- Example: `Cron Jobs, System Extensions, Binary Integrity`

#### Bypass-aware Kill Switch Action
- Events from bypassed monitors are logged with action `ALERT: Kill switch bypassed for monitor`
- Events from normal monitors continue to use `KILL_SWITCH: Gateway locked`

---

### File Integrity Monitor — New Files

| File | Critical | Notes |
|---|---|---|
| `~/.ssh/authorized_keys` | ✅ Yes | Modification allows unauthorized SSH login |
| `~/.ssh/id_rsa` | No | chmod 600 checked; infostealer target |
| `~/.ssh/id_ed25519` | No | chmod 600 checked; infostealer target |
| `~/.ssh/id_ecdsa` | No | chmod 600 checked; infostealer target |
| `/etc/hosts` | No | DNS hijacking target |

---

### Dashboard

#### Active Connections Panel
- Shows live TCP connections to node/openclaw processes (`lsof`)
- Updates every 30 seconds
- Panel only visible when connections exist

#### Score Sparkline
- Unicode block character sparkline (`▁▂▃▄▅▆▇█`) in the dashboard header
- Tracks the last 24 security score readings
- Appears below the score number once enough data is collected
- Gives instant visual history of score stability

#### Alert Export
- "Export Alerts" button (dashboard + tray menu)
- Saves all kill switch events to a timestamped JSON file on the Desktop
- Format: `openclaw-alerts-YYYY-MM-DD-HHmmss.json`

#### Sync Token Button
- Forces a token sync with the openclaw gateway on demand
- Shows ✓/✗ feedback, auto-clears after 5 seconds

---

### Settings

#### New Sections
- **ALERTING** — webhook URL, enable/disable, Test Webhook button
- **EMAIL ALERTS** — full SMTP configuration
- **KILL SWITCH RULES** — bypass monitor list
- **NOTIFICATIONS** — daily digest enable/disable + hour

#### New Interval Controls
- Launch Agents, Binary Integrity, Sudo Activity, System Posture, Cron Jobs, System Extensions
- All configurable independently in Settings → MONITOR INTERVALS

---

### Security Hardening

#### Sudo-Gated Quit
- Quit requires macOS administrator authentication (native auth dialog via osascript)
- Prevents someone with physical access from bypassing monitoring by clicking Quit
- Cancel = quit denied; notification shown

#### Stale Kill Switch Reconciliation
- On startup, if kill switch state file says `engaged=true` but the gateway is actually running unlocked, a native dialog prompts the user to choose:
  - **Re-lock Gateway** — re-applies the hardened plist
  - **Acknowledge & Continue** — clears the engaged state, resumes normal monitoring

---

### Auto-Update
- Checks GitHub Releases API on startup (10-second delay)
- Also checks npm registry for openclaw CLI updates
- Tray menu item appears when monitor app update is available — click opens GitHub Releases page in browser
- macOS notification shown for both monitor app and npm CLI updates

---

### Daily Digest Notification
- Optional daily macOS notification at a configurable hour
- Summary: monitors OK/warn/alert counts + last security event

---

## Settings Reference

| Setting | Default | Description |
|---|---|---|
| `gatewayPort` | 18789 | Gateway port |
| `launchAgentCheckInterval` | 300s | Launch Agents monitor |
| `binaryIntegrityCheckInterval` | 300s | Binary hash monitor |
| `sudoLogCheckInterval` | 60s | Sudo log monitor |
| `systemPostureCheckInterval` | 300s | System posture monitor |
| `cronJobCheckInterval` | 300s | Cron job monitor |
| `systemExtensionCheckInterval` | 600s | System extension monitor |
| `webhookAlertsEnabled` | false | Enable webhook alerting |
| `webhookAlertUrl` | "" | Webhook destination URL |
| `emailAlertsEnabled` | false | Enable SMTP email alerting |
| `smtpHost` | "" | SMTP server hostname |
| `smtpPort` | 587 | SMTP port |
| `smtpSsl` | true | Enable SSL/TLS |
| `smtpUser` | "" | SMTP username |
| `smtpPassword` | "" | SMTP password (stored chmod 600) |
| `smtpFrom` | "" | From address |
| `alertEmailTo` | "" | Alert recipient address |
| `killSwitchDisabledMonitors` | [] | Monitors that bypass gateway lock |
| `dailyDigestEnabled` | true | Daily summary notification |
| `dailyDigestHour` | 9 | Hour to send digest (0–23) |
| `tokenMaxAgeDays` | 30 | Max gateway token age before warning |
| `startMinimized` | true | Start in menu bar, no window |
| `showNotificationOnKillSwitch` | true | macOS notification on kill switch |
| `autoReapplyEgress` | true | Re-apply pf rules when anchor missing |

---

## File Layout

```
~/.openclaw/
  monitor-settings.json        # All settings (chmod 600)
  monitor-settings.integrity   # SHA-256 sidecar for tamper detection
  kill-switch-state.json       # Persisted kill switch state + event log
  security-tray.log            # Append-only kill switch event log
  security-alerts.log          # openclaw gateway alert log (watched)
```

---

## Commits This Build

| Hash | Description |
|---|---|
| `abda53a` | feat: Launch Agents, Binary Integrity, TCC, Sudo, Webhook, connections, export, digest |
| `7afea27` | feat: Test Webhook button in Settings |
| `3bbb071` | feat: System Posture, Cron Jobs, System Extensions, Email Alerts, kill switch bypass rules, score sparkline |
