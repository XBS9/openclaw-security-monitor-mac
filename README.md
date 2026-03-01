# OpenClaw Security Monitor

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/donate?business=6xxwhp%40gmail.com)

A free, open-source macOS menu-bar app that continuously watches your Mac for signs of compromise, privilege escalation, and persistence attacks — with an automatic kill switch that locks your OpenClaw gateway the moment a critical threat is detected.

---

## 📄 Documentation

**[User Guide & Technical Reference (PDF)](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.5.4/OpenClaw-Security-Monitor-Guide.pdf)**
— Full installation instructions, all 16 monitors explained, settings reference, limitations, FAQ, and troubleshooting.

---

## Download

| Architecture | Download |
|---|---|
| Apple Silicon (M1/M2/M3/M4) | **[OpenClawSecurityMonitor-1.6.0-arm64.dmg](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.6.0/OpenClawSecurityMonitor-1.6.0-arm64.dmg)** |
| Intel | **[OpenClawSecurityMonitor-1.6.0-x64.dmg](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.6.0/OpenClawSecurityMonitor-1.6.0-x64.dmg)** |

Requires macOS 11.0+. Open the DMG, drag `OpenClawSecurityMonitor` to Applications, then right-click → Open on first launch.

---

## What's New in v1.6.0

**Event-driven File Integrity Monitoring** — FIM now detects file changes in milliseconds via FileSystemWatcher (kqueue/FSEvents) instead of waiting up to 60 seconds. A 500ms debounce coalesces rapid editor saves.

**Persistent baselines** — All 5 baseline monitors now save to `~/.openclaw/baselines/` as JSON files with SHA-256 integrity sidecars. Changes made while the monitor was offline are detected on restart rather than silently absorbed.

**Baseline tamper protection** — Each baseline JSON is protected by a SHA-256 `.integrity` sidecar file. Tampering triggers an immediate alert and re-establishment. Files are `chmod 600` after every write.

**Alert-level email/webhook notifications** — Email and webhook alerts now fire on any monitor escalation (Ok → Warning or Alert), not just kill switch events. Per-monitor rate limiting prevents alert storms (configurable cooldown, default 5 min).

**App self-protection** — Registers as a LaunchAgent with `KeepAlive=true` so launchd automatically restarts the monitor if it's killed. SystemPosture warns if the plist is missing.

---

## What It Does

16 live security monitors running in your menu bar:

| Monitor | What It Catches | Kill Switch |
|---------|----------------|:-----------:|
| Gateway Health | OpenClaw gateway process down | — |
| File Integrity (FIM) | Hash change on SSH keys, auth tokens, config files, /etc/hosts | ✓ |
| Alert Log | New entries in security-alerts.log | — |
| Egress Rules | pf firewall anchor missing | — |
| Auth Patches | Patched auth files removed | — |
| Namespace Isolation | Unexpected processes in namespace | — |
| Config Permissions | openclaw.json / gateway.env not chmod 600 | — |
| Network Exposure | Unexpected open ports | — |
| Token Age | Gateway token older than 30 days | — |
| Launch Agents | New .plist in ~/Library/LaunchAgents | ✓ |
| Binary Integrity | Gateway binary hash changed | ✓ |
| TCC Permissions | App newly granted camera/mic/screen access | — |
| Sudo Activity | New sudo usage in system log | — |
| System Posture | SIP/Gatekeeper disabled · New admin account added | ✓ |
| Cron Jobs | New crontab / cron.d / periodic entry | — |
| System Extensions | New system extension bundle loaded | — |

### Kill Switch

When a critical threat is detected, the kill switch automatically locks the OpenClaw gateway via `launchctl` before an attacker can act. Every event is recorded in an on-disk audit trail. You disengage it manually from the Dashboard after reviewing the alert.

### Security Score

Dashboard shows a live 0–100 security score and a 24-reading sparkline (`▁▂▃▄▅▆▇█`) tracking your security posture over time.

### Email & Webhook Alerts

Optional SMTP email and webhook notifications on kill switch events and monitor escalations. Configurable per-monitor cooldown to prevent alert storms.

### Auto-Updates

The app checks for new releases automatically — once on launch and every 24 hours. When a newer version is found it downloads the DMG silently in the background, then shows a prompt:

> **Update Ready** — OpenClaw Monitor v1.6.0 has been downloaded.
> `[ Later ]` `[ Install Now ]`

---

## Quick Start

1. Download the DMG for your Mac (arm64 for Apple Silicon, x64 for Intel)
2. Open the DMG and drag `OpenClawSecurityMonitor` to `/Applications`
3. **Right-click → Open** on first launch (app is not notarized)
4. App runs as a menu-bar icon — no Dock icon
5. Future updates install automatically with one click

Full instructions in the [User Guide (PDF)](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.5.4/OpenClaw-Security-Monitor-Guide.pdf).

---

## Tech Stack

- .NET 8 + Avalonia 11.2.3 (C#)
- 65-test xUnit test suite — 0 failures
- All checks use built-in macOS tools (`csrutil`, `systemextensionsctl`, `dscl`, `launchctl`, etc.)
- Zero cloud dependency — no telemetry, no network calls except the optional update check

---

## License

MIT
