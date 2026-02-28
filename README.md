# OpenClaw Security Monitor

A free, open-source macOS menu-bar app that continuously watches your Mac for signs of compromise, privilege escalation, and persistence attacks — with an automatic kill switch that locks your OpenClaw gateway the moment a critical threat is detected.

---

## 📄 Documentation

**[User Guide & Technical Reference (PDF)](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.5.2/OpenClaw-Security-Monitor-Guide.pdf)**
— Full installation instructions, all 16 monitors explained, settings reference, limitations, FAQ, and troubleshooting.

---

## Download

**[→ Download OpenClawMonitor-1.5.2.zip](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.5.2/OpenClawMonitor-1.5.2.zip)**

Requires macOS 12+. See the [User Guide](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.5.2/OpenClaw-Security-Monitor-Guide.pdf) for installation steps.

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

### Email Alerts

Optional SMTP email notification on every kill switch event — works with Gmail, Outlook, or any SMTP server.

---

## Quick Start

1. Download and unzip `OpenClawMonitor-1.5.2.zip`
2. Move `OpenClawMonitor.app` to `/Applications`
3. **Right-click → Open** on first launch (app is not notarized)
4. App runs as a menu-bar icon — no Dock icon

Full instructions in the [User Guide (PDF)](https://github.com/XBS9/openclaw-security-monitor-mac/releases/download/v1.5.2/OpenClaw-Security-Monitor-Guide.pdf).

---

## Tech Stack

- .NET 8 + Avalonia 11.2.3 (C#)
- 53-test xUnit test suite — 0 failures
- All checks use built-in macOS tools (`csrutil`, `systemextensionsctl`, `dscl`, `launchctl`, etc.)
- Zero cloud dependency — no telemetry, no network calls except the optional update check

---

## License

MIT
