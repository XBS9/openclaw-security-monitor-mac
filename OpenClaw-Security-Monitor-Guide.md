# OpenClaw Security Monitor
## User Guide & Technical Reference — v1.5.2

---

## Table of Contents

1. [What Is OpenClaw Security Monitor?](#what-is-it)
2. [Installation](#installation)
3. [First Launch & Setup](#first-launch)
4. [The Dashboard](#dashboard)
5. [All 16 Monitors — Detailed Reference](#monitors)
6. [The Kill Switch](#kill-switch)
7. [Email Alerts](#email-alerts)
8. [Settings Reference](#settings)
9. [How the Security Score Works](#score)
10. [Limitations & What It Cannot Protect Against](#limitations)
11. [Frequently Asked Questions](#faq)
12. [Troubleshooting](#troubleshooting)
13. [Technical Architecture](#architecture)

---

## 1. What Is OpenClaw Security Monitor? {#what-is-it}

OpenClaw Security Monitor is a **free, open-source macOS menu-bar application** that continuously watches your Mac for signs of compromise, privilege escalation, and persistence attacks.

It runs silently in your menu bar (no Dock icon) and performs 16 independent security checks every few minutes. When something suspicious is detected it alerts you immediately — and for the most critical threats, it can automatically lock your OpenClaw gateway before an attacker has time to act.

**Designed for:** Developers, security researchers, and power users who run the OpenClaw AI gateway on their Mac and want real-time protection against the most common macOS attack vectors.

**Not designed for:** Enterprise endpoint detection, network-level threat hunting, or replacing a full EDR product.

### Key capabilities at a glance

- 16 live security monitors covering persistence, privilege escalation, system integrity, and network exposure
- **Kill switch** — automatically locks the OpenClaw gateway when a critical threat is detected
- **Email alerts** via SMTP on every kill switch event
- **Security score** (0–100) with 24-reading sparkline history
- **File Integrity Monitoring (FIM)** on 17 critical files including SSH keys, `/etc/hosts`, and auth tokens
- **Zero cloud dependency** — all checks run locally using built-in macOS tools
- Fully configurable check intervals and bypass rules
- 53-test unit test suite; open source on GitHub

---

## 2. Installation {#installation}

### Requirements

- macOS 12 Monterey or later (macOS 13 Ventura+ recommended)
- Apple Silicon or Intel Mac
- ~150 MB disk space
- The OpenClaw gateway (for kill-switch functionality — all other monitors work without it)

### Steps

1. **Download** `OpenClawMonitor-1.5.2.zip` from the GitHub releases page:
   `https://github.com/XBS9/openclaw-security-monitor-mac/releases`

2. **Unzip** the downloaded file — you'll get `OpenClawMonitor.app`

3. **Move** `OpenClawMonitor.app` to your `/Applications` folder

4. **First launch** — because the app is not notarized by Apple, macOS will block it by default:
   - Right-click (or Control-click) `OpenClawMonitor.app`
   - Select **Open**
   - Click **Open** in the security dialog

   After the first launch you can open it normally from Spotlight or Launchpad.

5. The app will appear as an icon in your **menu bar** (top-right area of your screen). There is no Dock icon by design.

### Uninstalling

1. Quit the app (right-click tray icon → Quit)
2. Delete `/Applications/OpenClawMonitor.app`
3. Optionally delete `~/.openclaw/` to remove all settings and state

---

## 3. First Launch & Setup {#first-launch}

On first launch the app will:

1. Create `~/.openclaw/` and write default settings to `~/.openclaw/monitor-settings.json`
2. Apply `chmod 600` to the settings file (readable only by you)
3. Start all 16 monitors with staggered initial delays (1–30 seconds) to avoid a spike of activity at startup
4. Establish an **in-memory baseline** for monitors that do change-detection (LaunchAgents, Admin accounts, Cron jobs, System Extensions)

**The first few minutes** after launch you will see all monitors in "Starting…" state. This is normal. They transition to OK, Warning, or Alert as each completes its first check.

### Recommended first steps

1. Open the Dashboard (click tray icon → Open Dashboard)
2. Wait 2–3 minutes for all monitors to complete their first check
3. Review any warnings — many are informational (e.g., "SSH on" if you use SSH)
4. Go to Settings and configure email alerts if you want notifications when you're away from your Mac
5. Add any monitors you don't want triggering the kill switch to **Settings → Kill Switch Rules → Bypass list**

---

## 4. The Dashboard {#dashboard}

Open the Dashboard by clicking the tray icon and selecting **Open Dashboard**.

### Security Score

The large number at the top (0–100) is your current security score:

| Score | Meaning |
|-------|---------|
| 90–100 | All monitors OK |
| 70–89 | One or more Warnings |
| 50–69 | Multiple Warnings |
| 1–49 | One or more Alerts |
| 0 | Kill switch engaged |

The **sparkline** (`▁▂▃▄▅▆▇█`) next to the score shows the last 24 readings, giving you a visual history of how your security posture has changed over time.

### Monitor rows

Each of the 16 monitors appears as a row showing:
- **Name** — the monitor name
- **State** — OK (green), Warning (yellow), Alert (red), or Starting (grey)
- **Detail** — a short human-readable description of the current status
- **Last checked** — timestamp of the most recent check

### Kill Switch panel

When the kill switch is engaged, a red banner appears at the top of the Dashboard. You can:
- **View the event** that triggered it
- **Disengage** the kill switch (re-enables the gateway)
- **Clear unreviewed alerts** (resets the unreviewed count without disengaging)

### Pause / Resume

The **Pause All Monitors** button stops all background polling. Use this when you're doing system maintenance that would otherwise trigger false alerts (e.g., installing software that adds LaunchAgents). Click **Resume** when done.

---

## 5. All 16 Monitors — Detailed Reference {#monitors}

### 5.1 Gateway Health

**What it checks:** Pings the OpenClaw gateway HTTP health endpoint every `StatusPollInterval` seconds (default: 15s).

**States:**
- OK — gateway is running and responding
- Warning — gateway is unreachable (may be starting up)
- Alert — gateway has been down for multiple consecutive checks

**Kill switch:** No — gateway being down is the *result* of a kill switch, not a cause.

**Notes:** This is the most frequently checked monitor. If you don't use the OpenClaw gateway, this will always show Warning, which is expected.

---

### 5.2 File Integrity Monitoring (FIM)

**What it checks:** SHA-256 hash of 17 critical files. Any hash change from the established baseline triggers an alert.

**Default monitored files:**
| File | Why it matters |
|------|----------------|
| `~/.openclaw/workspace/SOUL.md` | Core AI identity file — tampering changes AI behaviour |
| `~/.openclaw/workspace/IDENTITY.md` | AI identity |
| `~/.openclaw/workspace/AGENTS.md` | Agent definitions |
| `~/.openclaw/workspace/TOOLS.md` | Tool definitions |
| `~/.openclaw/openclaw.json` | Gateway config — tampering redirects traffic |
| `~/.openclaw/gateway.env` | Gateway secrets |
| `~/Library/LaunchAgents/ai.openclaw.gateway.hardened.plist` | Service definition — tampering enables privilege escalation |
| `~/Library/LaunchAgents/ai.openclaw.gateway.unlocked.plist` | Unlocked service plist |
| `~/.zshrc` | Shell startup — common persistence vector |
| `~/.openclaw/identity/device.json` | Device identity |
| `~/.openclaw/identity/device-auth.json` | Device auth credentials |
| `~/.openclaw/agents/main/agent/auth-profiles.json` | OAuth profiles |
| `~/.openclaw/agents/main/agent/auth.json` | JWT credentials (high-value target) |
| `~/.ssh/authorized_keys` | SSH authorized keys — adding a key grants remote access |
| `~/.ssh/id_rsa` | SSH private key |
| `~/.ssh/id_ed25519` | SSH private key |
| `/etc/hosts` | DNS resolution — hijacking redirects network traffic |

**States:**
- OK — all files match baseline hashes
- Warning — a non-critical file changed (e.g., `.zshrc` after you edited it)
- Alert — a critical file changed

**Kill switch:** Yes — changes to critical files (marked `Critical = true`) trigger the kill switch.

**Notes:** Baseline is established on first check after launch. You can add your own files in Settings → Monitored Files.

Also checks **file permissions** on sensitive files. `openclaw.json`, `gateway.env`, SSH keys, and auth files should be `600` (owner read/write only). If they're world-readable, a Warning is issued.

---

### 5.3 Alert Log

**What it checks:** Watches `~/.openclaw/security-alerts.log` for new lines every `AlertLogInterval` seconds (default: 30s).

**States:**
- OK — no new alerts since last check
- Warning — new low-severity entries
- Alert — new high-severity entries

**Kill switch:** No.

**Notes:** Other tools in the OpenClaw ecosystem write to this log. This monitor ensures you see those alerts in the Dashboard even if you're not looking at other logs.

---

### 5.4 Egress Rules

**What it checks:** Verifies the macOS packet filter (`pf`) has the OpenClaw egress anchor loaded. Checks every `EgressCheckInterval` seconds (default: 300s).

**States:**
- OK — pf anchor is loaded, rules are intact
- Alert — anchor is missing (outbound traffic is unrestricted)

**Kill switch:** No — egress rules being missing doesn't indicate compromise by itself.

**Auto-repair:** If `AutoReapplyEgress = true` (default), the monitor will attempt to re-apply the egress script automatically.

---

### 5.5 Auth Patches

**What it checks:** Counts the number of patched authentication files in the OpenClaw installation. Expects a minimum of `ExpectedPatchedFileCount` (default: 7) patched files.

**States:**
- OK — expected number of patches present
- Alert — fewer patches than expected (files may have been replaced or reverted)

**Kill switch:** No.

---

### 5.6 Namespace Isolation

**What it checks:** Verifies that only expected processes are running in the OpenClaw namespace. Checks every `NamespaceCheckInterval` seconds (default: 300s).

**States:**
- OK — only expected processes present
- Alert — unexpected process detected in namespace

**Kill switch:** No.

---

### 5.7 Config Permissions

**What it checks:** Verifies that `openclaw.json` and `gateway.env` have `600` permissions (readable only by owner). Checks every `PermissionCheckInterval` seconds (default: 300s).

**States:**
- OK — permissions correct
- Warning — files are too permissive (readable by group or world)

**Kill switch:** No — loose permissions are a misconfiguration, not an active attack.

---

### 5.8 Network Exposure

**What it checks:** Scans for unexpected open network ports using `lsof`. Compares against expected ports (gateway port + known macOS services). Checks every `ExposureCheckInterval` seconds (default: 300s).

**States:**
- OK — only expected ports listening
- Warning — unexpected port open (could be legitimate software)
- Alert — high-risk port open (e.g., port 22 when SSH is supposed to be off)

**Kill switch:** No.

---

### 5.9 Token Age

**What it checks:** Reads the creation date of the gateway auth token and warns if it's older than `TokenMaxAgeDays` (default: 30 days). Checks every `TokenAgeCheckInterval` seconds (default: 6 hours).

**States:**
- OK — token is fresh
- Warning — token is older than threshold

**Kill switch:** No.

**Notes:** Old tokens are a risk because a compromised token that was never rotated gives persistent access. Rotate your gateway token regularly.

---

### 5.10 Launch Agents

**What it checks:** Lists all `.plist` files in `~/Library/LaunchAgents/` every `LaunchAgentCheckInterval` seconds (default: 300s). Compares against an in-memory baseline set at first check.

**States:**
- OK — no changes since baseline
- Warning — a known plist was removed (possible tampering)
- Alert — **new plist detected**

**Kill switch:** Yes — a new LaunchAgent plist is one of the most reliable indicators of malware persistence. The kill switch fires immediately.

**Notes:** The baseline resets when the app restarts. Legitimate software that adds LaunchAgents (e.g., during installation) will trigger this. You can pause monitors during installations and resume afterward, or disengage the kill switch if it fires for a known-good installer.

---

### 5.11 Binary Integrity

**What it checks:** SHA-256 hash of the OpenClaw gateway binary. Any change triggers a kill switch. Checks every `BinaryIntegrityCheckInterval` seconds (default: 300s).

**States:**
- OK — binary matches baseline hash
- Alert — **binary hash changed**

**Kill switch:** Yes — a modified gateway binary could be a trojanized replacement. The kill switch fires immediately.

**Notes:** Baseline is set on first check after launch. If you intentionally update the gateway, restart the app afterward to re-establish the baseline.

---

### 5.12 TCC Permissions

**What it checks:** Reads the macOS Transparency, Consent, and Control (TCC) database to detect apps that have been newly granted access to camera, microphone, screen recording, contacts, calendar, or location. Checks every check interval.

**States:**
- OK — no new TCC grants since baseline
- Alert — new app granted sensitive permission

**Kill switch:** No — TCC grants require user interaction, so this is more of a "did you mean to do that?" alert.

**Notes:** Requires the app to have TCC database read access. On some macOS versions this may prompt for Full Disk Access permission.

---

### 5.13 Sudo Activity

**What it checks:** Monitors the system log for new `sudo` usage via `log show`. Checks every `SudoLogCheckInterval` seconds (default: 60s).

**States:**
- OK — no new sudo activity
- Warning — sudo was used since last check

**Kill switch:** No — sudo usage is common for legitimate admin work.

**Notes:** This is an informational monitor. Frequent sudo usage during normal work will generate regular warnings.

---

### 5.14 System Posture

**What it checks:** Comprehensive system security configuration check every `SystemPostureCheckInterval` seconds (default: 300s). Six sub-checks:

| Sub-check | Command | Alert level |
|-----------|---------|-------------|
| System Integrity Protection (SIP) | `csrutil status` | Alert if disabled |
| Gatekeeper | `spctl --status` | Alert if disabled |
| Auto-login | `defaults read com.apple.loginwindow autoLoginUser` | Warning if set |
| Application Firewall | `defaults read com.apple.alf globalstate` | Warning if off (state=0) |
| Admin group membership | `dscl . -read /Groups/admin` | **Kill Switch** if new admin added |
| Remote access (SSH, Screen Sharing, Remote Management) | `systemsetup`, `launchctl list` | Warning if any enabled |

**Kill switch:** Yes — only for new admin account detection. SIP/Gatekeeper being disabled raises an Alert but does not trigger the kill switch (as it may reflect a deliberate developer configuration).

**Notes:** The admin baseline is in-memory. If someone adds themselves to the admin group between app launches, it will not be detected until the second check after the next launch.

---

### 5.15 Cron Jobs

**What it checks:** Monitors three cron sources for new entries every `CronJobCheckInterval` seconds (default: 300s):
- User crontab (`crontab -l`)
- System cron directory (`/etc/cron.d/`)
- Periodic tasks (`/etc/periodic/`)

**States:**
- OK — no changes since baseline
- Warning — new cron entry detected

**Kill switch:** No — cron is used by legitimate software. The warning gives you visibility to investigate.

**Notes:** Comment lines (`#`) are ignored. The baseline resets on app restart.

---

### 5.16 System Extensions

**What it checks:** Lists loaded system extensions via `systemextensionsctl list` every `SystemExtensionCheckInterval` seconds (default: 600s). System extensions have deep OS access — they can intercept network traffic, keystrokes, and file operations.

**States:**
- OK — no changes since baseline
- Warning — a known extension was removed
- Alert — **new extension detected**

**Kill switch:** No — software updates (including macOS updates) legitimately add extensions. The Alert gives you time to review.

**Notes:** Requires SIP to be enabled on some macOS versions to list extensions correctly.

---

## 6. The Kill Switch {#kill-switch}

The kill switch is the most powerful feature of OpenClaw Security Monitor. When triggered, it:

1. **Records a security event** with timestamp, monitor name, trigger, and details
2. **Locks the OpenClaw gateway** via `launchctl unload` (prevents restart)
3. **Notifies you** via the tray icon (turns red), Dashboard banner, and optionally email
4. **Persists state** to `~/.openclaw/kill-switch-state.json` — survives app restart

### What triggers the kill switch

| Monitor | Trigger |
|---------|---------|
| File Integrity | Critical file hash changed |
| Launch Agents | New .plist in ~/Library/LaunchAgents |
| Binary Integrity | Gateway binary hash changed |
| System Posture | New user added to admin group |

### Kill switch bypass list

Some monitors can trigger the kill switch but you may not want them to for your workflow. Add monitor names to **Settings → Kill Switch Rules → Bypass monitors** (comma-separated). Bypassed monitors still record the event and show Alert state — they just don't lock the gateway.

Example bypass list for a developer machine:
```
Binary Integrity, Launch Agents
```

### Disengaging the kill switch

1. Open the Dashboard
2. Review the event that triggered it
3. Click **Disengage Kill Switch**
4. The gateway will be re-enabled and monitoring resumes normally

### Retry behaviour

If the gateway lock fails (e.g., `launchctl` returns an error), the kill switch automatically retries once after a 2-second delay. If it still fails, a `LOCK_FAILED` event is recorded and you'll need to manually lock the gateway.

---

## 7. Email Alerts {#email-alerts}

Configure in **Settings → Email Alerts**.

| Setting | Description |
|---------|-------------|
| Enable Email Alerts | Master switch |
| SMTP Host | Your mail server (e.g., `smtp.gmail.com`) |
| SMTP Port | Usually 587 (STARTTLS) or 465 (SSL) |
| Use SSL | Enable for port 465; leave off for 587 |
| Username | Your email login |
| Password | Your email password or app password |
| From Address | Sender address |
| Alert To | Recipient address |

### Gmail setup

Gmail requires an **App Password** (not your regular password) when 2FA is enabled:
1. Go to myaccount.google.com → Security → 2-Step Verification → App passwords
2. Create an app password for "Mail"
3. Use that 16-character password in the SMTP Password field
4. Host: `smtp.gmail.com`, Port: `587`, SSL: off (uses STARTTLS)

### What the email contains

Each alert email includes:
- Timestamp
- Monitor that triggered
- Trigger description
- Full details
- Action taken (kill switch fired / bypassed)

Emails are sent fire-and-forget with a 15-second timeout. If SMTP fails, it is silently swallowed (the kill switch still fires — email is best-effort).

---

## 8. Settings Reference {#settings}

Open Settings via tray icon → Settings, or Dashboard → Settings button.

### Monitor Intervals

| Setting | Default | Min | Max | Description |
|---------|---------|-----|-----|-------------|
| Status Poll | 15s | 5s | 600s | Gateway health check frequency |
| File Integrity | 60s | 10s | 3600s | FIM check frequency |
| Alert Log | 30s | 5s | 600s | Alert log check frequency |
| Egress | 300s | 30s | 3600s | pf anchor check frequency |
| Patches | 300s | 30s | 3600s | Auth patch count check |
| Namespace | 300s | 30s | 3600s | Namespace isolation check |
| Permissions | 300s | 30s | 3600s | Config permissions check |
| Exposure | 300s | 30s | 3600s | Open port scan |
| Token Age | 6h | 5m | 24h | Token age check |
| Launch Agents | 300s | 30s | 3600s | LaunchAgents scan |
| Binary Integrity | 300s | 30s | 3600s | Binary hash check |
| Sudo Log | 60s | 30s | 600s | Sudo activity check |
| System Posture | 300s | 30s | 3600s | SIP/GK/admin/firewall check |
| Cron Jobs | 300s | 30s | 3600s | Crontab/cron.d/periodic check |
| System Extensions | 600s | 60s | 3600s | systemextensionsctl check |

### Monitored Files

The FIM file list is fully configurable. Each entry has:
- **Path** — absolute or `~/` relative path
- **Critical** — if true, changes trigger the kill switch; if false, changes raise Alert only
- **Check Permissions** — if set (e.g., `"600"`), warns if file permissions are too loose

### Kill Switch Rules

**Bypass monitors** — comma-separated list of monitor names. Monitors in this list still alert but do not lock the gateway.

### Behavior

| Setting | Default | Description |
|---------|---------|-------------|
| Start Minimized | Yes | App starts without opening the Dashboard |
| Show Notification | Yes | macOS notification on kill switch fire |
| Token Max Age | 30 days | Days before token age warning |
| Expected Patch Count | 7 | Minimum patched file count |

---

## 9. How the Security Score Works {#score}

The score is calculated on every monitor update:

```
score = 100
  - (alerts × 25)     — capped at 75 points deducted
  - (warnings × 5)    — capped at 20 points deducted
  - (starting × 2)    — minor penalty for unchecked monitors
minimum = 0
```

A single Alert (e.g., SIP disabled) drops your score by 25 points. Three simultaneous Alerts (uncommon) would floor the score at 25. The kill switch engaged state forces the score to 0.

The **sparkline** records the last 24 score readings (one per update cycle) and maps them to block characters:
- `▁` = 0–12 (critical)
- `█` = 88–100 (excellent)

---

## 10. Limitations & What It Cannot Protect Against {#limitations}

OpenClaw Security Monitor is a **detection and response tool for known macOS attack patterns**. It is not a firewall, antivirus, or full EDR product. The following limitations apply:

### Detection limitations

| Limitation | Impact |
|-----------|--------|
| **In-memory baselines reset on restart** | Threats that occur between app restarts (when no baseline exists for comparison) are not detected until the second check after launch |
| **Polling-based, not event-driven** | Threats are detected on the next poll cycle — default intervals of 1–10 minutes. A fast attack could complete before the next check |
| **No kernel-level visibility** | Cannot see kernel extensions (kexts), kernel patches, or rootkits that operate below the OS |
| **No memory analysis** | Cannot detect in-memory malware that leaves no filesystem footprint |
| **No network deep inspection** | Egress monitoring only checks that the pf anchor exists — it does not analyze actual traffic content |
| **systemextensionsctl limitations** | On some macOS configurations, `systemextensionsctl list` may not return all extensions or may require elevated permissions |

### What it cannot protect against

**Kernel-level rootkits** — An attacker with kernel access can hide processes, files, and network connections from all userspace tools including this app.

**Physical access attacks** — FileVault protects data at rest, but someone with physical access and your login credentials can bypass most software protections.

**Supply chain attacks** — If a software package you install contains malware, the LaunchAgent and Binary Integrity monitors may catch the persistence mechanism but cannot prevent the initial compromise.

**Zero-day exploits** — If an attacker uses a privilege escalation 0-day to gain root silently, they can potentially disable or modify this app before it detects anything.

**Social engineering** — If you are tricked into running a malicious command yourself (e.g., via a fake sudo prompt), the app will see the resulting file changes but cannot stop you from running the command.

**Attacks between poll cycles** — A sufficiently fast attack (e.g., automated malware) could add a LaunchAgent, establish persistence, and clean up within 5 minutes — before the LaunchAgent monitor's next poll.

**iCloud and network drive attacks** — Files synced via iCloud Drive or other cloud services are not monitored unless you explicitly add them to the FIM list.

**App-level sandbox bypass** — The app runs as your user and has the same permissions you do. It cannot protect files that your user account can modify.

**Disabling the app itself** — An attacker with your user account can simply kill the app process before taking action.

### What it does well

- **Persistent malware detection** — LaunchAgents, cron jobs, and system extensions are the most common macOS persistence mechanisms and all three are monitored
- **Privilege escalation detection** — New admin accounts trigger an immediate kill switch
- **Configuration drift detection** — SIP, Gatekeeper, and firewall state changes are caught quickly
- **High-value file tampering** — FIM on SSH keys, auth tokens, and config files catches infostealer activity
- **Visibility** — Even when it cannot stop an attack, it gives you a clear audit trail

---

## 11. Frequently Asked Questions {#faq}

**Q: The app shows "Gateway Health: Warning" all the time. Is something wrong?**
A: Only if you have the OpenClaw gateway installed. If you don't use the gateway, this warning is expected and harmless. You can increase the status poll interval in Settings to reduce log noise.

**Q: The kill switch fired when I installed software. How do I recover?**
A: Open the Dashboard, review the event (it will name the new LaunchAgent), verify it's from the software you just installed, then click "Disengage Kill Switch." The gateway will restart. Consider adding "Launch Agents" to the bypass list if you install software frequently.

**Q: How do I add more files to FIM monitoring?**
A: Settings → Monitored Files → Add. Enter the full path (or `~/` for home directory). Check "Critical" if a change should trigger the kill switch; leave unchecked for Alert-only.

**Q: The app is using a lot of CPU. Why?**
A: By default, File Integrity runs every 60 seconds and hashes 17 files. If you have slow disk or many large files added to the FIM list, this can cause CPU spikes. Increase the File Integrity interval in Settings.

**Q: Can I run this without the OpenClaw gateway?**
A: Yes. 14 of 16 monitors work independently. Only "Gateway Health" and "Binary Integrity" are gateway-specific. The kill switch will still function for LaunchAgent and system posture events — it just won't lock a gateway that isn't there.

**Q: Is my data sent anywhere?**
A: No. All checks run locally using built-in macOS commands. No telemetry is collected. The only outbound network request is the optional GitHub update check, which just fetches the public releases page.

**Q: The score dropped to 0 but everything looks fine in the Dashboard.**
A: The kill switch is engaged. Look for the red banner in the Dashboard and review the triggering event.

**Q: How do I reset everything to a clean state?**
A: Disengage the kill switch → Quit the app → Delete `~/.openclaw/kill-switch-state.json` → Restart the app.

---

## 12. Troubleshooting {#troubleshooting}

### App won't open (Gatekeeper blocked)

Right-click → Open → Open. This only needs to be done once.

### Monitor stuck in "Starting..." permanently

Some monitors require specific macOS permissions:
- **TCC Permissions** monitor may need Full Disk Access — go to System Settings → Privacy & Security → Full Disk Access → add OpenClawMonitor
- **Sudo Activity** monitor uses `log show` which may require additional permissions on macOS 14+

### Kill switch won't disengage

Check that the gateway LaunchAgent plist exists at `~/Library/LaunchAgents/ai.openclaw.gateway.hardened.plist`. If it was deleted, `launchctl` has nothing to load. Reinstall the OpenClaw gateway.

### Email alerts not sending

1. Verify SMTP settings with a separate email client
2. Gmail: use an App Password, not your account password
3. Check `~/.openclaw/security-tray.log` for SMTP error messages
4. Try port 465 with SSL enabled if port 587 is blocked by your ISP

### Settings changes not saving

The settings file is protected with `chmod 600`. If the file is owned by a different user (e.g., after copying from another machine), the app cannot write to it. Fix: `chmod 600 ~/.openclaw/monitor-settings.json` and `chown $USER ~/.openclaw/monitor-settings.json`

### App consuming high memory

The app retains up to 200 kill-switch events in memory and on disk. If you've had many events over time, consider clearing old events from `~/.openclaw/kill-switch-state.json` (valid JSON, edit carefully).

---

## 13. Technical Architecture {#architecture}

### Technology stack

- **.NET 8** — cross-platform runtime
- **Avalonia 11.2.3** — cross-platform UI framework
- **C#** — application language

### File locations

| Path | Contents |
|------|----------|
| `/Applications/OpenClawMonitor.app` | Application bundle |
| `~/.openclaw/monitor-settings.json` | All settings (chmod 600) |
| `~/.openclaw/monitor-settings.integrity` | SHA-256 integrity sidecar |
| `~/.openclaw/kill-switch-state.json` | Kill switch state + event audit trail |
| `~/.openclaw/security-tray.log` | Append-only event log |
| `~/.openclaw/monitor-startup-errors.log` | Startup error log |

### Settings integrity

The settings file is protected against tampering with a SHA-256 hash stored in a sidecar file. On load, the hash is verified. If the file has been modified externally, the app falls back to defaults and overwrites the file. This prevents an attacker from disabling monitors by editing the settings file.

### Kill switch persistence

Kill switch state is persisted to `~/.openclaw/kill-switch-state.json` on every event. This means:
- If the app is killed, the kill switch state is preserved on restart
- The gateway remains locked across reboots (launchctl unload persists)
- Up to 200 events are retained in the audit trail

### Source code

Full source code is available at:
`https://github.com/XBS9/openclaw-security-monitor-mac`

The project includes a 53-test xUnit test suite covering all monitor logic, kill switch behavior, and settings validation. Tests use mock implementations of all external dependencies (no real processes or files are touched during testing).

---

*OpenClaw Security Monitor v1.5.2 — Open source, MIT License*
*https://github.com/XBS9/openclaw-security-monitor-mac*
