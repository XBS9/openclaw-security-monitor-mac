using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Checks macOS system security posture on every SystemPostureCheckInterval:
///
///   • SIP (System Integrity Protection) — disabled → Alert
///   • Gatekeeper — disabled → Alert
///   • Auto-login — enabled → Warning (convenience feature that bypasses login screen)
///   • macOS Application Firewall — off → Warning
///   • Admin group membership — new admin added → Kill Switch (privilege escalation)
///   • Remote access: SSH, Screen Sharing, Remote Management — each on → Warning
///
/// Admin baseline is in-memory; reset on app restart.
/// </summary>
public class SystemPostureMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private HashSet<string>? _adminBaseline;

    public SystemPostureMonitor(ICommandService cmd, KillSwitch killSwitch,
        TraySettings settings, MonitorHub hub)
    {
        _cmd        = cmd;
        _killSwitch = killSwitch;
        _settings   = settings;
        _hub        = hub;
    }

    public void Start()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _ = RunAsync(_cts.Token);
    }

    public void Stop() => _cts?.Cancel();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(15, _settings.SystemPostureCheckInterval)), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.SystemPostureCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var alerts   = new List<string>();
            var warnings = new List<string>();

            // ── SIP ─────────────────────────────────────────────────────────
            var (_, sipOut, _) = await _cmd.RunAsync("csrutil status 2>/dev/null");
            if (!sipOut.Contains("enabled", StringComparison.OrdinalIgnoreCase))
                alerts.Add("SIP disabled");

            // ── Gatekeeper ──────────────────────────────────────────────────
            var (_, gkOut, _) = await _cmd.RunAsync("spctl --status 2>/dev/null");
            if (!gkOut.Contains("enabled", StringComparison.OrdinalIgnoreCase))
                alerts.Add("Gatekeeper disabled");

            // ── Auto-login ──────────────────────────────────────────────────
            var (_, autoLoginOut, _) = await _cmd.RunAsync(
                "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo '__disabled__'");
            var autoLoginUser = autoLoginOut.Trim();
            if (autoLoginUser != "__disabled__" && !string.IsNullOrWhiteSpace(autoLoginUser))
                warnings.Add($"Auto-login: {autoLoginUser}");

            // ── Application Firewall ─────────────────────────────────────────
            // globalstate: 0=off, 1=on, 2=block all incoming
            var (_, alfOut, _) = await _cmd.RunAsync(
                "defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo '1'");
            if (int.TryParse(alfOut.Trim(), out int alfState) && alfState == 0)
                warnings.Add("App Firewall off");

            // ── Admin accounts ───────────────────────────────────────────────
            var (_, adminOut, _) = await _cmd.RunAsync(
                "dscl . -read /Groups/admin GroupMembership 2>/dev/null");
            var admins = ParseAdminMembers(adminOut);

            if (_adminBaseline == null)
            {
                var loadResult = BaselinePersistence.TryLoad("admin-accounts", out var saved);

                if (loadResult == BaselinePersistence.LoadResult.Tampered)
                {
                    alerts.Add("Admin baseline tampered — re-establishing");
                    _adminBaseline = admins;
                    BaselinePersistence.Save("admin-accounts", _adminBaseline);
                }
                else if (loadResult == BaselinePersistence.LoadResult.Ok && saved != null)
                {
                    _adminBaseline = saved;
                    var newSinceRestart = admins.Except(_adminBaseline).ToList();
                    if (newSinceRestart.Count > 0)
                    {
                        var names = string.Join(", ", newSinceRestart);
                        await _killSwitch.FireAsync("SystemPostureMonitor",
                            $"New admin account since last run: {newSinceRestart[0]}",
                            $"New account(s) added to admin group while monitor was offline: {names}");
                        _adminBaseline.UnionWith(newSinceRestart);
                        BaselinePersistence.Save("admin-accounts", _adminBaseline);
                    }
                }
                else
                {
                    _adminBaseline = admins;
                    BaselinePersistence.Save("admin-accounts", _adminBaseline);
                }
            }
            else
            {
                var newAdmins = admins.Except(_adminBaseline).ToList();
                if (newAdmins.Count > 0)
                {
                    var names = string.Join(", ", newAdmins);
                    await _killSwitch.FireAsync("SystemPostureMonitor",
                        $"New admin account: {newAdmins[0]}",
                        $"New account(s) added to admin group: {names}");
                    _adminBaseline.UnionWith(newAdmins);
                    BaselinePersistence.Save("admin-accounts", _adminBaseline);
                }
            }

            // ── Self-protection plist ────────────────────────────────────────
            // LaunchAgent with KeepAlive=true makes launchd restart the monitor after kill.
            // If the plist is missing, any local user process can silence monitoring forever.
            var selfPlistPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "LaunchAgents", "com.openclaw.security-monitor.plist");
            if (!File.Exists(selfPlistPath) ||
                !File.ReadAllText(selfPlistPath).Contains("KeepAlive",
                    StringComparison.OrdinalIgnoreCase))
            {
                warnings.Add("Self-protection plist missing — monitor can be silenced");
            }

            // ── Remote access ────────────────────────────────────────────────
            var (_, sshOut, _) = await _cmd.RunAsync(
                "systemsetup -getremotelogin 2>/dev/null || echo 'Remote Login: Off'");
            if (sshOut.Contains(": On", StringComparison.OrdinalIgnoreCase))
                warnings.Add("SSH on");

            var (_, screenOut, _) = await _cmd.RunAsync(
                "launchctl list com.apple.screensharing 2>/dev/null && echo SCREEN_ON || echo SCREEN_OFF");
            if (screenOut.Contains("SCREEN_ON"))
                warnings.Add("Screen Sharing on");

            var (_, rdOut, _) = await _cmd.RunAsync(
                "launchctl list com.apple.RemoteDesktopAgent 2>/dev/null && echo RD_ON || echo RD_OFF");
            if (rdOut.Contains("RD_ON"))
                warnings.Add("Remote Mgmt on");

            // ── Report ───────────────────────────────────────────────────────
            if (alerts.Count > 0)
            {
                _hub.Report(MonitorHub.SystemPosture, MonitorState.Alert,
                    string.Join("; ", alerts.Concat(warnings)));
            }
            else if (warnings.Count > 0)
            {
                _hub.Report(MonitorHub.SystemPosture, MonitorState.Warning,
                    string.Join("; ", warnings));
            }
            else
            {
                var adminCount = _adminBaseline?.Count ?? admins.Count;
                _hub.Report(MonitorHub.SystemPosture, MonitorState.Ok,
                    $"SIP ✓ · GK ✓ · {adminCount} admin(s)");
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.SystemPosture, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }

    private static HashSet<string> ParseAdminMembers(string dsclOutput)
    {
        // dscl output: "GroupMembership: root jorge ..."
        var members = new HashSet<string>(StringComparer.Ordinal);
        var line = dsclOutput.Split('\n')
            .FirstOrDefault(l => l.StartsWith("GroupMembership:", StringComparison.OrdinalIgnoreCase));
        if (line == null) return members;
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 1; i < parts.Length; i++) // skip "GroupMembership:"
            members.Add(parts[i].Trim());
        return members;
    }
}
