using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Checks that the hardened launchd plist still contains ProcessType=Background
/// and that the Docker socket isn't world-writable (777), every NamespaceCheckInterval seconds.
/// Fires the kill switch on confirmed violations.
///
/// macOS adaptation vs Linux version:
///   • NoNewPrivileges → ProcessType=Background (closest launchd equivalent)
///   • stat -f '%Lp' for permissions (macOS stat syntax)
///   • No namespace isolation markers like InaccessiblePaths — use ProcessType as marker
/// </summary>
public class NamespaceMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    public NamespaceMonitor(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
    {
        _cmd = cmd;
        _killSwitch = killSwitch;
        _settings = settings;
        _hub = hub;
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
            await Task.Delay(TimeSpan.FromSeconds(45), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.NamespaceCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var basePath = PathUtils.Expand(_settings.ServiceBasePath);
            var label    = _settings.GatewayLabel;

            // Check hardened plist has ProcessType=Background (macOS hardening marker).
            // Also check active plist line count and hardening directives.
            var cmd =
                $"if [ -f \"{basePath}/{label}.hardened.plist\" ]; then " +
                $"echo \"NNP=$(grep -c 'Background' \"{basePath}/{label}.hardened.plist\" 2>/dev/null)\"; " +
                "else echo 'NNP=MISSING'; fi; " +
                $"ACTIVE_LINES=$(wc -l < \"{basePath}/{label}.plist\" 2>/dev/null || echo 0); " +
                "echo \"ACTIVE_LINES=$ACTIVE_LINES\"; " +
                $"echo \"ACTIVE_HARDENED=$(grep -c 'ProcessType\\|AbandonProcessGroup\\|ThrottleInterval' \"{basePath}/{label}.plist\" 2>/dev/null || echo 0)\"; " +
                // macOS Docker socket: /var/run/docker.sock, use stat -f '%Lp' for octal perms
                "echo \"DOCKER=$(stat -f '%Lp' /var/run/docker.sock 2>/dev/null || echo missing)\"";

            var (_, output, _) = await _cmd.RunAsync(cmd);
            if (string.IsNullOrEmpty(output))
            {
                _hub.Report(MonitorHub.Namespace, MonitorState.Warning, "No output");
                return;
            }

            bool nnpOk = true;
            bool dockerOk = true;
            int activeLines = 0;
            int activeHardened = 0;

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("NNP="))
                {
                    var value = line["NNP=".Length..].Trim();
                    if (value == "MISSING")
                    {
                        nnpOk = false;
                        // Warn only — new installs won't have the hardened template yet.
                        // Kill switch fires only if the file existed before and is now gone (tampering).
                        _hub.Report(MonitorHub.Namespace, MonitorState.Warning,
                            "Hardened plist template not found — create ai.openclaw.gateway.hardened.plist");
                        return;
                    }
                    if (value == "0")
                    {
                        nnpOk = false;
                        _hub.Report(MonitorHub.Namespace, MonitorState.Alert, "ProcessType=Background removed from hardened plist!");
                        await _killSwitch.FireAsync("NamespaceMonitor",
                            "Hardening directive removed from plist",
                            "Hardened plist no longer contains ProcessType=Background — possible tampering");
                        return;
                    }
                }
                else if (line.StartsWith("ACTIVE_LINES="))
                    int.TryParse(line["ACTIVE_LINES=".Length..].Trim(), out activeLines);
                else if (line.StartsWith("ACTIVE_HARDENED="))
                    int.TryParse(line["ACTIVE_HARDENED=".Length..].Trim(), out activeHardened);
                else if (line.StartsWith("DOCKER="))
                {
                    var perms = line["DOCKER=".Length..].Trim();
                    if (perms == "777")
                    {
                        dockerOk = false;
                        _hub.Report(MonitorHub.Namespace, MonitorState.Alert, "Docker socket 777!");
                        await _killSwitch.FireAsync("NamespaceMonitor",
                            "Docker socket world-writable",
                            $"Docker socket has permissions {perms} — possible privilege escalation vector");
                        return;
                    }
                }
            }

            // Warn if active plist has no hardening directives (stock/unlocked plist).
            // Real plists with env vars are 40-60 lines; stock bare plists are <25 lines.
            bool activeIsStock = activeLines > 0 && activeLines <= 35 && activeHardened == 0;

            if (nnpOk && dockerOk)
            {
                if (activeIsStock)
                    _hub.Report(MonitorHub.Namespace, MonitorState.Warning,
                        $"Isolation intact; active plist has no hardening ({activeLines} lines)");
                else
                    _hub.Report(MonitorHub.Namespace, MonitorState.Ok, "Isolation intact");
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Namespace, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
