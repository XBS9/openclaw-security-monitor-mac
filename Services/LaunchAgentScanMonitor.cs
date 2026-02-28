using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Scans ~/Library/LaunchAgents for unknown .plist files not present at startup.
/// Alerts on newly-added plists, which are a common persistence vector for malware.
///
/// Uses an in-memory baseline established on the first check.
/// New plist → kill switch (persistence backdoor is a critical threat).
/// Removed known plist → Warning (could indicate tampering with openclaw itself).
/// </summary>
public class LaunchAgentScanMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private HashSet<string>? _baseline;

    public LaunchAgentScanMonitor(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.LaunchAgentCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            // List .plist basenames in ~/Library/LaunchAgents
            var (_, output, _) = await _cmd.RunAsync(
                "ls ~/Library/LaunchAgents/ 2>/dev/null | grep '\\.plist$'");

            var current = new HashSet<string>(
                output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                      .Select(l => l.Trim())
                      .Where(l => l.EndsWith(".plist", StringComparison.OrdinalIgnoreCase)),
                StringComparer.Ordinal);

            if (_baseline == null)
            {
                _baseline = current;
                _hub.Report(MonitorHub.LaunchAgents, MonitorState.Ok,
                    $"Baseline set ({current.Count} agents)");
                return;
            }

            var newAgents     = current.Except(_baseline).ToList();
            var removedAgents = _baseline.Except(current).ToList();

            if (newAgents.Count > 0)
            {
                var names = string.Join(", ", newAgents.Take(3));
                if (newAgents.Count > 3) names += $" +{newAgents.Count - 3} more";

                _hub.Report(MonitorHub.LaunchAgents, MonitorState.Alert,
                    $"New agent: {names}");

                await _killSwitch.FireAsync("LaunchAgentScanMonitor",
                    $"New LaunchAgent: {newAgents[0]}",
                    $"Unknown persistence plist(s) added to ~/Library/LaunchAgents: {string.Join(", ", newAgents)}");

                // Absorb so we don't re-fire for the same plist on every cycle
                _baseline.UnionWith(newAgents);
                return;
            }

            if (removedAgents.Count > 0)
            {
                var names = string.Join(", ", removedAgents.Take(3));
                _hub.Report(MonitorHub.LaunchAgents, MonitorState.Warning,
                    $"Removed: {names}");
                _baseline.ExceptWith(removedAgents);
                return;
            }

            _hub.Report(MonitorHub.LaunchAgents, MonitorState.Ok,
                $"OK ({current.Count} agents)");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.LaunchAgents, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }
}
