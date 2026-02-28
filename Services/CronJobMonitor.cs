using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Monitors cron job entries for unexpected additions.
///
/// Sources checked:
///   • User crontab  (crontab -l)
///   • /etc/cron.d/  (system cron snippet files)
///   • /etc/periodic/ (macOS periodic task directories)
///
/// Uses an in-memory baseline; new entries → Warning.
/// Cron is not a kill-switch trigger because legitimate software also uses cron.
/// </summary>
public class CronJobMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private HashSet<string>? _baseline;

    public CronJobMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
    {
        _cmd      = cmd;
        _settings = settings;
        _hub      = hub;
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
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(20, _settings.CronJobCheckInterval)), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.CronJobCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var entries = new HashSet<string>(StringComparer.Ordinal);

            // User crontab
            var (_, userCron, _) = await _cmd.RunAsync("crontab -l 2>/dev/null");
            foreach (var line in userCron.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var l = line.Trim();
                if (!l.StartsWith('#') && !string.IsNullOrEmpty(l))
                    entries.Add("user:" + l);
            }

            // /etc/cron.d/ files
            var (_, cronD, _) = await _cmd.RunAsync("ls /etc/cron.d/ 2>/dev/null");
            foreach (var f in cronD.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                entries.Add("cron.d:" + f.Trim());

            // /etc/periodic/ subdirectory entries
            var (_, periodic, _) = await _cmd.RunAsync("ls /etc/periodic/ 2>/dev/null");
            foreach (var d in periodic.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                entries.Add("periodic:" + d.Trim());

            if (_baseline == null)
            {
                _baseline = entries;
                _hub.Report(MonitorHub.CronJobs, MonitorState.Ok,
                    entries.Count == 0 ? "No cron jobs" : $"Baseline set ({entries.Count} entries)");
                return;
            }

            var newEntries = entries.Except(_baseline).ToList();
            if (newEntries.Count > 0)
            {
                var summary = string.Join(", ", newEntries.Take(2));
                if (newEntries.Count > 2) summary += $" +{newEntries.Count - 2} more";
                _hub.Report(MonitorHub.CronJobs, MonitorState.Warning,
                    $"New: {summary}");
                _baseline.UnionWith(newEntries);
                return;
            }

            _hub.Report(MonitorHub.CronJobs, MonitorState.Ok,
                entries.Count == 0 ? "No cron jobs" : $"OK ({entries.Count} entries)");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.CronJobs, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }
}
