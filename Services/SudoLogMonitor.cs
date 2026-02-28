using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Monitors the macOS unified log for unexpected sudo invocations.
///
/// Uses `log show` to query recent entries mentioning "sudo" every
/// SudoLogCheckInterval seconds. Alerts if a COMMAND= entry appears
/// from a process not in the known-safe allowlist.
///
/// Known-safe callers: standard macOS system processes, bash/zsh,
/// and the OpenClaw monitor itself.
/// </summary>
public class SudoLogMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private static readonly HashSet<string> KnownSafe = new(StringComparer.OrdinalIgnoreCase)
    {
        "sudo", "bash", "sh", "zsh", "fish",
        "osascript", "OpenClawSecurityMonitorMac",
        "installer", "softwareupdate", "mdmclient",
        "system_installd", "com.apple", "launchd",
        "xpcproxy", "sshd", "systemextensionsctl"
    };

    public SudoLogMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(90), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.SudoLogCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            // Look back slightly further than the check interval to avoid missing events
            var minutesBack = Math.Max(2, (_settings.SudoLogCheckInterval / 60) + 1);

            var (_, output, _) = await _cmd.RunAsync(
                $"log show " +
                $"--predicate 'senderImagePath ENDSWITH \"sudo\" AND eventMessage CONTAINS \"TTY\"' " +
                $"--last {minutesBack}m --style compact 2>/dev/null " +
                "| grep -v '^Timestamp\\|^---\\|^$' | tail -30");

            if (string.IsNullOrWhiteSpace(output))
            {
                _hub.Report(MonitorHub.SudoLog, MonitorState.Ok, "No sudo activity");
                return;
            }

            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                              .Select(l => l.Trim())
                              .Where(l => !string.IsNullOrEmpty(l))
                              .ToList();

            // Entries with COMMAND= represent actual sudo executions
            var execLines = lines.Where(l => l.Contains("COMMAND=", StringComparison.OrdinalIgnoreCase))
                                 .ToList();

            if (execLines.Count == 0)
            {
                _hub.Report(MonitorHub.SudoLog, MonitorState.Ok,
                    $"{lines.Count} sudo event(s), no executions");
                return;
            }

            var suspicious = new List<string>();
            foreach (var line in execLines)
            {
                var lower = line.ToLowerInvariant();
                bool isSafe = KnownSafe.Any(s => lower.Contains(s.ToLowerInvariant()));
                if (!isSafe)
                    suspicious.Add(line.Length > 80 ? line[..77] + "…" : line);
            }

            if (suspicious.Count > 0)
            {
                _hub.Report(MonitorHub.SudoLog, MonitorState.Alert,
                    $"Unexpected sudo: {suspicious[0]}");
                return;
            }

            _hub.Report(MonitorHub.SudoLog, MonitorState.Ok,
                $"{execLines.Count} sudo exec(s), all expected");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.SudoLog, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }
}
