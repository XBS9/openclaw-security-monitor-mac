using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Watches security-alerts.log for new threat signatures every AlertLogInterval seconds,
/// and checks the gateway macOS log for abnormal authentication failure rates.
///
/// macOS adaptation: uses 'log show' instead of journalctl for auth rate detection.
/// </summary>
public class AlertLogWatcher : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private int _lastLineCount;
    private bool _firstRun = true;

    public AlertLogWatcher(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(10), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.AlertLogInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private static readonly string[] ThreatPatterns =
    [
        "PROMPT_INJECTION",
        "ignore.*previous.*instructions",
        "ignore.*above.*instructions",
        "you are now",
        "act as",
        "new role",
        "override.*safety",
        "bypass.*security",
        "disable.*sandbox",
        "reveal.*system.*prompt",
        "reveal.*(secret|token|key|password)",
        @"cat.*\.env",
        @"cat.*openclaw\.json",
        @"curl.*webhook",
        @"curl.*exfil",
        "base64.*openclaw",
        "exfiltrat",
        "execute.*rm -rf",
        "tool.*hijack",
        "infostealer",
    ];

    private const int AuthRateThreshold = 10;

    private async Task CheckAsync()
    {
        try
        {
            var logPath = PathUtils.Expand(_settings.SecurityAlertsLogPath);

            var cmd = $"if [ -f \"{logPath}\" ]; then " +
                      $"echo \"COUNT=$(wc -l < \"{logPath}\")\"; " +
                      "else echo 'COUNT=0'; fi";

            var (_, output, _) = await _cmd.RunAsync(cmd);
            if (string.IsNullOrEmpty(output)) return;

            int currentCount = 0;
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("COUNT="))
                    int.TryParse(line["COUNT=".Length..], out currentCount);
            }

            if (_firstRun)
            {
                _lastLineCount = currentCount;
                _firstRun = false;
                _hub.Report(MonitorHub.AlertLog, MonitorState.Ok, "Watching log");
                return;
            }

            if (currentCount < _lastLineCount)
                _lastLineCount = currentCount;

            int threatCount = 0;
            if (currentCount > _lastLineCount)
            {
                var newLines = currentCount - _lastLineCount;
                var patternArg = string.Join("|", ThreatPatterns);
                var tailCmd = $"tail -n {newLines} \"{logPath}\" | grep -iE '{patternArg}' || true";
                var (_, newOutput, _) = await _cmd.RunAsync(tailCmd);

                _lastLineCount = currentCount;

                if (!string.IsNullOrEmpty(newOutput))
                    threatCount = newOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
            }

            // Auth rate check via gateway error log (fast — avoids 'log show' which blocks minutes without sudo).
            // Counts auth-related error lines written in the last ~60 seconds by inspecting tail of err log.
            // NOTE: "closed before connect" is intentionally excluded — OpenClaw emits this during its own
            // internal reconnects (e.g. Telegram cron re-pairing), causing constant false positives.
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var errLog = Path.Combine(home, ".openclaw", "logs", "gateway.err.log");
            var authCmd = File.Exists(errLog)
                ? $"tail -n 200 \"{errLog}\" | grep -ciE 'auth.*fail|Unauthorized|invalid.*token|\\b401\\b' || echo 0"
                : "echo 0";
            var (_, authOutput, _) = await _cmd.RunAsync(authCmd);
            int.TryParse(authOutput.Trim(), out var authFailCount);

            if (threatCount > 0 && authFailCount > AuthRateThreshold)
            {
                _hub.Report(MonitorHub.AlertLog, MonitorState.Warning,
                    $"{threatCount} threat signature(s); {authFailCount} auth failures/min");
            }
            else if (threatCount > 0)
            {
                _hub.Report(MonitorHub.AlertLog, MonitorState.Warning,
                    $"{threatCount} threat signature(s) in alerts log");
            }
            else if (authFailCount > AuthRateThreshold)
            {
                _hub.Report(MonitorHub.AlertLog, MonitorState.Warning,
                    $"Auth rate: {authFailCount} failures/min — possible brute-force");
            }
            else
            {
                _hub.Report(MonitorHub.AlertLog, MonitorState.Ok, "No new alerts");
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.AlertLog, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
