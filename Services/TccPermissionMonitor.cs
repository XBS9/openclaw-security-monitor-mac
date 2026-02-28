using System.IO;
using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Audits macOS TCC (Transparency, Consent, and Control) grants for high-risk permissions:
///   • Screen Recording (kTCCServiceScreenCapture)
///   • Accessibility (kTCCServiceAccessibility)
///   • Full Disk Access (kTCCServiceSystemPolicyAllFiles)
///
/// Requires the monitor app to have Full Disk Access to read TCC.db.
/// Gracefully degrades if access is denied — reports Warning instead of crashing.
/// Alerts if a new high-risk grant appears since the last check.
/// </summary>
public class TccPermissionMonitor : IDisposable
{
    private const int CheckIntervalSeconds = 600;

    private readonly ICommandService _cmd;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private HashSet<string>? _baseline;

    private static readonly string TccDbPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "Library", "Application Support", "com.apple.TCC", "TCC.db");

    // Services we consider high-risk
    private const string HighRiskServices =
        "'kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceSystemPolicyAllFiles'";

    public TccPermissionMonitor(ICommandService cmd, MonitorHub hub)
    {
        _cmd = cmd;
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
            await Task.Delay(TimeSpan.FromSeconds(60), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(CheckIntervalSeconds));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            if (!File.Exists(TccDbPath))
            {
                _hub.Report(MonitorHub.TccPermissions, MonitorState.Warning,
                    "TCC.db not found");
                return;
            }

            // macOS uses 'allowed' (0/1) on older versions, 'auth_value' (2=allowed) on newer.
            // Accept either to stay compatible across macOS versions.
            var query =
                $"SELECT client, service FROM access " +
                $"WHERE service IN ({HighRiskServices}) " +
                $"AND (allowed=1 OR auth_value=2)";

            var (exitCode, output, _) = await _cmd.RunAsync(
                $"sqlite3 \"{TccDbPath}\" \"{query}\" 2>/dev/null");

            if (exitCode != 0)
            {
                _hub.Report(MonitorHub.TccPermissions, MonitorState.Warning,
                    "Needs Full Disk Access to audit TCC");
                return;
            }

            var grants = new HashSet<string>(
                output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                      .Select(l => l.Trim())
                      .Where(l => !string.IsNullOrEmpty(l)),
                StringComparer.Ordinal);

            if (_baseline == null)
            {
                _baseline = grants;
                var label = grants.Count == 0
                    ? "No high-risk grants"
                    : $"Baseline: {grants.Count} high-risk grant(s)";
                _hub.Report(MonitorHub.TccPermissions, MonitorState.Ok, label);
                return;
            }

            var newGrants = grants.Except(_baseline).ToList();
            if (newGrants.Count > 0)
            {
                // Format as "app(Service)" for readability
                var desc = string.Join(", ", newGrants.Take(3).Select(g =>
                {
                    var parts = g.Split('|');
                    if (parts.Length >= 2)
                    {
                        var svc = parts[1].Replace("kTCCService", "");
                        return $"{parts[0]}({svc})";
                    }
                    return g;
                }));
                _hub.Report(MonitorHub.TccPermissions, MonitorState.Alert,
                    $"New TCC grant: {desc}");
                _baseline.UnionWith(newGrants);
                return;
            }

            _hub.Report(MonitorHub.TccPermissions, MonitorState.Ok,
                grants.Count == 0
                    ? "No high-risk grants"
                    : $"OK ({grants.Count} grants, unchanged)");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.TccPermissions, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }
}
