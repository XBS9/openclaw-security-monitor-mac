using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Audits loaded macOS system extensions via systemextensionsctl.
///
/// System extensions (successor to kernel extensions) have deep access to the
/// OS — they can intercept network traffic, keystrokes, and file operations.
///
/// New extensions detected since baseline → Alert.
/// Removed extensions → Warning.
/// Not a kill-switch trigger because legitimate software updates add extensions.
///
/// Baseline is in-memory; reset on app restart.
/// </summary>
public class SystemExtensionMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private HashSet<string>? _baseline;

    public SystemExtensionMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(25), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.SystemExtensionCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var (_, output, _) = await _cmd.RunAsync("systemextensionsctl list 2>/dev/null");
            var extensions = ParseExtensions(output);

            if (_baseline == null)
            {
                _baseline = extensions;
                _hub.Report(MonitorHub.SystemExtensions, MonitorState.Ok,
                    $"Baseline set ({extensions.Count} extensions)");
                return;
            }

            var newExts     = extensions.Except(_baseline).ToList();
            var removedExts = _baseline.Except(extensions).ToList();

            if (newExts.Count > 0)
            {
                var names = string.Join(", ", newExts.Take(2));
                if (newExts.Count > 2) names += $" +{newExts.Count - 2} more";
                _hub.Report(MonitorHub.SystemExtensions, MonitorState.Alert,
                    $"New extension: {names}");
                _baseline.UnionWith(newExts);
                return;
            }

            if (removedExts.Count > 0)
            {
                _hub.Report(MonitorHub.SystemExtensions, MonitorState.Warning,
                    $"Removed: {string.Join(", ", removedExts.Take(2))}");
                _baseline.ExceptWith(removedExts);
                return;
            }

            _hub.Report(MonitorHub.SystemExtensions, MonitorState.Ok,
                $"OK ({extensions.Count} extensions)");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.SystemExtensions, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }

    private static HashSet<string> ParseExtensions(string output)
    {
        // systemextensionsctl list output looks like:
        //   [activated enabled] com.vendor.ext    (1.0.0)
        // We extract the bundle ID between ] and (
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var l = line.Trim();
            if (!l.StartsWith('[')) continue;
            var idx = l.IndexOf(']');
            if (idx < 0) continue;
            var rest = l[(idx + 1)..].Trim();
            // rest is like "com.vendor.ext    (1.0.0)"
            var space = rest.IndexOfAny(new[] { ' ', '\t', '(' });
            var bundleId = space > 0 ? rest[..space].Trim() : rest;
            if (!string.IsNullOrEmpty(bundleId))
                result.Add(bundleId);
        }
        return result;
    }
}
