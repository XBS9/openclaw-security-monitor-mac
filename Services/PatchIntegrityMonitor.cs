using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Verifies timing-safe auth patches are applied to OpenClaw dist files.
/// Also detects version changes and auto-reapplies patches after updates.
/// Does not fire the kill switch — patch warnings require manual action.
/// </summary>
public class PatchIntegrityMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;
    private readonly AutoPatchService _autoPatch;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private string? _lastKnownVersion;

    public event Action<string>? PatchWarning;

    public PatchIntegrityMonitor(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
    {
        _cmd = cmd;
        _killSwitch = killSwitch;
        _settings = settings;
        _hub = hub;
        _autoPatch = new AutoPatchService(cmd, settings);
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
            await Task.Delay(TimeSpan.FromSeconds(20), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.PatchCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    public async Task<(int PatchedCount, string Method, List<string> Files)> GetPatchStatusAsync()
    {
        var npmPath  = PathUtils.Expand(_settings.NpmGlobalPath);
        var distPath = $"{npmPath}/lib/node_modules/openclaw/dist";

        var (_, upstreamOutput, _) = await _cmd.RunAsync(
            $"grep -rl 'safeEqualSecret' \"{distPath}\"/*.js 2>/dev/null || true");
        var upstreamFiles = upstreamOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .ToList();

        if (upstreamFiles.Count > 0)
            return (upstreamFiles.Count, "upstream", upstreamFiles);

        var (_, localOutput, _) = await _cmd.RunAsync(
            $"grep -rl '__safeTokenEqual' \"{distPath}\"/ 2>/dev/null || true");
        var localFiles = localOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .ToList();

        return (localFiles.Count, "local", localFiles);
    }

    private async Task CheckVersionAndAutoPatchAsync()
    {
        try
        {
            var version = await _autoPatch.GetOpenClawVersionAsync();
            if (string.IsNullOrWhiteSpace(version) || version == "unknown")
                return;

            if (_lastKnownVersion == null)
            {
                _lastKnownVersion = version;
                return;
            }

            if (version != _lastKnownVersion)
            {
                var oldVersion = _lastKnownVersion;
                _lastKnownVersion = version;

                var (upstreamCount, method, _) = await GetPatchStatusAsync();
                if (method == "upstream" && upstreamCount > 0)
                {
                    _hub.Report(MonitorHub.Patches, MonitorState.Ok,
                        $"Version changed: {oldVersion} → {version}; upstream fix present ({upstreamCount} files)");
                    return;
                }

                _hub.Report(MonitorHub.Patches, MonitorState.Warning,
                    $"Version changed: {oldVersion} → {version}, re-patching...");

                var (success, _) = await _autoPatch.RunPatchAsync();
                if (success)
                {
                    _hub.Report(MonitorHub.Patches, MonitorState.Ok,
                        $"Auto-patched after update to {version}");
                }
                else
                {
                    var msg = $"Auto-patch failed after update to {version}";
                    _hub.Report(MonitorHub.Patches, MonitorState.Warning, msg);
                    PatchWarning?.Invoke(msg);
                }
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Patches, MonitorState.Warning,
                $"Version check failed: {ex.Message}");
        }
    }

    private async Task CheckAsync()
    {
        try
        {
            await CheckVersionAndAutoPatchAsync();

            var (count, method, _) = await GetPatchStatusAsync();

            if (method == "upstream" && count > 0)
            {
                _hub.Report(MonitorHub.Patches, MonitorState.Ok,
                    $"Upstream fixed ({count} files use safeEqualSecret)");
            }
            else if (method == "local" && count >= _settings.ExpectedPatchedFileCount)
            {
                _hub.Report(MonitorHub.Patches, MonitorState.Ok,
                    $"{count}/{_settings.ExpectedPatchedFileCount} patched (local)");
            }
            else if (method == "local" && count > 0)
            {
                var msg = $"Partial patches: {count}/{_settings.ExpectedPatchedFileCount}. Run auto-patch.";
                _hub.Report(MonitorHub.Patches, MonitorState.Warning, msg);
                PatchWarning?.Invoke(msg);
            }
            else
            {
                var msg = "No auth patches found. Run auto-patch or update OpenClaw.";
                _hub.Report(MonitorHub.Patches, MonitorState.Warning, msg);
                PatchWarning?.Invoke(msg);
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Patches, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
