using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Checks SHA-256 hashes and permissions for monitored files every FileIntegrityInterval seconds.
/// Fires the kill switch if a critical file is tampered with.
///
/// macOS adaptations vs Linux version:
///   • shasum -a 256 instead of sha256sum (stock macOS)
///   • stat -f '%Lp' instead of stat -c '%a' for octal permissions
///   • No lsattr / immutable check (macOS uses BSD flags, not ext4 immutable)
/// </summary>
public class FileIntegrityMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private readonly Dictionary<string, FileBaseline> _baselines = new();
    private bool _baselineEstablished;

    public FileIntegrityMonitor(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.FileIntegrityInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var files = _settings.MonitoredFiles;
            var commands = new List<string>();

            foreach (var f in files)
            {
                var p = PathUtils.Expand(f.Path);
                // macOS: shasum -a 256 outputs "hash  filename", cut first field
                commands.Add($"echo \"HASH:{f.Path}:$(shasum -a 256 \"{p}\" 2>/dev/null | awk '{{print $1}}')\"");
                if (f.CheckPermissions != null)
                    // macOS: stat -f '%Lp' for octal permissions
                    commands.Add($"echo \"PERM:{f.Path}:$(stat -f '%Lp' \"{p}\" 2>/dev/null)\"");
            }

            var batchCmd = string.Join("; ", commands);
            var (_, output, _) = await _cmd.RunAsync(batchCmd);

            if (string.IsNullOrEmpty(output))
            {
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Warning, "No output from check");
                return;
            }

            var results = new Dictionary<string, FileBaseline>();
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split(':', 3);
                if (parts.Length < 3) continue;

                var type  = parts[0];
                var path  = parts[1];
                var value = parts[2].Trim();

                if (!results.ContainsKey(path))
                    results[path] = new FileBaseline { Path = path };

                var config = files.FirstOrDefault(f => f.Path == path);
                if (config != null)
                    results[path].IsCritical = config.Critical;

                switch (type)
                {
                    case "HASH":
                        results[path].Hash = value;
                        break;
                    case "PERM":
                        results[path].Permissions = value;
                        break;
                }
            }

            if (!_baselineEstablished)
            {
                foreach (var (path, baseline) in results)
                    _baselines[path] = baseline;
                _baselineEstablished = true;
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Ok, $"Baseline set ({results.Count} files)");
                return;
            }

            var warnings = new List<string>();

            foreach (var (path, current) in results)
            {
                if (!_baselines.TryGetValue(path, out var baseline))
                {
                    _baselines[path] = current;
                    continue;
                }

                if (!string.IsNullOrEmpty(baseline.Hash) && !string.IsNullOrEmpty(current.Hash)
                    && baseline.Hash != current.Hash)
                {
                    if (current.IsCritical)
                    {
                        _baselines[path] = current;
                        _hub.Report(MonitorHub.FileIntegrity, MonitorState.Alert, $"TAMPERED: {path}");
                        var oldHash = baseline.Hash.Length > 12 ? baseline.Hash[..12] + "..." : baseline.Hash;
                        var newHash = current.Hash.Length > 12 ? current.Hash[..12] + "..." : current.Hash;
                        await _killSwitch.FireAsync("FileIntegrityMonitor",
                            $"Critical file modified: {path}",
                            $"SHA-256 changed from {oldHash} to {newHash}");
                        return;
                    }
                    // Non-critical change — update baseline and warn so it's visible.
                    _baselines[path] = current;
                    var shortPath = path.Length > 40 ? "..." + path[^37..] : path;
                    warnings.Add($"Changed: {shortPath}");
                }

                var config2 = files.FirstOrDefault(f => f.Path == path);
                if (config2?.CheckPermissions != null
                    && !string.IsNullOrEmpty(current.Permissions)
                    && current.Permissions != config2.CheckPermissions)
                {
                    warnings.Add($"Perms {current.Permissions} on {System.IO.Path.GetFileName(path)} (expected {config2.CheckPermissions})");
                }
            }

            if (warnings.Count > 0)
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Warning, string.Join("; ", warnings));
            else
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Ok, $"OK ({results.Count} files)");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.FileIntegrity, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
