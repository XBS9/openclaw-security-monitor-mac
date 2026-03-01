using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Detects tampering with critical files via SHA-256 hashing.
///
/// v1.6.0 enhancements:
///   • Event-driven detection via FileSystemWatcher (millisecond latency) in addition to
///     the 60-second periodic poll. FSW uses kqueue/FSEvents on macOS internally.
///     500 ms debounce coalesces rapid multi-event saves (e.g. vim's swap+rename).
///   • Persistent baseline stored in ~/.openclaw/baselines/file-integrity.json with a
///     SHA-256 integrity sidecar. Changes made while the monitor was offline are detected
///     on startup rather than silently absorbed into a fresh in-memory baseline.
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

    // FileSystemWatcher state
    private List<FileSystemWatcher>? _watchers;
    private readonly Dictionary<string, CancellationTokenSource> _debouncers = new();
    private readonly object _debounceLock = new();

    public FileIntegrityMonitor(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
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
        DisposeWatchers();
    }

    // -------------------------------------------------------------------------
    // Main polling loop
    // -------------------------------------------------------------------------

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(5, _settings.FileIntegrityInterval)), ct);
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
            var files    = _settings.MonitoredFiles;
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
                await EstablishBaselineAsync(results);
                return;
            }

            var warnings   = new List<string>();
            var baselineDirty = false;

            foreach (var (path, current) in results)
            {
                if (!_baselines.TryGetValue(path, out var baseline))
                {
                    _baselines[path] = current;
                    baselineDirty = true;
                    continue;
                }

                if (!string.IsNullOrEmpty(baseline.Hash) && !string.IsNullOrEmpty(current.Hash)
                    && baseline.Hash != current.Hash)
                {
                    if (current.IsCritical)
                    {
                        _baselines[path] = current;
                        BaselinePersistence.SaveDict("file-integrity", _baselines);
                        _hub.Report(MonitorHub.FileIntegrity, MonitorState.Alert, $"TAMPERED: {path}");
                        var oldHash = baseline.Hash.Length > 12 ? baseline.Hash[..12] + "..." : baseline.Hash;
                        var newHash = current.Hash.Length > 12 ? current.Hash[..12] + "..." : current.Hash;
                        await _killSwitch.FireAsync("FileIntegrityMonitor",
                            $"Critical file modified: {path}",
                            $"SHA-256 changed from {oldHash} to {newHash}");
                        return;
                    }
                    // Non-critical change — update baseline and warn.
                    _baselines[path] = current;
                    baselineDirty    = true;
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

            if (baselineDirty)
                BaselinePersistence.SaveDict("file-integrity", _baselines);

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

    // -------------------------------------------------------------------------
    // Baseline establishment (first run or persistent load)
    // -------------------------------------------------------------------------

    private async Task EstablishBaselineAsync(Dictionary<string, FileBaseline> currentResults)
    {
        var loadResult = BaselinePersistence.TryLoadDict("file-integrity", out var saved);

        if (loadResult == BaselinePersistence.LoadResult.Tampered)
        {
            // Re-establish from current state and alert
            foreach (var (path, baseline) in currentResults)
                _baselines[path] = baseline;
            _baselineEstablished = true;
            BaselinePersistence.SaveDict("file-integrity", _baselines);
            _hub.Report(MonitorHub.FileIntegrity, MonitorState.Alert,
                "Baseline tampered — re-establishing from current state");
            SetupFileSystemWatchers();
            return;
        }

        if (loadResult == BaselinePersistence.LoadResult.Ok && saved != null)
        {
            // Merge persisted baseline; new files since last run absorbed silently
            foreach (var (path, baseline) in saved)
                _baselines[path] = baseline;

            // Check for hash changes made while the monitor was offline
            string? criticalTamperedPath = null;
            FileBaseline? criticalOld = null, criticalNew = null;
            var changedFiles = new List<string>();

            foreach (var (path, current) in currentResults)
            {
                if (!_baselines.TryGetValue(path, out var baseline))
                {
                    _baselines[path] = current; // new file since last run
                    continue;
                }

                if (!string.IsNullOrEmpty(baseline.Hash) && !string.IsNullOrEmpty(current.Hash)
                    && baseline.Hash != current.Hash)
                {
                    _baselines[path] = current;
                    if (current.IsCritical)
                    {
                        criticalTamperedPath = path;
                        criticalOld          = baseline;
                        criticalNew          = current;
                        break; // handle below
                    }
                    var shortPath = path.Length > 40 ? "..." + path[^37..] : path;
                    changedFiles.Add(shortPath);
                }
            }

            _baselineEstablished = true;
            BaselinePersistence.SaveDict("file-integrity", _baselines);
            SetupFileSystemWatchers();

            if (criticalTamperedPath != null)
            {
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Alert,
                    $"TAMPERED since last run: {criticalTamperedPath}");
                var oldHash = criticalOld?.Hash is { Length: > 12 } oh ? oh[..12] + "..." : criticalOld?.Hash ?? "";
                var newHash = criticalNew?.Hash is { Length: > 12 } nh ? nh[..12] + "..." : criticalNew?.Hash ?? "";
                await _killSwitch.FireAsync("FileIntegrityMonitor",
                    $"Critical file modified since last run: {criticalTamperedPath}",
                    $"SHA-256 changed from {oldHash} to {newHash}");
                return;
            }

            if (changedFiles.Count > 0)
            {
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Warning,
                    $"Changed since last run: {string.Join("; ", changedFiles)}");
                return;
            }

            _hub.Report(MonitorHub.FileIntegrity, MonitorState.Ok,
                $"Baseline loaded ({currentResults.Count} files)");
            return;
        }

        // First run — establish and persist
        foreach (var (path, baseline) in currentResults)
            _baselines[path] = baseline;
        _baselineEstablished = true;
        BaselinePersistence.SaveDict("file-integrity", _baselines);
        _hub.Report(MonitorHub.FileIntegrity, MonitorState.Ok,
            $"Baseline set ({currentResults.Count} files)");
        SetupFileSystemWatchers();
    }

    // -------------------------------------------------------------------------
    // FileSystemWatcher — event-driven detection
    // -------------------------------------------------------------------------

    private void SetupFileSystemWatchers()
    {
        DisposeWatchers();
        _watchers = [];

        var dirs = _settings.MonitoredFiles
            .Select(f => PathUtils.Expand(f.Path))
            .Where(p => !string.IsNullOrEmpty(p))
            .Select(p => System.IO.Path.GetDirectoryName(p)!)
            .Where(d => !string.IsNullOrEmpty(d))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    EnableRaisingEvents = true
                };
                watcher.Changed += OnFileSystemEvent;
                watcher.Created += OnFileSystemEvent;
                watcher.Deleted += OnFileSystemEvent;
                _watchers.Add(watcher);
            }
            catch { /* directory may be inaccessible */ }
        }
    }

    private void OnFileSystemEvent(object sender, FileSystemEventArgs e)
    {
        if (!_baselineEstablished) return;
        if (_disposed != 0) return;

        // Only react to files in our monitored list
        var config = _settings.MonitoredFiles
            .FirstOrDefault(f =>
                PathUtils.Expand(f.Path).Equals(e.FullPath, StringComparison.Ordinal));
        if (config == null) return;

        // 500 ms debounce: coalesces rapid editor save events (vim swap+rename, etc.)
        lock (_debounceLock)
        {
            if (_debouncers.TryGetValue(e.FullPath, out var existing))
            {
                existing.Cancel();
                existing.Dispose();
            }

            var cts   = new CancellationTokenSource();
            var token = cts.Token;
            _debouncers[e.FullPath] = cts;

            _ = Task.Delay(500, token).ContinueWith(
                async t =>
                {
                    if (t.IsCanceled) return;
                    lock (_debounceLock) _debouncers.Remove(e.FullPath);
                    await CheckSingleFileAsync(e.FullPath, config);
                },
                CancellationToken.None,
                TaskContinuationOptions.NotOnCanceled,
                TaskScheduler.Default);
        }
    }

    /// <summary>
    /// Re-hashes a single file triggered by FSW and compares to the in-memory baseline.
    /// Called after the 500 ms debounce delay.
    /// </summary>
    private async Task CheckSingleFileAsync(string expandedPath, MonitoredFileConfig config)
    {
        if (!_baselineEstablished || _disposed != 0) return;

        try
        {
            var batchCmd = $"echo \"HASH:{config.Path}:$(shasum -a 256 \"{expandedPath}\" 2>/dev/null | awk '{{print $1}}')\"";
            var (_, output, _) = await _cmd.RunAsync(batchCmd);
            if (string.IsNullOrEmpty(output)) return;

            var parts = output.Trim().Split(':', 3);
            if (parts.Length < 3) return;

            var currentHash = parts[2].Trim();
            if (!_baselines.TryGetValue(config.Path, out var baseline)) return;
            if (string.IsNullOrEmpty(baseline.Hash) || string.IsNullOrEmpty(currentHash)) return;
            if (baseline.Hash == currentHash) return;

            var current = new FileBaseline
            {
                Path       = config.Path,
                Hash       = currentHash,
                IsCritical = config.Critical
            };
            _baselines[config.Path] = current;
            BaselinePersistence.SaveDict("file-integrity", _baselines);

            if (config.Critical)
            {
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Alert, $"TAMPERED: {config.Path}");
                var oldHash = baseline.Hash.Length > 12 ? baseline.Hash[..12] + "..." : baseline.Hash;
                var newHash = currentHash.Length > 12 ? currentHash[..12] + "..." : currentHash;
                await _killSwitch.FireAsync("FileIntegrityMonitor",
                    $"Critical file modified: {config.Path}",
                    $"SHA-256 changed from {oldHash} to {newHash}");
            }
            else
            {
                var shortPath = config.Path.Length > 40 ? "..." + config.Path[^37..] : config.Path;
                _hub.Report(MonitorHub.FileIntegrity, MonitorState.Warning, $"Changed: {shortPath}");
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Cleanup
    // -------------------------------------------------------------------------

    private void DisposeWatchers()
    {
        if (_watchers == null) return;
        foreach (var w in _watchers)
        {
            try
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            catch { }
        }
        _watchers = null;

        lock (_debounceLock)
        {
            foreach (var cts in _debouncers.Values)
            {
                try { cts.Cancel(); cts.Dispose(); } catch { }
            }
            _debouncers.Clear();
        }
    }
}
