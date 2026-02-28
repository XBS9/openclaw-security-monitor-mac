using System.IO;
using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// SHA-256 hashes the openclaw Node.js binary on first run (baseline),
/// then re-checks every BinaryIntegrityCheckInterval seconds.
///
/// An unexpected hash change indicates the binary may have been replaced
/// by a malicious version (supply-chain or local tampering attack).
///
/// Does not fire the kill switch on change — legitimate npm updates also
/// change the binary. Instead shows Alert state so the user can review.
/// The baseline resets on monitor restart, establishing a new trusted state
/// after a known-good update.
/// </summary>
public class BinaryIntegrityMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private string? _baselineHash;
    private string? _binaryPath;

    public BinaryIntegrityMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(20), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.BinaryIntegrityCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            // Locate the openclaw binary (symlink in npm bin dir → actual Node script)
            if (_binaryPath == null)
            {
                var npmPath = PathUtils.ExpandFull(_settings.NpmGlobalPath);
                var candidates = new[]
                {
                    Path.Combine(npmPath, "bin", "openclaw"),
                    "/opt/homebrew/bin/openclaw",
                    "/usr/local/bin/openclaw",
                };
                _binaryPath = candidates.FirstOrDefault(File.Exists);
            }

            if (_binaryPath == null)
            {
                _hub.Report(MonitorHub.BinaryIntegrity, MonitorState.Warning,
                    "openclaw binary not found");
                return;
            }

            // shasum -a 256 outputs "hash  filename" — awk extracts just the hash
            var (_, output, _) = await _cmd.RunAsync(
                $"shasum -a 256 \"{_binaryPath}\" 2>/dev/null | awk '{{print $1}}'");
            var hash = output.Trim();

            if (string.IsNullOrEmpty(hash))
            {
                _hub.Report(MonitorHub.BinaryIntegrity, MonitorState.Warning,
                    "Could not hash binary");
                return;
            }

            var shortHash = hash[..Math.Min(12, hash.Length)];

            if (_baselineHash == null)
            {
                _baselineHash = hash;
                _hub.Report(MonitorHub.BinaryIntegrity, MonitorState.Ok,
                    $"Baseline: {shortHash}…");
                return;
            }

            if (_baselineHash != hash)
            {
                var oldShort = _baselineHash[..Math.Min(12, _baselineHash.Length)];
                _hub.Report(MonitorHub.BinaryIntegrity, MonitorState.Alert,
                    $"Binary changed! {oldShort}…→{shortHash}…");
                // Update baseline so status doesn't stay Alert forever for the same change
                _baselineHash = hash;
                return;
            }

            _hub.Report(MonitorHub.BinaryIntegrity, MonitorState.Ok,
                $"OK ({shortHash}…)");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.BinaryIntegrity, MonitorState.Warning,
                $"Check failed: {ex.Message}");
        }
    }
}
