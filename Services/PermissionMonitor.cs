using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Verifies that ~/.openclaw/ is mode 700 and that all known sensitive files inside
/// it are mode 600. Auto-corrects wrong permissions on every check cycle.
///
/// Background: the February 2026 Vidar infostealer campaign specifically targeted
/// ~/.openclaw/ — world-readable configs (default on macOS) allowed the stealer to
/// exfiltrate gateway tokens, device keys, and soul/memory files without privilege
/// escalation. Directory and file permission hardening is the primary mitigation.
///
/// macOS: stat -f '%Lp' returns the octal permission bits (e.g. "700", "600").
/// </summary>
public class PermissionMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    // Known sensitive files that must be 600.
    // Checked on every cycle; auto-fixed if wrong.
    private static readonly string[] SensitiveFiles =
    [
        "~/.openclaw/openclaw.json",
        "~/.openclaw/gateway.env",
        "~/.openclaw/.credentials.json",
        "~/.openclaw/identity/device.json",
        "~/.openclaw/identity/device-auth.json",
        "~/.openclaw/agents/main/agent/auth-profiles.json",
        "~/.openclaw/agents/main/agent/auth.json",
    ];

    public PermissionMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
    {
        _cmd = cmd;
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
            await Task.Delay(TimeSpan.FromSeconds(8), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.PermissionCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dir  = Path.Combine(home, ".openclaw");

            // Batch: check dir + all sensitive files in a single shell invocation.
            // "missing" is emitted when stat finds no file — those entries are skipped.
            var cmds = new List<string>
            {
                $"echo \"DIR:{dir}:$(stat -f '%Lp' \"{dir}\" 2>/dev/null || echo missing)\""
            };

            foreach (var raw in SensitiveFiles)
            {
                var path = PathUtils.Expand(raw);
                cmds.Add($"echo \"FILE:{raw}:$(stat -f '%Lp' \"{path}\" 2>/dev/null || echo missing)\"");
            }

            var (_, output, _) = await _cmd.RunAsync(string.Join("; ", cmds));

            var fixes  = new List<string>();   // chmod commands to run
            var fixedNames = new List<string>(); // human-readable names for the report
            var checked_ = 0;

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split(':', 3);
                if (parts.Length < 3) continue;

                var type     = parts[0];
                var rawPath  = parts[1].Trim();
                var perm     = parts[2].Trim();

                if (perm == "missing") continue;   // file doesn't exist yet — skip

                checked_++;
                var expected = type == "DIR" ? "700" : "600";
                var fullPath = type == "DIR" ? rawPath : PathUtils.Expand(rawPath);

                if (perm != expected)
                {
                    fixes.Add($"/bin/chmod {expected} \"{fullPath}\"");
                    fixedNames.Add(Path.GetFileName(fullPath));
                }
            }

            if (fixes.Count > 0)
            {
                // Auto-fix: run all chmod commands in one shell invocation
                await _cmd.RunAsync(string.Join("; ", fixes));
                _hub.Report(MonitorHub.Permissions, MonitorState.Warning,
                    $"Fixed permissions: {string.Join(", ", fixedNames)}");
                return;
            }

            _hub.Report(MonitorHub.Permissions, MonitorState.Ok,
                $"700 dir · {checked_ - 1} files at 600");
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Permissions, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
