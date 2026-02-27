using System.Collections.Generic;
using System.IO;
using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Tracks how long ago the gateway token was last rotated, using the mtime of
/// device-auth.json (or device.json / gateway.env as fallbacks) as a proxy.
/// Warns when the token is older than TokenMaxAgeDays.
///
/// Also checks two additional conditions on every cycle:
///   1. Token sync: gateway.auth.token must equal gateway.remote.token in openclaw.json.
///      A mismatch causes "gateway token mismatch" errors in the TUI/CLI. Fix: run oc-sync.
///   2. Stale oauth.json: removed in OpenClaw v2026.2.23; leftover file is a data-exposure risk.
///
/// Background: CVE-2026-25253 can silently exfiltrate the gateway token via a
/// single malicious webpage. Periodic rotation limits the exposure window even if
/// an exfiltration went undetected. The official recommendation is to rotate every
/// 30 days via: openclaw auth rotate-token
///
/// The token age is also reset automatically after any successful OpenClaw upgrade
/// that regenerates device credentials, so the monitor naturally resets its clock
/// when that happens.
///
/// macOS: stat -f "%m" returns the mtime as a Unix epoch integer.
/// Checks run at TokenAgeCheckInterval seconds (default: every 6 hours).
/// </summary>
public class TokenAgeMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    // Files checked in priority order — we take the NEWEST mtime as "last rotated".
    // device-auth.json is written on every successful auth; gateway.env on gateway init.
    private static readonly string[] CandidateFiles =
    [
        "~/.openclaw/identity/device-auth.json",
        "~/.openclaw/identity/device.json",
        "~/.openclaw/gateway.env",
    ];

    public TokenAgeMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(15), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.TokenAgeCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var warnings = new List<string>();

            // ── 1. Stale oauth.json check ────────────────────────────────────
            // oauth.json was removed in OpenClaw v2026.2.23 (exposed PKCE verifiers).
            // A leftover file is a minor data-exposure risk and should be deleted.
            var oauthPath = PathUtils.Expand("~/.openclaw/oauth.json");
            var (_, oauthOut, _) = await _cmd.RunAsync(
                $"[ -f \"{oauthPath}\" ] && echo EXISTS || echo GONE");
            if (oauthOut.Trim() == "EXISTS")
                warnings.Add("oauth.json found — delete it (stale, v2026.2.23+)");

            // ── 2. Token sync check ──────────────────────────────────────────
            // gateway.auth.token (what the gateway expects) must equal
            // gateway.remote.token (what the TUI/CLI sends). A mismatch causes
            // "unauthorized: gateway token mismatch" on every TUI connection.
            // Cause: Security Monitor restarts can rotate auth.token without
            // updating remote.token. Fix: run oc-sync.
            // Use ExpandFull() so python3 gets the real filesystem path, not "$HOME/...".
            var configFullPath = PathUtils.ExpandFull(_settings.OpenClawConfigPath);
            if (File.Exists(configFullPath))
            {
                var (_, syncOut, _) = await _cmd.RunAsync(
                    $"python3 -c \"" +
                    $"import json; c=json.load(open('{configFullPath}')); " +
                    $"a=c.get('gateway',{{}}).get('auth',{{}}).get('token',''); " +
                    $"r=c.get('gateway',{{}}).get('remote',{{}}).get('token',''); " +
                    $"print('MATCH' if a and r and a==r else 'MISMATCH')\" 2>/dev/null || echo UNKNOWN");
                if (syncOut.Trim() == "MISMATCH")
                    warnings.Add("Token mismatch — run: oc-sync");
            }

            // ── 3. Token age check ───────────────────────────────────────────
            // Emit the mtime (Unix epoch seconds) for each existing candidate file.
            // "0" is emitted when a file does not exist so it is ignored in parsing.
            var cmds = CandidateFiles.Select(raw =>
            {
                var path = PathUtils.Expand(raw);
                return $"[ -f \"{path}\" ] && stat -f \"%m\" \"{path}\" || echo 0";
            });

            var (_, output, _) = await _cmd.RunAsync(string.Join("; ", cmds));

            long latestEpoch = 0;
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (long.TryParse(line.Trim(), out var ts) && ts > latestEpoch)
                    latestEpoch = ts;
            }

            if (latestEpoch == 0)
            {
                warnings.Add("Token files not found — paired?");
            }
            else
            {
                var tokenDate = DateTimeOffset.FromUnixTimeSeconds(latestEpoch).LocalDateTime;
                var ageDays   = (int)(DateTime.Now - tokenDate).TotalDays;
                var maxDays   = _settings.TokenMaxAgeDays;

                if (ageDays > maxDays)
                    warnings.Add($"Token {ageDays}d old (>{maxDays}d) — rotate");
                else if (warnings.Count == 0)
                {
                    // All clean — report age status
                    var remaining = maxDays - ageDays;
                    _hub.Report(MonitorHub.TokenAge, MonitorState.Ok,
                        $"Token {ageDays}d old · rotate in {remaining}d");
                    return;
                }
                // else: has other warnings but age is fine — omit age from message
            }

            if (warnings.Count > 0)
                _hub.Report(MonitorHub.TokenAge, MonitorState.Warning,
                    string.Join(" · ", warnings));
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.TokenAge, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
