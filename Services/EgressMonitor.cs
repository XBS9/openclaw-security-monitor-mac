using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Verifies and auto-manages the OPENCLAW_EGRESS pf anchor on macOS every EgressCheckInterval seconds.
/// Automatically switches between two egress modes based on gateway lock state:
///
///   • Allowlist mode (gateway locked / hardened plist active):
///     Only approved domains (Anthropic, Telegram, GitHub, etc.) are permitted outbound.
///
///   • Denylist mode (gateway unlocked / normal operation):
///     All outbound traffic permitted except known-bad exfil/OAST callback domains.
///
/// NOPASSWD sudoers entries for both scripts allow passwordless auto-reapplication.
/// Mode is tracked via ~/.openclaw/egress-mode marker file written by each script.
///
/// macOS adaptation: pfctl instead of iptables.
///   sudo pfctl -sr | grep openclaw  → check if anchor is active
///   sudo pfctl -a openclaw -sr     → check rules in anchor
/// </summary>
public class EgressMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    public EgressMonitor(ICommandService cmd, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.EgressCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>
    /// Returns the egress mode the gateway's current lock state requires:
    /// "allowlist" when the hardened plist is active (ProcessType=Background present),
    /// "denylist" when the unlocked / stock plist is active.
    /// </summary>
    private async Task<string> GetExpectedModeAsync()
    {
        var basePath = PathUtils.Expand(_settings.ServiceBasePath);
        var label    = _settings.GatewayLabel;
        var (_, output, _) = await _cmd.RunAsync(
            $"grep -c 'ProcessType' \"{basePath}/{label}.plist\" 2>/dev/null || echo 0");
        return int.TryParse(output.Trim(), out var count) && count > 0
            ? "allowlist"
            : "denylist";
    }

    private async Task<string> GetCurrentModeAsync()
    {
        var modePath = PathUtils.Expand(_settings.EgressModePath);
        var (_, output, _) = await _cmd.RunAsync(
            $"cat \"{modePath}\" 2>/dev/null || echo unknown");
        return output.Trim();
    }

    /// <summary>
    /// Returns the number of rules in the openclaw pf anchor, or -1 if sudo is unavailable.
    /// Uses a pre-flight sudo check so we can distinguish "0 rules" from "sudo requires password".
    /// (Piping pfctl to wc -l masks sudo exit codes, so we probe sudo separately first.)
    /// </summary>
    private async Task<int> GetRuleCountAsync()
    {
        // Pre-flight: check if passwordless sudo is available. If not, report -1 immediately.
        var (sudoExit, _, _) = await _cmd.RunAsync("sudo -n true 2>/dev/null");
        if (sudoExit != 0) return -1;

        var (_, output, _) = await _cmd.RunAsync(
            "sudo -n pfctl -a openclaw -sr 2>/dev/null | wc -l");
        return int.TryParse(output.Trim(), out var n) ? Math.Max(0, n) : -1;
    }

    private async Task ApplyModeAsync(string mode)
    {
        var script = mode == "allowlist"
            ? PathUtils.Expand(_settings.EgressScriptPath)
            : PathUtils.Expand(_settings.EgressDenylistScriptPath);
        await _cmd.RunAsync($"sudo -n \"{script}\" 2>/dev/null");
    }

    private async Task CheckAsync()
    {
        try
        {
            var expectedMode = await GetExpectedModeAsync();
            var currentMode  = await GetCurrentModeAsync();
            var ruleCount    = await GetRuleCountAsync();

            if (ruleCount < 0)
            {
                _hub.Report(MonitorHub.Egress, MonitorState.Warning,
                    "Egress not enforced — add NOPASSWD sudoers entry for pfctl to enable");
                return;
            }

            // In denylist mode the anchor is intentionally cleared (0 rules = open traffic).
            // "anchor missing" only means a problem in allowlist mode where rules must be loaded.
            bool anchorMissing = expectedMode == "allowlist" && ruleCount == 0;
            bool modeMismatch  = currentMode != expectedMode;

            if (anchorMissing || modeMismatch)
            {
                var reason = modeMismatch
                    ? $"mode {currentMode}→{expectedMode}"
                    : "anchor empty";
                _hub.Report(MonitorHub.Egress, MonitorState.Warning, $"Reapplying ({reason})");

                await ApplyModeAsync(expectedMode);

                ruleCount    = await GetRuleCountAsync();
                currentMode  = await GetCurrentModeAsync();
                anchorMissing = expectedMode == "allowlist" && ruleCount == 0;
            }

            var modeLabel = expectedMode == "allowlist"
                ? "allowlist [locked]"
                : "denylist [unlocked]";

            if (!anchorMissing)
            {
                var ruleInfo = expectedMode == "allowlist"
                    ? $" · {ruleCount} rules"
                    : "";
                _hub.Report(MonitorHub.Egress, MonitorState.Ok, $"{modeLabel}{ruleInfo}");
            }
            else
            {
                // Only allowlist mode can reach here (denylist never sets anchorMissing).
                _hub.Report(MonitorHub.Egress, MonitorState.Alert,
                    "Allowlist missing — reapply failed");
                await _killSwitch.FireAsync("EgressMonitor",
                    "Egress allowlist missing after reapply",
                    "pf openclaw anchor is empty in locked mode and reapplication failed");
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Egress, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
