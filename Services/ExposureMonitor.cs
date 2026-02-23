using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Checks two public-exposure vectors every ExposureCheckInterval seconds:
///
///   1. Gateway bind address (openclaw.json → gateway.bind)
///      "loopback" / "127.0.0.1" → OK (localhost only)
///      "0.0.0.0" or absent      → Warning (entire LAN can reach the gateway)
///      The default OpenClaw bind is 0.0.0.0 — 30,000+ instances were found exposed
///      to the internet because of this (Bitsight / Bitdefender audits, Feb 2026).
///
///   2. Tailscale Funnel active on the gateway port
///      Tailscale Funnel makes the endpoint reachable from the public internet.
///      Tailscale Serve (tailnet-only) is the safer option for remote access.
///      Exception: ElevenLabs ConvAI callbacks require a public URL, so Funnel may
///      be intentional — the Warning is informational in that case.
///
/// Parse strategy: python3 (always present on macOS) reads openclaw.json safely
/// without requiring jq or shell string manipulation of arbitrary JSON.
/// </summary>
public class ExposureMonitor : IDisposable
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    public ExposureMonitor(ICommandService cmd, TraySettings settings, MonitorHub hub)
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
            await Task.Delay(TimeSpan.FromSeconds(12), ct);
            await CheckAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.ExposureCheckInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await CheckAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task CheckAsync()
    {
        try
        {
            var configPath = PathUtils.Expand(_settings.OpenClawConfigPath);
            var port       = _settings.GatewayPort;

            // Read gateway.bind from openclaw.json.
            // python3 handles JSONC/comments gracefully — OpenClaw config is plain JSON.
            // Falls back to "0.0.0.0" when the key is absent (OpenClaw's default).
            string bindCmd;
            if (File.Exists(configPath))
            {
                // Single-quoted python avoids any bash quoting issues with the path
                bindCmd =
                    $"python3 -c \"import json; " +
                    $"d=json.load(open('{configPath}')); " +
                    $"print(d.get('gateway',{{}}).get('bind','0.0.0.0'))\" 2>/dev/null " +
                    $"|| echo '0.0.0.0'";
            }
            else
            {
                bindCmd = "echo 'config-missing'";
            }

            // Check Tailscale Funnel for the gateway port.
            // 'tailscale funnel status' exits non-zero when funnel is off, so we normalise.
            // If tailscale is not installed the command fails → FUNNEL_OFF (safe default).
            var funnelCmd =
                $"tailscale funnel status 2>/dev/null | grep -q '{port}' " +
                $"&& echo FUNNEL_ON || echo FUNNEL_OFF";

            var (_, bindOutput,   _) = await _cmd.RunAsync(bindCmd);
            var (_, funnelOutput, _) = await _cmd.RunAsync(funnelCmd);

            var bind      = bindOutput.Trim();
            var funnelOn  = funnelOutput.Trim() == "FUNNEL_ON";

            var issues = new List<string>();

            // ── Bind address check ──────────────────────────────────────────
            bool safeBinding = bind is "loopback" or "127.0.0.1";
            bool missingConfig = bind == "config-missing";

            if (missingConfig)
            {
                issues.Add("openclaw.json not found");
            }
            else if (!safeBinding)
            {
                // "0.0.0.0" = LAN-wide; anything else is also non-loopback
                var label = string.IsNullOrEmpty(bind) ? "default(0.0.0.0)" : bind;
                issues.Add($"bind={label} — LAN-exposed");
            }

            // ── Tailscale Funnel check ───────────────────────────────────────
            if (funnelOn)
                issues.Add($"Tailscale Funnel active on :{port} (public internet)");

            // ── Report ───────────────────────────────────────────────────────
            if (issues.Count == 0)
            {
                _hub.Report(MonitorHub.Exposure, MonitorState.Ok,
                    $"bind={bind} · no public funnel");
            }
            else
            {
                _hub.Report(MonitorHub.Exposure, MonitorState.Warning,
                    string.Join("; ", issues));
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Exposure, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
