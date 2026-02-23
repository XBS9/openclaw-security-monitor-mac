using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Polls gateway health every StatusPollInterval seconds.
/// Fires the kill switch if the gateway mode flips to Unknown on two consecutive reads.
/// </summary>
public class StatusMonitor : IDisposable
{
    private readonly GatewayService _gateway;
    private readonly KillSwitch _killSwitch;
    private readonly TraySettings _settings;
    private readonly MonitorHub _hub;

    private CancellationTokenSource? _cts;
    private int _disposed;

    private GatewayMode _lastKnownMode = GatewayMode.Unknown;
    private bool _firstRun = true;
    private int _consecutiveUnknown;

    public event Action<GatewayStatus>? StatusChanged;

    public StatusMonitor(GatewayService gateway, KillSwitch killSwitch, TraySettings settings, MonitorHub hub)
    {
        _gateway = gateway;
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
            await PollAsync();
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.StatusPollInterval));
            while (await timer.WaitForNextTickAsync(ct))
                await PollAsync();
        }
        catch (OperationCanceledException) { }
    }

    private async Task PollAsync()
    {
        try
        {
            var status = await _gateway.GetStatusAsync();
            StatusChanged?.Invoke(status);

            _hub.Report(MonitorHub.Gateway,
                status.IsRunning ? MonitorState.Ok : MonitorState.Alert,
                status.IsRunning
                    ? $"Active — {status.Mode}{(!string.IsNullOrEmpty(status.Uptime) ? $" ({status.Uptime})" : "")}"
                    : "Stopped");

            if (_firstRun)
            {
                _lastKnownMode = status.Mode;
                _firstRun = false;
                return;
            }

            if (status.Mode == GatewayMode.Unknown)
            {
                _consecutiveUnknown++;
                // Only fire after 2 consecutive unknowns when we previously had a known mode.
                // _lastKnownMode is only updated when mode is not Unknown, so this works correctly.
                if (_consecutiveUnknown >= 2 && _lastKnownMode != GatewayMode.Unknown)
                {
                    await _killSwitch.FireAsync("StatusMonitor",
                        "Unknown plist detected",
                        $"Gateway mode changed from {_lastKnownMode} to Unknown — possible custom plist");
                }
            }
            else
            {
                _consecutiveUnknown = 0;
                // Only track the last *known* mode so the Unknown check above works.
                _lastKnownMode = status.Mode;
            }
        }
        catch (Exception ex)
        {
            _hub.Report(MonitorHub.Gateway, MonitorState.Warning, $"Check failed: {ex.Message}");
        }
    }
}
