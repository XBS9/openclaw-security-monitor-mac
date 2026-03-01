using System.Collections.ObjectModel;
using System.Text.Json;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;
using OpenClawSecurityMonitorMac.Services;

namespace OpenClawSecurityMonitorMac.ViewModels;

public partial class MonitorStatusItem : ObservableObject
{
    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private string _status = "Starting...";

    [ObservableProperty]
    private Color _dotColor = Colors.Gray;

    [ObservableProperty]
    private string _lastChecked = "";
}

public partial class DashboardViewModel : ObservableObject
{
    private readonly KillSwitch _killSwitch;
    private readonly GatewayService _gateway;
    private readonly TraySettings _settings;
    private readonly Action _openLogAction;
    private readonly Action _openPatchAction;
    private readonly Action _openSettingsAction;
    private readonly Action _openAboutAction;
    private readonly Action _exitAction;
    private readonly Action _togglePauseAction;
    private readonly Func<bool> _isPausedFunc;

    private GatewayStatus _currentStatus = new();

    [ObservableProperty]
    private string _statusTitle = "Checking...";

    [ObservableProperty]
    private string _statusDetail = "";

    [ObservableProperty]
    private Color _statusColor = Colors.Gray;

    [ObservableProperty]
    private string _scoreDisplay = "--";

    [ObservableProperty]
    private IBrush _scoreBrush = Brushes.Gray;

    [ObservableProperty]
    private string _lockButtonText = "Lock Gateway";

    [ObservableProperty]
    private string _pauseButtonText = "Pause Monitors";

    [ObservableProperty]
    private bool _isAlertVisible;

    [ObservableProperty]
    private string _alertBannerText = "";

    [ObservableProperty]
    private string _syncStatusText = "";

    [ObservableProperty]
    private bool _isSyncStatusVisible;

    [ObservableProperty]
    private IBrush _syncStatusBrush = Brushes.Gray;

    public ObservableCollection<MonitorStatusItem> MonitorStatuses { get; } = new();
    public ObservableCollection<string> RecentEvents { get; } = new();
    public ObservableCollection<string> ActiveConnections { get; } = new();

    [ObservableProperty]
    private bool _isConnectionsVisible;

    [ObservableProperty]
    private string _exportStatusText = "";

    [ObservableProperty]
    private string _scoreSparkline = "";

    [ObservableProperty]
    private string _versionText = GetVersionText();

    private readonly List<double> _scoreHistory = new();
    private const string SparkChars = "▁▂▃▄▅▆▇█";

    private static string GetVersionText()
    {
        var v = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        return v != null
            ? $"OpenClaw Security Monitor v{v.Major}.{v.Minor}.{v.Build} (macOS)"
            : "OpenClaw Security Monitor (macOS)";
    }

    public DashboardViewModel(
        KillSwitch killSwitch,
        GatewayService gateway,
        TraySettings settings,
        Action openLogAction,
        Action openPatchAction,
        Action openSettingsAction,
        Action openAboutAction,
        Action exitAction,
        Action togglePauseAction,
        Func<bool> isPausedFunc)
    {
        _killSwitch = killSwitch;
        _gateway = gateway;
        _settings = settings;
        _openLogAction = openLogAction;
        _openPatchAction = openPatchAction;
        _openSettingsAction = openSettingsAction;
        _openAboutAction = openAboutAction;
        _exitAction = exitAction;
        _togglePauseAction = togglePauseAction;
        _isPausedFunc = isPausedFunc;

        PauseButtonText = _isPausedFunc() ? "Resume Monitors" : "Pause Monitors";

        InitMonitorStatuses();
        RefreshEvents();
    }

    private void InitMonitorStatuses()
    {
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Gateway Health",      Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "File Integrity",      Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Alert Log",           Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Egress Rules",        Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Auth Patches",        Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Namespace Isolation", Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Config Permissions",  Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Network Exposure",    Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Token Age",           Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Launch Agents",       Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Binary Integrity",    Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "TCC Permissions",     Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Sudo Activity",       Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "System Posture",      Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "Cron Jobs",           Status = "Starting..." });
        MonitorStatuses.Add(new MonitorStatusItem { Name = "System Extensions",   Status = "Starting..." });
    }

    public void UpdateStatus(GatewayStatus status)
    {
        _currentStatus = status;

        if (_killSwitch.IsEngaged)
        {
            // Check actual plist state — the gateway may have been manually recovered
            // (e.g. via `openclaw gateway install --force`) without clearing the kill switch.
            // Show what is actually true rather than always claiming "Gateway Locked".
            bool actuallyLocked = status.Mode == GatewayMode.Locked;

            StatusTitle  = actuallyLocked
                ? "ALERT — Gateway Locked"
                : "ALERT — Running (unreviewed)";
            StatusDetail = actuallyLocked
                ? "Kill switch triggered. Review alerts before unlocking."
                : "Alert unreviewed. Gateway was manually recovered — click Unlock to acknowledge.";
            StatusColor  = Color.FromRgb(220, 50, 50);
            ScoreDisplay = actuallyLocked ? "3.3" : "--";
            ScoreBrush   = new SolidColorBrush(Color.FromRgb(200, 80, 80));
            LockButtonText = actuallyLocked ? "Unlock Gateway" : "Acknowledge Alert";

            var lastEvt = _killSwitch.Events.LastOrDefault();
            AlertBannerText  = lastEvt != null
                ? $"⚠ {lastEvt.Trigger}: {lastEvt.Details}"
                : "⚠ Security alert triggered";
            IsAlertVisible = true;
        }
        else if (!status.IsRunning)
        {
            StatusTitle  = "Gateway Stopped";
            StatusDetail = "The OpenClaw gateway is not running.";
            StatusColor  = Color.FromRgb(180, 60, 60);
            ScoreDisplay = "--";
            ScoreBrush   = Brushes.Gray;
            LockButtonText = "Start Gateway";
            IsAlertVisible = false;
        }
        else
        {
            var modeStr    = status.Mode switch
            {
                GatewayMode.Unlocked => "Unlocked",
                GatewayMode.Locked   => "Locked",
                _                    => "Unknown"
            };
            var uptimeStr = !string.IsNullOrEmpty(status.Uptime) ? $" for {status.Uptime}" : "";

            StatusTitle  = $"Gateway {modeStr}";
            StatusDetail = $"Running{uptimeStr} on port {status.Port}";
            StatusColor  = status.Mode == GatewayMode.Unlocked
                ? Color.FromRgb(50, 180, 50)
                : Color.FromRgb(240, 180, 20);
            ScoreDisplay = status.SecurityScore > 0 ? status.SecurityScore.ToString("F1") : "--";
            ScoreBrush   = status.Mode == GatewayMode.Unlocked
                ? new SolidColorBrush(Color.FromRgb(80, 220, 80))
                : new SolidColorBrush(Color.FromRgb(240, 200, 80));
            LockButtonText = status.Mode == GatewayMode.Unlocked ? "Lock Gateway" : "Unlock Gateway";
            IsAlertVisible = false;
        }

        RefreshEvents();

        if (status.SecurityScore > 0)
            RecordScore(status.SecurityScore);
    }

    private void RecordScore(double score)
    {
        _scoreHistory.Add(score);
        if (_scoreHistory.Count > 24) _scoreHistory.RemoveAt(0);

        if (_scoreHistory.Count < 2) { ScoreSparkline = ""; return; }
        var min   = _scoreHistory.Min();
        var max   = _scoreHistory.Max();
        var range = max - min;
        var sb    = new System.Text.StringBuilder();
        foreach (var s in _scoreHistory)
        {
            int idx = range < 0.01 ? 7 : (int)Math.Round((s - min) / range * 7);
            sb.Append(SparkChars[Math.Clamp(idx, 0, 7)]);
        }
        ScoreSparkline = sb.ToString();
    }

    public void RefreshMonitors(MonitorHub hub)
    {
        // Match by Name — Dictionary order is not guaranteed, so never use index-based matching.
        var byName = hub.GetAll().ToDictionary(s => s.Name);
        foreach (var item in MonitorStatuses)
        {
            if (!byName.TryGetValue(item.Name, out var hubStatus)) continue;
            item.Status   = hubStatus.Detail;
            item.DotColor = hubStatus.State switch
            {
                MonitorState.Ok      => Colors.LimeGreen,
                MonitorState.Warning => Colors.Orange,
                MonitorState.Alert   => Color.FromRgb(220, 80, 80),
                _                    => Colors.Gray
            };
            item.LastChecked = hubStatus.LastChecked.HasValue
                ? FormatTimeAgo(hubStatus.LastChecked.Value)
                : "";
        }
    }

    private void RefreshEvents()
    {
        RecentEvents.Clear();
        var events = _killSwitch.Events;
        if (events.Count == 0)
        {
            RecentEvents.Add("No security events recorded.");
        }
        else
        {
            foreach (var evt in events.TakeLast(10).Reverse())
                RecentEvents.Add($"[{evt.Timestamp:HH:mm:ss}] {evt.Trigger}");
        }
    }

    private static string FormatTimeAgo(DateTime dt)
    {
        var elapsed = DateTime.Now - dt;
        if (elapsed.TotalSeconds < 90) return "just now";
        if (elapsed.TotalMinutes < 60) return $"{(int)elapsed.TotalMinutes}m ago";
        return $"{(int)elapsed.TotalHours}h ago";
    }

    [RelayCommand]
    private async Task ToggleLock()
    {
        if (_killSwitch.IsEngaged || _currentStatus.Mode == GatewayMode.Locked)
        {
            if (_killSwitch.IsEngaged)
            {
                _killSwitch.Disengage();
                _killSwitch.ClearAlerts();
            }
            await _gateway.UnlockAsync();
        }
        else
        {
            await _gateway.LockAsync();
        }
        await RefreshAfterActionAsync();
    }

    [RelayCommand]
    private async Task Restart()
    {
        await _gateway.RestartAsync();
        await RefreshAfterActionAsync();
    }

    [RelayCommand]
    private async Task RefreshStatus()
    {
        var status = await _gateway.GetStatusAsync();
        _ = Dispatcher.UIThread.InvokeAsync(() => UpdateStatus(status));
    }

    private async Task RefreshAfterActionAsync()
    {
        await Task.Delay(1500);
        var status = await _gateway.GetStatusAsync();
        _ = Dispatcher.UIThread.InvokeAsync(() => UpdateStatus(status));
    }

    [RelayCommand]
    private void OpenLog() => _openLogAction();

    [RelayCommand]
    private void OpenPatch() => _openPatchAction();

    [RelayCommand]
    private void OpenSettings() => _openSettingsAction();

    [RelayCommand]
    private void OpenAbout() => _openAboutAction();

    [RelayCommand]
    private void Donate()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = "open",
                ArgumentList    = { "https://www.paypal.com/donate?business=6xxwhp%40gmail.com" },
                UseShellExecute = false,
                CreateNoWindow  = true
            });
        }
        catch { }
    }

    [RelayCommand]
    private void Exit() => _exitAction();

    [RelayCommand]
    private async Task SyncToken()
    {
        SyncStatusText       = "Syncing token...";
        SyncStatusBrush      = Brushes.Gray;
        IsSyncStatusVisible  = true;

        var (success, message) = await _gateway.SyncTokenAsync();

        SyncStatusText  = success ? $"✓ {message}" : $"✗ {message}";
        SyncStatusBrush = success
            ? new SolidColorBrush(Color.FromRgb(80, 200, 100))
            : new SolidColorBrush(Color.FromRgb(220, 100, 80));

        // Auto-clear after 5 seconds
        await Task.Delay(5000);
        IsSyncStatusVisible = false;
        SyncStatusText      = "";
    }

    [RelayCommand]
    private void TogglePause()
    {
        _togglePauseAction();
        PauseButtonText = _isPausedFunc() ? "Resume Monitors" : "Pause Monitors";
    }

    public void UpdateConnections(List<string> connections)
    {
        ActiveConnections.Clear();
        if (connections.Count == 0)
        {
            IsConnectionsVisible = false;
            return;
        }
        foreach (var c in connections)
            ActiveConnections.Add(c);
        IsConnectionsVisible = true;
    }

    [RelayCommand]
    private async Task ExportAlerts()
    {
        try
        {
            var events   = _killSwitch.Events.ToList();
            var statuses = _killSwitch.Events.Count == 0
                ? new List<object>()
                : new List<object>();

            var report = new
            {
                ExportedAt = DateTime.Now,
                Host       = Environment.MachineName,
                User       = Environment.UserName,
                Events     = events.Select(e => new
                {
                    e.Timestamp,
                    e.Monitor,
                    e.Trigger,
                    e.Details,
                    e.Action
                }),
            };

            var json = JsonSerializer.Serialize(report,
                new JsonSerializerOptions { WriteIndented = true });

            var path = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"openclaw-alerts-{DateTime.Now:yyyy-MM-dd-HHmmss}.json");

            await System.IO.File.WriteAllTextAsync(path, json);

            ExportStatusText = $"✓ Saved to Desktop/{System.IO.Path.GetFileName(path)}";
            await Task.Delay(5000);
            ExportStatusText = "";
        }
        catch (Exception ex)
        {
            ExportStatusText = $"✗ Export failed: {ex.Message}";
            await Task.Delay(4000);
            ExportStatusText = "";
        }
    }
}
