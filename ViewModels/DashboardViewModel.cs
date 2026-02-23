using System.Collections.ObjectModel;
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

    public ObservableCollection<MonitorStatusItem> MonitorStatuses { get; } = new();
    public ObservableCollection<string> RecentEvents { get; } = new();

    [ObservableProperty]
    private string _versionText = GetVersionText();

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
    }

    public void UpdateStatus(GatewayStatus status)
    {
        _currentStatus = status;

        if (_killSwitch.IsEngaged)
        {
            StatusTitle  = "ALERT — Gateway Locked";
            StatusDetail = "Kill switch triggered. Review alerts before unlocking.";
            StatusColor  = Color.FromRgb(220, 50, 50);
            ScoreDisplay = "3.3";
            ScoreBrush   = new SolidColorBrush(Color.FromRgb(200, 80, 80));
            LockButtonText = "Unlock Gateway";

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
    private void Exit() => _exitAction();

    [RelayCommand]
    private void TogglePause()
    {
        _togglePauseAction();
        PauseButtonText = _isPausedFunc() ? "Resume Monitors" : "Pause Monitors";
    }
}
