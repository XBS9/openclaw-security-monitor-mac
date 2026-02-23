using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;
using OpenClawSecurityMonitorMac.Models;
using OpenClawSecurityMonitorMac.Services;
using OpenClawSecurityMonitorMac.ViewModels;
using OpenClawSecurityMonitorMac.Views;

namespace OpenClawSecurityMonitorMac.Core;

public class TrayApplication : IDisposable
{
    private readonly TraySettings _settings;
    private readonly DirectBashService _bash;
    private readonly GatewayService _gateway;
    private readonly KillSwitch _killSwitch;
    private readonly MonitorHub _monitorHub;

    private TrayIcon? _trayIcon;
    private NativeMenuItem? _statusItem;
    private NativeMenuItem? _alertItem;
    private NativeMenuItem? _lockUnlockItem;
    private NativeMenuItem? _logItem;
    private NativeMenuItem? _pauseItem;

    private bool _monitorsPaused;
    private Timer? _autoResumeTimer;

    private StatusMonitor? _statusMonitor;
    private FileIntegrityMonitor? _fileIntegrityMonitor;
    private AlertLogWatcher? _alertLogWatcher;
    private EgressMonitor? _egressMonitor;
    private PatchIntegrityMonitor? _patchMonitor;
    private NamespaceMonitor? _namespaceMonitor;
    private PermissionMonitor? _permissionMonitor;
    private ExposureMonitor? _exposureMonitor;
    private TokenAgeMonitor? _tokenAgeMonitor;

    private GatewayStatus _currentStatus = new();
    private bool _patchWarning;

    private int _disposed;

    private DashboardWindow? _dashboardWindow;
    private DashboardViewModel? _dashboardVm;
    private LogViewerWindow? _logWindow;
    private PatchWindow? _patchWindow;
    private AboutWindow? _aboutWindow;
    private SettingsWindow? _settingsWindow;

    // Cached icons for fast tray updates
    private WindowIcon? _iconGray;
    private WindowIcon? _iconGreen;
    private WindowIcon? _iconYellow;
    private WindowIcon? _iconRed;

    public TrayApplication(TraySettings settings, DirectBashService bash,
        GatewayService gateway, KillSwitch killSwitch)
    {
        _settings = settings;
        _bash = bash;
        _gateway = gateway;
        _killSwitch = killSwitch;
        _monitorHub = new MonitorHub();
    }

    public void Initialize()
    {
        Dispatcher.UIThread.Invoke(() =>
        {
            InitIcons();
            CreateTrayIcon();
        });

        _killSwitch.Triggered += OnKillSwitchTriggered;
        _monitorHub.Updated   += OnMonitorUpdated;

        StartMonitors();
    }

    // -------------------------------------------------------------------------
    // Icon generation (shield shape via programmatic pixel drawing)
    // -------------------------------------------------------------------------

    private void InitIcons()
    {
        _iconGray   = CreateShieldIcon(128, 128, 140);   // gray
        _iconGreen  = CreateShieldIcon(50,  180, 50);    // green
        _iconYellow = CreateShieldIcon(240, 180, 20);    // yellow/amber
        _iconRed    = CreateShieldIcon(220, 50,  50);    // red
    }

    /// <summary>
    /// Generates a 32x32 shield-shaped icon with the given RGB color.
    /// Uses Marshal-based pixel writes (no unsafe code required).
    /// </summary>
    private static WindowIcon? CreateShieldIcon(byte r, byte g, byte b)
    {
        try
        {
            const int size = 32;
            var bitmap = new WriteableBitmap(
                new PixelSize(size, size), new Vector(96, 96),
                PixelFormat.Bgra8888, AlphaFormat.Premul);

            using (var fb = bitmap.Lock())
            {
                for (int y = 0; y < size; y++)
                {
                    for (int x = 0; x < size; x++)
                    {
                        bool inShield = IsInShield(x, y, size);
                        var ptr = fb.Address + y * fb.RowBytes + x * 4;

                        // Pre-multiplied alpha BGRA
                        byte alpha = inShield ? (byte)220 : (byte)0;
                        Marshal.WriteByte(ptr + 0, inShield ? (byte)(b * 220 / 255) : (byte)0); // B premul
                        Marshal.WriteByte(ptr + 1, inShield ? (byte)(g * 220 / 255) : (byte)0); // G premul
                        Marshal.WriteByte(ptr + 2, inShield ? (byte)(r * 220 / 255) : (byte)0); // R premul
                        Marshal.WriteByte(ptr + 3, alpha);                                       // A
                    }
                }
            }

            using var ms = new System.IO.MemoryStream();
            bitmap.Save(ms);
            ms.Position = 0;
            return new WindowIcon(ms);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsInShield(int x, int y, int size)
    {
        // Normalize: center at 0.5, y top=0 bottom=1
        float nx = x / (float)(size - 1);
        float ny = y / (float)(size - 1);

        const float margin = 0.1f;

        if (ny < 0 || ny > 1 || nx < 0 || nx > 1) return false;

        if (ny <= 0.55f)
        {
            // Top section: near-rectangular with slight rounding
            return nx >= margin && nx <= (1f - margin);
        }
        else
        {
            // Bottom: tapers to a point at center-bottom
            float t        = (ny - 0.55f) / 0.45f;
            float sideInset = margin + t * (0.5f - margin);
            return nx >= sideInset && nx <= (1f - sideInset);
        }
    }

    // -------------------------------------------------------------------------
    // Tray icon setup
    // -------------------------------------------------------------------------

    private void CreateTrayIcon()
    {
        var menu = new NativeMenu();

        _statusItem = new NativeMenuItem("Status: Starting...") { IsEnabled = false };
        menu.Add(_statusItem);

        _alertItem = new NativeMenuItem("") { IsEnabled = false };
        // Hide initially — shown when kill switch fires
        menu.Add(new NativeMenuItemSeparator());

        _lockUnlockItem = new NativeMenuItem("Lock Gateway");
        _lockUnlockItem.Click += async (_, _) =>
        {
            try { await ToggleLockAsync(); }
            catch (Exception ex) { ShowNotification("Error", $"Gateway toggle failed: {ex.Message}"); }
        };
        menu.Add(_lockUnlockItem);

        var restartItem = new NativeMenuItem("Restart Gateway");
        restartItem.Click += async (_, _) =>
        {
            try { await RestartAsync(); }
            catch (Exception ex) { ShowNotification("Error", $"Restart failed: {ex.Message}"); }
        };
        menu.Add(restartItem);

        _pauseItem = new NativeMenuItem("Pause Monitors (Maintenance)");
        _pauseItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(TogglePause);
        menu.Add(_pauseItem);

        menu.Add(new NativeMenuItemSeparator());

        var dashItem = new NativeMenuItem("Dashboard...");
        dashItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(ShowDashboard);
        menu.Add(dashItem);

        _logItem = new NativeMenuItem("Security Log...");
        _logItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(ShowLogViewer);
        menu.Add(_logItem);

        var patchItem = new NativeMenuItem("Run Auto-Patch...");
        patchItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(ShowPatchWindow);
        menu.Add(patchItem);

        menu.Add(new NativeMenuItemSeparator());

        var aboutItem = new NativeMenuItem("About...");
        aboutItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(ShowAbout);
        menu.Add(aboutItem);

        var settingsItem = new NativeMenuItem("Settings");
        settingsItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(OpenSettings);
        menu.Add(settingsItem);

        menu.Add(new NativeMenuItemSeparator());

        var exitItem = new NativeMenuItem("Quit");
        exitItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(ExitApp);
        menu.Add(exitItem);

        _trayIcon = new TrayIcon
        {
            ToolTipText = "OpenClaw Security Monitor — Starting...",
            IsVisible   = true,
            Icon        = _iconGray,
            Menu        = menu
        };
        _trayIcon.Clicked += (_, _) => Dispatcher.UIThread.InvokeAsync(ShowDashboard);
    }

    // -------------------------------------------------------------------------
    // Monitor startup
    // -------------------------------------------------------------------------

    private void StartMonitors()
    {
        _statusMonitor = new StatusMonitor(_gateway, _killSwitch, _settings, _monitorHub);
        _statusMonitor.StatusChanged += OnStatusChanged;
        _statusMonitor.Start();

        _fileIntegrityMonitor = new FileIntegrityMonitor(_bash, _killSwitch, _settings, _monitorHub);
        _fileIntegrityMonitor.Start();

        _alertLogWatcher = new AlertLogWatcher(_bash, _killSwitch, _settings, _monitorHub);
        _alertLogWatcher.Start();

        _egressMonitor = new EgressMonitor(_bash, _killSwitch, _settings, _monitorHub);
        _egressMonitor.Start();

        _patchMonitor = new PatchIntegrityMonitor(_bash, _killSwitch, _settings, _monitorHub);
        _patchMonitor.PatchWarning += OnPatchWarning;
        _patchMonitor.Start();

        _namespaceMonitor = new NamespaceMonitor(_bash, _killSwitch, _settings, _monitorHub);
        _namespaceMonitor.Start();

        _permissionMonitor = new PermissionMonitor(_bash, _settings, _monitorHub);
        _permissionMonitor.Start();

        _exposureMonitor = new ExposureMonitor(_bash, _settings, _monitorHub);
        _exposureMonitor.Start();

        _tokenAgeMonitor = new TokenAgeMonitor(_bash, _settings, _monitorHub);
        _tokenAgeMonitor.Start();
    }

    // -------------------------------------------------------------------------
    // Event handlers
    // -------------------------------------------------------------------------

    private void OnStatusChanged(GatewayStatus status)
    {
        _currentStatus = status;
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            UpdateTrayState();
            _dashboardVm?.UpdateStatus(status);
        });
    }

    private void OnMonitorUpdated()
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            _dashboardVm?.RefreshMonitors(_monitorHub);
        });
    }

    private void OnKillSwitchTriggered(SecurityEvent evt)
    {
        var lockedStatus = new GatewayStatus
        {
            IsRunning = _currentStatus.IsRunning,
            Mode      = GatewayMode.Locked,
            SecurityScore = 3.3,
            Uptime    = _currentStatus.Uptime
        };
        _currentStatus = lockedStatus;

        Dispatcher.UIThread.InvokeAsync(() =>
        {
            UpdateTrayState();
            _dashboardVm?.UpdateStatus(lockedStatus);

            if (_settings.ShowNotificationOnKillSwitch)
                ShowNotification("Security Alert", $"{evt.Trigger}. Gateway locked down.");
        });
    }

    private void OnPatchWarning(string message)
    {
        _patchWarning = true;
        Dispatcher.UIThread.InvokeAsync(UpdateTrayState);
    }

    // -------------------------------------------------------------------------
    // Tray state update
    // -------------------------------------------------------------------------

    private void UpdateTrayState()
    {
        if (_trayIcon == null) return;

        try
        {
            var status         = _currentStatus;
            var engaged        = _killSwitch.IsEngaged;
            var unreviewedCount = _killSwitch.UnreviewedCount;

            if (engaged || !status.IsRunning)
            {
                _trayIcon.Icon        = _iconRed;
                var reason            = engaged ? "ALERT" : "Stopped";
                _trayIcon.ToolTipText = $"OpenClaw — {reason}";
                if (_lockUnlockItem != null) _lockUnlockItem.Header = "Unlock Gateway";
            }
            else if (_patchWarning)
            {
                _trayIcon.Icon        = _iconYellow;
                _trayIcon.ToolTipText = "OpenClaw — Warning (patches needed)";
                if (_lockUnlockItem != null)
                    _lockUnlockItem.Header = status.Mode == GatewayMode.Unlocked ? "Lock Gateway" : "Unlock Gateway";
            }
            else
            {
                var modeStr  = status.Mode == GatewayMode.Unlocked ? "Unlocked" :
                               status.Mode == GatewayMode.Locked   ? "Locked"   : "Unknown";
                var scoreStr = status.SecurityScore > 0 ? $" ({status.SecurityScore:F1})" : "";
                var upStr    = !string.IsNullOrEmpty(status.Uptime) ? $" | {status.Uptime}" : "";

                _trayIcon.Icon        = status.Mode == GatewayMode.Locked ? _iconYellow : _iconGreen;
                _trayIcon.ToolTipText = TruncateTooltip($"OpenClaw — {modeStr}{scoreStr}{upStr}");
                if (_lockUnlockItem != null)
                    _lockUnlockItem.Header = status.Mode == GatewayMode.Unlocked ? "Lock Gateway" : "Unlock Gateway";
            }

            var modeDisplay = status.Mode switch
            {
                GatewayMode.Unlocked => "Unlocked (6.7)",
                GatewayMode.Locked   => "Locked (3.3)",
                _                    => "Unknown"
            };
            var runStr = status.IsRunning
                ? (!string.IsNullOrEmpty(status.Uptime) ? $" | Running {status.Uptime}" : " | Running")
                : " | Stopped";
            if (_statusItem != null) _statusItem.Header = $"Status: {modeDisplay}{runStr}";

            if (unreviewedCount > 0)
            {
                var lastEvt = _killSwitch.Events.LastOrDefault();
                if (_alertItem != null)
                {
                    _alertItem.Header    = $"⚠ ALERT: {lastEvt?.Trigger ?? "Review..."}";
                    _alertItem.IsEnabled = true;
                }
            }
            else
            {
                if (_alertItem != null)
                {
                    _alertItem.Header    = "";
                    _alertItem.IsEnabled = false;
                }
            }

            if (_logItem != null)
                _logItem.Header = unreviewedCount > 0
                    ? $"Security Log... ({unreviewedCount} new)"
                    : "Security Log...";
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[TrayApp] UpdateTrayState error: {ex.Message}");
        }
    }

    private static string TruncateTooltip(string text) =>
        text.Length > 63 ? text[..63] : text;

    // -------------------------------------------------------------------------
    // Window management
    // -------------------------------------------------------------------------

    private void ShowDashboard()
    {
        if (_dashboardWindow != null)
        {
            _dashboardVm?.UpdateStatus(_currentStatus);
            _dashboardVm?.RefreshMonitors(_monitorHub);
            _dashboardWindow.Show();
            _dashboardWindow.Activate();
            return;
        }

        _dashboardVm = new DashboardViewModel(
            _killSwitch, _gateway, _settings,
            openLogAction:      ShowLogViewer,
            openPatchAction:    ShowPatchWindow,
            openSettingsAction: OpenSettings,
            openAboutAction:    ShowAbout,
            exitAction:         ExitApp,
            togglePauseAction:  TogglePause,
            isPausedFunc:       () => _monitorsPaused);

        _dashboardVm.UpdateStatus(_currentStatus);
        _dashboardVm.RefreshMonitors(_monitorHub);

        _dashboardWindow = new DashboardWindow { DataContext = _dashboardVm };
        _dashboardWindow.Closed += (_, _) => _dashboardWindow = null;
        _dashboardWindow.Show();
    }

    private async Task ToggleLockAsync()
    {
        if (_currentStatus.Mode == GatewayMode.Unlocked && !_killSwitch.IsEngaged)
        {
            await _gateway.LockAsync();
        }
        else
        {
            if (_killSwitch.IsEngaged)
            {
                _killSwitch.Disengage();
                _killSwitch.ClearAlerts();
                _patchWarning = false;
            }
            await _gateway.UnlockAsync();
        }
        await RefreshStatusNowAsync();
    }

    private async Task RestartAsync()
    {
        await _gateway.RestartAsync();
        await RefreshStatusNowAsync();
    }

    private async Task RefreshStatusNowAsync()
    {
        await Task.Delay(1500);
        var status = await _gateway.GetStatusAsync();
        OnStatusChanged(status);
    }

    private void TogglePause()
    {
        if (_monitorsPaused)
        {
            _autoResumeTimer?.Dispose();
            _autoResumeTimer = null;
            _statusMonitor?.Start();
            _fileIntegrityMonitor?.Start();
            _alertLogWatcher?.Start();
            _egressMonitor?.Start();
            _patchMonitor?.Start();
            _namespaceMonitor?.Start();
            _permissionMonitor?.Start();
            _exposureMonitor?.Start();
            _tokenAgeMonitor?.Start();
            _monitorsPaused = false;
            if (_pauseItem != null) _pauseItem.Header = "Pause Monitors (Maintenance)";
            ShowNotification("Monitors Resumed", "All security monitors are active.");
        }
        else
        {
            _statusMonitor?.Stop();
            _fileIntegrityMonitor?.Stop();
            _alertLogWatcher?.Stop();
            _egressMonitor?.Stop();
            _patchMonitor?.Stop();
            _namespaceMonitor?.Stop();
            _permissionMonitor?.Stop();
            _exposureMonitor?.Stop();
            _tokenAgeMonitor?.Stop();
            _monitorsPaused = true;
            if (_pauseItem != null) _pauseItem.Header = "Resume Monitors";
            _autoResumeTimer?.Dispose();
            _autoResumeTimer = new Timer(_ =>
            {
                Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (_monitorsPaused) TogglePause();
                });
            }, null, TimeSpan.FromHours(1), Timeout.InfiniteTimeSpan);
            ShowNotification("Monitors Paused",
                "Security monitors paused for maintenance. Auto-resume in 1 hour.");
        }
    }

    private void ShowLogViewer()
    {
        if (_logWindow != null)
        {
            _logWindow.Activate();
            return;
        }

        _killSwitch.ClearAlerts();
        UpdateTrayState();

        var vm = new LogViewerViewModel(_killSwitch, _gateway);
        _logWindow = new LogViewerWindow { DataContext = vm };
        _logWindow.Closed += (_, _) => _logWindow = null;
        _logWindow.Show();
    }

    private void ShowPatchWindow()
    {
        if (_patchWindow != null)
        {
            _patchWindow.Activate();
            return;
        }

        var autoPatch = new AutoPatchService(_bash, _settings);
        var vm = new PatchViewModel(autoPatch);
        _patchWindow = new PatchWindow { DataContext = vm };
        _patchWindow.Closed += (_, _) => { vm.Cleanup(); _patchWindow = null; };
        _patchWindow.Show();
    }

    private void ShowAbout()
    {
        if (_aboutWindow != null)
        {
            _aboutWindow.Activate();
            return;
        }

        _aboutWindow = new AboutWindow();
        _aboutWindow.Closed += (_, _) => _aboutWindow = null;
        _aboutWindow.Show();
    }

    private void OpenSettings()
    {
        if (_settingsWindow != null)
        {
            _settingsWindow.Activate();
            return;
        }

        var vm = new SettingsViewModel(_settings);
        _settingsWindow = new SettingsWindow(vm);
        _settingsWindow.Closed += (_, _) => _settingsWindow = null;
        _settingsWindow.Show();
    }

    private void ExitApp()
    {
        Dispose();
        if (Application.Current?.ApplicationLifetime
            is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.Shutdown();
        }
    }

    // -------------------------------------------------------------------------
    // macOS notification helper
    // -------------------------------------------------------------------------

    private static void ShowNotification(string title, string message)
    {
        try
        {
            // Use osascript for macOS user notifications
            var script = $"display notification \"{Escape(message)}\" with title \"{Escape(title)}\"";
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "osascript",
                ArgumentList = { "-e", script },
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
        catch
        {
            // Notifications are best-effort
        }
    }

    private static string Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    // -------------------------------------------------------------------------
    // Dispose
    // -------------------------------------------------------------------------

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        _killSwitch.Triggered -= OnKillSwitchTriggered;
        _monitorHub.Updated   -= OnMonitorUpdated;

        if (_statusMonitor  != null) _statusMonitor.StatusChanged -= OnStatusChanged;
        if (_patchMonitor   != null) _patchMonitor.PatchWarning   -= OnPatchWarning;

        _autoResumeTimer?.Dispose();
        _autoResumeTimer = null;

        _statusMonitor?.Dispose();
        _fileIntegrityMonitor?.Dispose();
        _alertLogWatcher?.Dispose();
        _egressMonitor?.Dispose();
        _patchMonitor?.Dispose();
        _namespaceMonitor?.Dispose();
        _permissionMonitor?.Dispose();
        _exposureMonitor?.Dispose();
        _tokenAgeMonitor?.Dispose();

        if (_trayIcon != null)
        {
            _trayIcon.IsVisible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        // WindowIcon does not implement IDisposable — GC handles cleanup
    }
}
