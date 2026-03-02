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
    private LaunchAgentScanMonitor? _launchAgentScanMonitor;
    private BinaryIntegrityMonitor? _binaryIntegrityMonitor;
    private TccPermissionMonitor? _tccPermissionMonitor;
    private SudoLogMonitor? _sudoLogMonitor;
    private SystemPostureMonitor? _systemPostureMonitor;
    private CronJobMonitor? _cronJobMonitor;
    private SystemExtensionMonitor? _systemExtensionMonitor;

    private WebhookAlertService? _webhookAlertService;
    private EmailAlertService? _emailAlertService;
    private DateTime _lastDigestDate = DateTime.MinValue;

    // Rate-limiting for StateEscalated notifications (per monitor name)
    private readonly Dictionary<string, DateTime> _lastAlertSentPerMonitor = new();
    private readonly object _alertRateLock = new();
    private Timer? _connectionsTimer;

    private GatewayStatus _currentStatus = new();
    private bool _patchWarning;

    private int _disposed;

    private DashboardWindow? _dashboardWindow;
    private DashboardViewModel? _dashboardVm;
    private LogViewerWindow? _logWindow;
    private PatchWindow? _patchWindow;
    private AboutWindow? _aboutWindow;
    private SettingsWindow? _settingsWindow;

    private NativeMenuItem? _updateItem;
    private CancellationTokenSource? _updateCts;
    private string? _updateLocalPath; // path to downloaded DMG once ready

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

        _webhookAlertService = new WebhookAlertService(_settings);
        _emailAlertService   = new EmailAlertService(_settings);
        _killSwitch.Triggered       += OnKillSwitchTriggered;
        _monitorHub.Updated         += OnMonitorUpdated;
        _monitorHub.StateEscalated  += OnMonitorStateEscalated;

        StartMonitors();
        EnsureSelfProtectionPlist();

        if (!_settings.HasShownFirstRun)
            Dispatcher.UIThread.InvokeAsync(ShowFirstRun);
        else if (!_settings.StartMinimized)
            Dispatcher.UIThread.InvokeAsync(ShowDashboard);

        _ = StartUpdateCheckAsync();
        _ = CheckStaleKillSwitchOnStartupAsync();
        _ = RunDailyDigestAsync();
        StartConnectionsTimer();
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

        var exportItem = new NativeMenuItem("Export Alerts...");
        exportItem.Click += (_, _) => ExportAlerts();
        menu.Add(exportItem);

        menu.Add(new NativeMenuItemSeparator());

        var aboutItem = new NativeMenuItem("About...");
        aboutItem.Click += (_, _) => Dispatcher.UIThread.InvokeAsync(ShowAbout);
        menu.Add(aboutItem);

        var donateItem = new NativeMenuItem("Donate ♥");
        donateItem.Click += (_, _) =>
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
        };
        menu.Add(donateItem);

        _updateItem = new NativeMenuItem("") { IsVisible = false };
        _updateItem.Click += (_, _) =>
        {
            try
            {
                // If the DMG was already downloaded, open it directly; otherwise open releases page
                var target = (_updateLocalPath != null && File.Exists(_updateLocalPath))
                    ? _updateLocalPath
                    : "https://github.com/XBS9/openclaw-security-monitor-mac/releases";

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = "open",
                    ArgumentList    = { target },
                    UseShellExecute = false,
                    CreateNoWindow  = true
                });
            }
            catch { }
        };
        menu.Add(_updateItem);

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

        _launchAgentScanMonitor = new LaunchAgentScanMonitor(_bash, _killSwitch, _settings, _monitorHub);
        _launchAgentScanMonitor.Start();

        _binaryIntegrityMonitor = new BinaryIntegrityMonitor(_bash, _settings, _monitorHub);
        _binaryIntegrityMonitor.Start();

        _tccPermissionMonitor = new TccPermissionMonitor(_bash, _monitorHub);
        _tccPermissionMonitor.Start();

        _sudoLogMonitor = new SudoLogMonitor(_bash, _settings, _monitorHub);
        _sudoLogMonitor.Start();

        _systemPostureMonitor = new SystemPostureMonitor(_bash, _killSwitch, _settings, _monitorHub);
        _systemPostureMonitor.Start();

        _cronJobMonitor = new CronJobMonitor(_bash, _settings, _monitorHub);
        _cronJobMonitor.Start();

        _systemExtensionMonitor = new SystemExtensionMonitor(_bash, _settings, _monitorHub);
        _systemExtensionMonitor.Start();
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
        _webhookAlertService?.SendAlert(evt);
        _emailAlertService?.SendAlert(evt);

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

    /// <summary>
    /// Fires when any monitor transitions to Warning or Alert for the first time.
    /// Sends email/webhook alerts with per-monitor rate limiting to prevent flooding.
    /// </summary>
    private void OnMonitorStateEscalated(MonitorStatus status)
    {
        var cooldown = TimeSpan.FromMinutes(_settings.AlertCooldownMinutes);
        var now = DateTime.Now;

        lock (_alertRateLock)
        {
            if (_lastAlertSentPerMonitor.TryGetValue(status.Name, out var lastSent) &&
                (now - lastSent) < cooldown)
                return;

            _lastAlertSentPerMonitor[status.Name] = now;
        }

        _webhookAlertService?.SendMonitorAlert(status);
        _emailAlertService?.SendMonitorAlert(status);
    }

    /// <summary>
    /// Writes a KeepAlive LaunchAgent plist for this app if it does not already exist,
    /// then loads it via launchctl. macOS launchd will restart the monitor automatically
    /// within ThrottleInterval seconds if the process is killed.
    /// Called at startup; fires-and-forgets so it never blocks Initialize().
    /// </summary>
    private void EnsureSelfProtectionPlist()
    {
        _ = EnsureSelfProtectionPlistAsync();
    }

    private async Task EnsureSelfProtectionPlistAsync()
    {
        try
        {
            var home      = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var plistPath = Path.Combine(home, "Library", "LaunchAgents",
                                         "com.openclaw.security-monitor.plist");

            if (File.Exists(plistPath)) return; // already installed

            const string appPath =
                "/Applications/OpenClawMonitor.app/Contents/MacOS/OpenClawSecurityMonitorMac";

            var plistXml =
                $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0">
                <dict>
                    <key>Label</key><string>com.openclaw.security-monitor</string>
                    <key>Program</key><string>{appPath}</string>
                    <key>KeepAlive</key><true/>
                    <key>RunAtLoad</key><true/>
                    <key>ThrottleInterval</key><integer>10</integer>
                </dict>
                </plist>
                """;

            File.WriteAllText(plistPath, plistXml);
            await _bash.RunAsync($"launchctl load \"{plistPath}\" 2>/dev/null || true");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[TrayApp] EnsureSelfProtectionPlist failed: {ex.Message}");
        }
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
            _launchAgentScanMonitor?.Start();
            _binaryIntegrityMonitor?.Start();
            _tccPermissionMonitor?.Start();
            _sudoLogMonitor?.Start();
            _systemPostureMonitor?.Start();
            _cronJobMonitor?.Start();
            _systemExtensionMonitor?.Start();
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
            _launchAgentScanMonitor?.Stop();
            _binaryIntegrityMonitor?.Stop();
            _tccPermissionMonitor?.Stop();
            _sudoLogMonitor?.Stop();
            _systemPostureMonitor?.Stop();
            _cronJobMonitor?.Stop();
            _systemExtensionMonitor?.Stop();
            _monitorsPaused = true;
            if (_pauseItem != null) _pauseItem.Header = "Resume Monitors";
            _autoResumeTimer?.Dispose();
            _autoResumeTimer = new Timer(_ =>
            {
                Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (_monitorsPaused) TogglePause();
                });
            }, null, TimeSpan.FromHours(2), Timeout.InfiniteTimeSpan);
            ShowNotification("Monitors Paused",
                "Security monitors paused for maintenance. Auto-resume in 2 hours.");
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

    private void ShowFirstRun()
    {
        var win = new FirstRunWindow();
        win.Closed += (_, _) =>
        {
            _settings.HasShownFirstRun = true;
            _settings.Save();
            if (!_settings.StartMinimized)
                ShowDashboard();
        };
        win.Show();
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

    // -------------------------------------------------------------------------
    // Startup: stale kill switch reconciliation
    // -------------------------------------------------------------------------

    /// <summary>
    /// If the kill switch state file says engaged=true but the actual gateway
    /// plist is not hardened (e.g. gateway was manually recovered via CLI without
    /// acknowledging the alert), prompt the user to choose:
    ///   • Re-lock Gateway   — re-applies the hardened plist
    ///   • Acknowledge       — clears the engaged state, resumes normal monitoring
    /// Runs after a short delay so monitors have time to get the first status read.
    /// </summary>
    private async Task CheckStaleKillSwitchOnStartupAsync()
    {
        if (!_killSwitch.IsEngaged) return;

        // Wait for the first gateway status poll to complete
        await Task.Delay(TimeSpan.FromSeconds(6));

        var status = await _gateway.GetStatusAsync();
        if (status.Mode == GatewayMode.Locked) return; // actually locked — nothing stale

        // Kill switch engaged but gateway is not in hardened mode.
        // Build a dialog describing what happened.
        var lastEvt   = _killSwitch.Events.LastOrDefault();
        var triggerMsg = lastEvt != null
            ? Escape($"{lastEvt.Trigger}\n{lastEvt.Details}")
            : "Unknown trigger";

        var script =
            "button returned of (display dialog " +
            $"\"Security Alert\\n\\nThe kill switch was triggered but the gateway is currently running UNLOCKED.\\n\\n" +
            $"Trigger: {triggerMsg}\\n\\n" +
            $"The gateway may have been manually recovered without acknowledging this alert.\\n\\n" +
            $"What would you like to do?\" " +
            "buttons {\"Re-lock Gateway\", \"Acknowledge & Continue\"} " +
            "default button \"Re-lock Gateway\" " +
            "with title \"OpenClaw Security Monitor — Action Required\" " +
            "with icon caution)";

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName               = "osascript",
            UseShellExecute        = false,
            CreateNoWindow         = true,
            RedirectStandardOutput = true
        };
        psi.ArgumentList.Add("-e");
        psi.ArgumentList.Add(script);

        try
        {
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            var choice = (await proc.StandardOutput.ReadToEndAsync()).Trim();
            await proc.WaitForExitAsync();

            if (choice == "Re-lock Gateway")
            {
                await _gateway.LockAsync();
            }
            else
            {
                // User acknowledged — clear engaged state
                _killSwitch.Disengage();
                _killSwitch.ClearAlerts();
                _patchWarning = false;
            }

            await RefreshStatusNowAsync();
            _ = Dispatcher.UIThread.InvokeAsync(ShowDashboard);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[TrayApp] StaleKillSwitchCheck failed: {ex.Message}");
        }
    }

    // -------------------------------------------------------------------------
    // Sudo-gated exit
    // -------------------------------------------------------------------------

    /// <summary>
    /// Requires administrator authentication before allowing the monitor to quit.
    /// Prevents someone with physical access from bypassing monitoring by just
    /// clicking Quit. Uses osascript to trigger macOS's native auth dialog.
    /// </summary>
    private async Task<bool> AuthenticateForQuitAsync()
    {
        const string script =
            "do shell script \"echo authorized\" with administrator privileges";

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName               = "osascript",
            UseShellExecute        = false,
            CreateNoWindow         = true,
            RedirectStandardOutput = true,
            RedirectStandardError  = true
        };
        psi.ArgumentList.Add("-e");
        psi.ArgumentList.Add(script);

        try
        {
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return false;
            await proc.WaitForExitAsync();
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private void ExitApp()
    {
        _ = ExitAppAsync();
    }

    private async Task ExitAppAsync()
    {
        bool authorized = await AuthenticateForQuitAsync();
        if (!authorized)
        {
            ShowNotification("Quit Denied",
                "Administrator authentication required to stop the security monitor.");
            return;
        }

        // Unload self-protection plist so launchd doesn't restart us after quit
        try
        {
            var home      = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var plistPath = Path.Combine(home, "Library", "LaunchAgents",
                                         "com.openclaw.security-monitor.plist");
            if (File.Exists(plistPath))
                await _bash.RunAsync($"launchctl unload \"{plistPath}\" 2>/dev/null || true");
        }
        catch { }

        Dispose();
        _ = Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (Application.Current?.ApplicationLifetime
                is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        });
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
    // Active connections display
    // -------------------------------------------------------------------------

    private void StartConnectionsTimer()
    {
        _connectionsTimer = new Timer(async _ =>
        {
            var (_, output, _) = await _bash.RunAsync(
                "lsof -i TCP -n -P 2>/dev/null | grep -i 'node\\|openclaw' | awk '{print $1, $9}' | sort -u");
            var connections = output
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l))
                .ToList();
            _ = Dispatcher.UIThread.InvokeAsync(() =>
                _dashboardVm?.UpdateConnections(connections));
        }, null, TimeSpan.FromSeconds(8), TimeSpan.FromSeconds(30));
    }

    // -------------------------------------------------------------------------
    // Alert export
    // -------------------------------------------------------------------------

    private void ExportAlerts()
    {
        try
        {
            var events = _killSwitch.Events.ToList();
            var report = new
            {
                ExportedAt = DateTime.Now,
                Host       = Environment.MachineName,
                User       = Environment.UserName,
                Events     = events.Select(e => new
                {
                    e.Timestamp, e.Monitor, e.Trigger, e.Details, e.Action
                })
            };

            var json = System.Text.Json.JsonSerializer.Serialize(report,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

            var path = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"openclaw-alerts-{DateTime.Now:yyyy-MM-dd-HHmmss}.json");

            System.IO.File.WriteAllText(path, json);
            ShowNotification("Alerts Exported",
                $"Saved to Desktop/{System.IO.Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            ShowNotification("Export Failed", ex.Message);
        }
    }

    // -------------------------------------------------------------------------
    // Daily digest notification
    // -------------------------------------------------------------------------

    private async Task RunDailyDigestAsync()
    {
        while (true)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(10));
                if (!_settings.DailyDigestEnabled) continue;

                var now = DateTime.Now;
                if (now.Hour == _settings.DailyDigestHour && _lastDigestDate.Date < now.Date)
                {
                    _lastDigestDate = now;
                    var all   = _monitorHub.GetAll();
                    var ok    = all.Count(s => s.State == MonitorState.Ok);
                    var warn  = all.Count(s => s.State == MonitorState.Warning);
                    var alert = all.Count(s => s.State == MonitorState.Alert);
                    var lastEvt = _killSwitch.Events.LastOrDefault();
                    var evtStr  = lastEvt != null ? $"Last: {lastEvt.Trigger}" : "No events";
                    ShowNotification("OpenClaw Daily Digest",
                        $"Monitors: {ok} OK, {warn} warn, {alert} alert. {evtStr}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TrayApp] DailyDigest error: {ex.Message}");
            }
        }
    }

    // -------------------------------------------------------------------------
    // Update check
    // -------------------------------------------------------------------------

    private async Task StartUpdateCheckAsync()
    {
        _updateCts = new CancellationTokenSource();
        var ct = _updateCts.Token;

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(10), ct); // don't slow startup

            var v       = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            var current = v != null ? $"{v.Major}.{v.Minor}.{v.Build}" : "0.0.0";

            // First check immediately, then repeat every 24 hours
            await PerformMonitorUpdateCheckAsync(current, ct);

            using var timer = new PeriodicTimer(TimeSpan.FromHours(24));
            while (await timer.WaitForNextTickAsync(ct))
                await PerformMonitorUpdateCheckAsync(current, ct);
        }
        catch (OperationCanceledException) { }

        // npm check runs once at startup (best-effort)
        if (!(_updateCts?.IsCancellationRequested ?? true))
            await CheckOpenClawNpmVersionAsync();
    }

    private async Task PerformMonitorUpdateCheckAsync(string current, CancellationToken ct)
    {
        var info = await UpdateChecker.CheckAsync(current);
        if (info == null || ct.IsCancellationRequested) return;

        // Show menu item immediately
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (_updateItem != null)
            {
                _updateItem.Header    = $"Downloading update — v{info.Version}...";
                _updateItem.IsVisible = true;
            }
        });

        // Download the DMG in the background
        ShowNotification("Update Available",
            $"OpenClaw Monitor v{info.Version} found — downloading in the background...");

        var localPath = await UpdateChecker.DownloadAsync(info, ct);
        if (localPath == null || ct.IsCancellationRequested) return;

        _updateLocalPath = localPath;

        // Update menu item to "ready"
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (_updateItem != null)
                _updateItem.Header = $"Install update — v{info.Version}";
        });

        // Show install dialog via osascript
        await OfferInstallAsync(info.Version, localPath, ct);
    }

    private async Task OfferInstallAsync(string version, string dmgPath, CancellationToken ct)
    {
        try
        {
            var script =
                $"display dialog \"OpenClaw Monitor v{version} has been downloaded and is ready to install.\\n\\n" +
                $"Click \\\"Install Now\\\" to open the disk image, then drag OpenClawSecurityMonitor to your Applications folder.\" " +
                $"with title \"Update Ready\" " +
                $"buttons {{\"Later\", \"Install Now\"}} " +
                $"default button \"Install Now\"";

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName              = "osascript",
                UseShellExecute       = false,
                RedirectStandardOutput = true,
                CreateNoWindow        = true
            };
            psi.ArgumentList.Add("-e");
            psi.ArgumentList.Add(script);

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;

            var output = await proc.StandardOutput.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);

            if (output.Contains("Install Now", StringComparison.OrdinalIgnoreCase))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = "open",
                    ArgumentList    = { dmgPath },
                    UseShellExecute = false,
                    CreateNoWindow  = true
                });
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[UpdateCheck] OfferInstall error: {ex.Message}");
        }
    }

    private async Task CheckOpenClawNpmVersionAsync()
    {
        try
        {
            var pkgPath = System.IO.Path.Combine(
                PathUtils.ExpandFull(_settings.NpmGlobalPath),
                "lib", "node_modules", "openclaw", "package.json");

            if (!System.IO.File.Exists(pkgPath)) return;

            var pkgJson   = System.IO.File.ReadAllText(pkgPath);
            var pkgDoc    = System.Text.Json.JsonDocument.Parse(pkgJson);
            var installed = pkgDoc.RootElement.GetProperty("version").GetString() ?? "";
            if (string.IsNullOrEmpty(installed)) return;

            // Fetch latest from npm registry (5s timeout)
            var (_, regOut, _) = await _bash.RunAsync(
                "curl -s --max-time 5 https://registry.npmjs.org/openclaw/latest 2>/dev/null " +
                "| python3 -c \"import sys,json; print(json.load(sys.stdin).get('version',''))\" 2>/dev/null");

            var latestNpm = regOut.Trim();
            if (string.IsNullOrEmpty(latestNpm) || latestNpm == installed) return;

            ShowNotification("OpenClaw Update Available",
                $"openclaw {latestNpm} available (installed: {installed}). Run: npm install -g openclaw");
        }
        catch
        {
            // Best-effort — npm registry unreachable is not a fatal condition
        }
    }

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
        _connectionsTimer?.Dispose();
        _connectionsTimer = null;

        _statusMonitor?.Dispose();
        _fileIntegrityMonitor?.Dispose();
        _alertLogWatcher?.Dispose();
        _egressMonitor?.Dispose();
        _patchMonitor?.Dispose();
        _namespaceMonitor?.Dispose();
        _permissionMonitor?.Dispose();
        _exposureMonitor?.Dispose();
        _tokenAgeMonitor?.Dispose();
        _launchAgentScanMonitor?.Dispose();
        _binaryIntegrityMonitor?.Dispose();
        _tccPermissionMonitor?.Dispose();
        _sudoLogMonitor?.Dispose();
        _systemPostureMonitor?.Dispose();
        _cronJobMonitor?.Dispose();
        _systemExtensionMonitor?.Dispose();

        _updateCts?.Cancel();
        _updateCts?.Dispose();
        _updateCts = null;

        if (_trayIcon != null)
        {
            _trayIcon.IsVisible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        // WindowIcon does not implement IDisposable — GC handles cleanup
    }
}
