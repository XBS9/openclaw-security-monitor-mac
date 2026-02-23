using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly TraySettings _settings;

    // ── Gateway ────────────────────────────────────────────────────────────
    [ObservableProperty] private int _gatewayPort;
    [ObservableProperty] private string _gatewayLabel = "";

    // ── Monitor intervals (seconds) ────────────────────────────────────────
    [ObservableProperty] private int _statusPollInterval;
    [ObservableProperty] private int _fileIntegrityInterval;
    [ObservableProperty] private int _alertLogInterval;
    [ObservableProperty] private int _egressCheckInterval;
    [ObservableProperty] private int _patchCheckInterval;
    [ObservableProperty] private int _namespaceCheckInterval;
    [ObservableProperty] private int _permissionCheckInterval;
    [ObservableProperty] private int _exposureCheckInterval;
    [ObservableProperty] private int _tokenAgeCheckInterval;

    // ── Security thresholds ────────────────────────────────────────────────
    [ObservableProperty] private int _tokenMaxAgeDays;
    [ObservableProperty] private int _expectedPatchedFileCount;

    // ── Behaviour ──────────────────────────────────────────────────────────
    [ObservableProperty] private bool _startMinimized;
    [ObservableProperty] private bool _showNotificationOnKillSwitch;
    [ObservableProperty] private bool _autoReapplyEgress;

    // ── Paths ──────────────────────────────────────────────────────────────
    [ObservableProperty] private string _npmGlobalPath = "";
    [ObservableProperty] private string _openClawConfigPath = "";
    [ObservableProperty] private string _gatewayEnvPath = "";
    [ObservableProperty] private string _securityAlertsLogPath = "";

    // ── Status ─────────────────────────────────────────────────────────────
    [ObservableProperty] private string _saveStatus = "";

    public event Action? CloseRequested;
    public event Action<string>? PathWarning;

    public SettingsViewModel(TraySettings settings)
    {
        _settings = settings;
        LoadFromSettings();
    }

    private void LoadFromSettings()
    {
        GatewayPort              = _settings.GatewayPort;
        GatewayLabel             = _settings.GatewayLabel;

        StatusPollInterval       = _settings.StatusPollInterval;
        FileIntegrityInterval    = _settings.FileIntegrityInterval;
        AlertLogInterval         = _settings.AlertLogInterval;
        EgressCheckInterval      = _settings.EgressCheckInterval;
        PatchCheckInterval       = _settings.PatchCheckInterval;
        NamespaceCheckInterval   = _settings.NamespaceCheckInterval;
        PermissionCheckInterval  = _settings.PermissionCheckInterval;
        ExposureCheckInterval    = _settings.ExposureCheckInterval;
        TokenAgeCheckInterval    = _settings.TokenAgeCheckInterval;

        TokenMaxAgeDays          = _settings.TokenMaxAgeDays;
        ExpectedPatchedFileCount = _settings.ExpectedPatchedFileCount;

        StartMinimized               = _settings.StartMinimized;
        ShowNotificationOnKillSwitch = _settings.ShowNotificationOnKillSwitch;
        AutoReapplyEgress            = _settings.AutoReapplyEgress;

        NpmGlobalPath           = _settings.NpmGlobalPath;
        OpenClawConfigPath      = _settings.OpenClawConfigPath;
        GatewayEnvPath          = _settings.GatewayEnvPath;
        SecurityAlertsLogPath   = _settings.SecurityAlertsLogPath;
    }

    [RelayCommand]
    private void Save()
    {
        _settings.GatewayPort            = GatewayPort;
        _settings.GatewayLabel           = GatewayLabel;

        _settings.StatusPollInterval      = StatusPollInterval;
        _settings.FileIntegrityInterval   = FileIntegrityInterval;
        _settings.AlertLogInterval        = AlertLogInterval;
        _settings.EgressCheckInterval     = EgressCheckInterval;
        _settings.PatchCheckInterval      = PatchCheckInterval;
        _settings.NamespaceCheckInterval  = NamespaceCheckInterval;
        _settings.PermissionCheckInterval = PermissionCheckInterval;
        _settings.ExposureCheckInterval   = ExposureCheckInterval;
        _settings.TokenAgeCheckInterval   = TokenAgeCheckInterval;

        _settings.TokenMaxAgeDays          = TokenMaxAgeDays;
        _settings.ExpectedPatchedFileCount = ExpectedPatchedFileCount;

        _settings.StartMinimized               = StartMinimized;
        _settings.ShowNotificationOnKillSwitch = ShowNotificationOnKillSwitch;
        _settings.AutoReapplyEgress            = AutoReapplyEgress;

        _settings.NpmGlobalPath          = NpmGlobalPath;
        _settings.OpenClawConfigPath     = OpenClawConfigPath;
        _settings.GatewayEnvPath         = GatewayEnvPath;
        _settings.SecurityAlertsLogPath  = SecurityAlertsLogPath;

        _settings.Validate();
        _settings.Save();

        var warnings = ValidatePaths();
        PathWarning?.Invoke(warnings);
        SaveStatus = "Saved ✓";
        _ = ClearSaveStatusAsync();
    }

    [RelayCommand]
    private void ResetDefaults()
    {
        var d = new TraySettings();
        GatewayPort              = d.GatewayPort;
        GatewayLabel             = d.GatewayLabel;
        StatusPollInterval       = d.StatusPollInterval;
        FileIntegrityInterval    = d.FileIntegrityInterval;
        AlertLogInterval         = d.AlertLogInterval;
        EgressCheckInterval      = d.EgressCheckInterval;
        PatchCheckInterval       = d.PatchCheckInterval;
        NamespaceCheckInterval   = d.NamespaceCheckInterval;
        PermissionCheckInterval  = d.PermissionCheckInterval;
        ExposureCheckInterval    = d.ExposureCheckInterval;
        TokenAgeCheckInterval    = d.TokenAgeCheckInterval;
        TokenMaxAgeDays          = d.TokenMaxAgeDays;
        ExpectedPatchedFileCount = d.ExpectedPatchedFileCount;
        StartMinimized               = d.StartMinimized;
        ShowNotificationOnKillSwitch = d.ShowNotificationOnKillSwitch;
        AutoReapplyEgress            = d.AutoReapplyEgress;
        NpmGlobalPath          = d.NpmGlobalPath;
        OpenClawConfigPath     = d.OpenClawConfigPath;
        GatewayEnvPath         = d.GatewayEnvPath;
        SecurityAlertsLogPath  = d.SecurityAlertsLogPath;
        SaveStatus = "Defaults restored — click Save to apply";
    }

    [RelayCommand]
    private void Cancel() => CloseRequested?.Invoke();

    private string ValidatePaths()
    {
        var missing = new List<string>();
        string Expand(string p) => p.Replace("~", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (!Directory.Exists(Expand(NpmGlobalPath)))           missing.Add("npm global prefix");
        if (!File.Exists(Expand(OpenClawConfigPath)))           missing.Add("openclaw.json");
        if (!File.Exists(Expand(GatewayEnvPath)))               missing.Add("gateway.env");
        if (!File.Exists(Expand(SecurityAlertsLogPath)))        missing.Add("security-alerts.log");
        return missing.Count == 0 ? "" : $"⚠ Not found: {string.Join(", ", missing)}";
    }

    private async Task ClearSaveStatusAsync()
    {
        await Task.Delay(2500);
        SaveStatus = "";
        CloseRequested?.Invoke();
    }
}
