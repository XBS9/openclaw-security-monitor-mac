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
    [ObservableProperty] private int _systemPostureCheckInterval;
    [ObservableProperty] private int _cronJobCheckInterval;
    [ObservableProperty] private int _systemExtensionCheckInterval;

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

    // ── Webhook alerting ───────────────────────────────────────────────────
    [ObservableProperty] private bool _webhookAlertsEnabled;
    [ObservableProperty] private string _webhookAlertUrl = "";
    [ObservableProperty] private string _webhookTestStatus = "";

    // ── Email alerting ─────────────────────────────────────────────────────
    [ObservableProperty] private bool _emailAlertsEnabled;
    [ObservableProperty] private string _smtpHost = "";
    [ObservableProperty] private int _smtpPort;
    [ObservableProperty] private bool _smtpSsl;
    [ObservableProperty] private string _smtpUser = "";
    [ObservableProperty] private string _smtpPassword = "";
    [ObservableProperty] private string _smtpFrom = "";
    [ObservableProperty] private string _alertEmailTo = "";

    // ── Alert escalation ───────────────────────────────────────────────────
    [ObservableProperty] private bool _alertOnAlerts;
    [ObservableProperty] private bool _alertOnWarnings;
    [ObservableProperty] private int  _alertCooldownMinutes;

    // ── Kill switch rules ──────────────────────────────────────────────────
    // Comma-separated monitor names that bypass gateway lock (alert still fires)
    [ObservableProperty] private string _killSwitchBypassText = "";

    // ── Daily digest ───────────────────────────────────────────────────────
    [ObservableProperty] private bool _dailyDigestEnabled;
    [ObservableProperty] private int _dailyDigestHour;

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

        StatusPollInterval          = _settings.StatusPollInterval;
        FileIntegrityInterval       = _settings.FileIntegrityInterval;
        AlertLogInterval            = _settings.AlertLogInterval;
        EgressCheckInterval         = _settings.EgressCheckInterval;
        PatchCheckInterval          = _settings.PatchCheckInterval;
        NamespaceCheckInterval      = _settings.NamespaceCheckInterval;
        PermissionCheckInterval     = _settings.PermissionCheckInterval;
        ExposureCheckInterval       = _settings.ExposureCheckInterval;
        TokenAgeCheckInterval       = _settings.TokenAgeCheckInterval;
        SystemPostureCheckInterval  = _settings.SystemPostureCheckInterval;
        CronJobCheckInterval        = _settings.CronJobCheckInterval;
        SystemExtensionCheckInterval = _settings.SystemExtensionCheckInterval;

        TokenMaxAgeDays          = _settings.TokenMaxAgeDays;
        ExpectedPatchedFileCount = _settings.ExpectedPatchedFileCount;

        StartMinimized               = _settings.StartMinimized;
        ShowNotificationOnKillSwitch = _settings.ShowNotificationOnKillSwitch;
        AutoReapplyEgress            = _settings.AutoReapplyEgress;

        NpmGlobalPath           = _settings.NpmGlobalPath;
        OpenClawConfigPath      = _settings.OpenClawConfigPath;
        GatewayEnvPath          = _settings.GatewayEnvPath;
        SecurityAlertsLogPath   = _settings.SecurityAlertsLogPath;

        WebhookAlertsEnabled    = _settings.WebhookAlertsEnabled;
        WebhookAlertUrl         = _settings.WebhookAlertUrl;

        AlertOnAlerts           = _settings.AlertOnAlerts;
        AlertOnWarnings         = _settings.AlertOnWarnings;
        AlertCooldownMinutes    = _settings.AlertCooldownMinutes;

        EmailAlertsEnabled   = _settings.EmailAlertsEnabled;
        SmtpHost             = _settings.SmtpHost;
        SmtpPort             = _settings.SmtpPort;
        SmtpSsl              = _settings.SmtpSsl;
        SmtpUser             = _settings.SmtpUser;
        SmtpPassword         = _settings.SmtpPassword;
        SmtpFrom             = _settings.SmtpFrom;
        AlertEmailTo         = _settings.AlertEmailTo;

        KillSwitchBypassText = string.Join(", ", _settings.KillSwitchDisabledMonitors);

        DailyDigestEnabled      = _settings.DailyDigestEnabled;
        DailyDigestHour         = _settings.DailyDigestHour;
    }

    [RelayCommand]
    private void Save()
    {
        _settings.GatewayPort            = GatewayPort;
        _settings.GatewayLabel           = GatewayLabel;

        _settings.StatusPollInterval           = StatusPollInterval;
        _settings.FileIntegrityInterval        = FileIntegrityInterval;
        _settings.AlertLogInterval             = AlertLogInterval;
        _settings.EgressCheckInterval          = EgressCheckInterval;
        _settings.PatchCheckInterval           = PatchCheckInterval;
        _settings.NamespaceCheckInterval       = NamespaceCheckInterval;
        _settings.PermissionCheckInterval      = PermissionCheckInterval;
        _settings.ExposureCheckInterval        = ExposureCheckInterval;
        _settings.TokenAgeCheckInterval        = TokenAgeCheckInterval;
        _settings.SystemPostureCheckInterval   = SystemPostureCheckInterval;
        _settings.CronJobCheckInterval         = CronJobCheckInterval;
        _settings.SystemExtensionCheckInterval = SystemExtensionCheckInterval;

        _settings.TokenMaxAgeDays          = TokenMaxAgeDays;
        _settings.ExpectedPatchedFileCount = ExpectedPatchedFileCount;

        _settings.StartMinimized               = StartMinimized;
        _settings.ShowNotificationOnKillSwitch = ShowNotificationOnKillSwitch;
        _settings.AutoReapplyEgress            = AutoReapplyEgress;

        _settings.NpmGlobalPath          = NpmGlobalPath;
        _settings.OpenClawConfigPath     = OpenClawConfigPath;
        _settings.GatewayEnvPath         = GatewayEnvPath;
        _settings.SecurityAlertsLogPath  = SecurityAlertsLogPath;

        _settings.WebhookAlertsEnabled   = WebhookAlertsEnabled;
        _settings.WebhookAlertUrl        = WebhookAlertUrl;

        _settings.AlertOnAlerts          = AlertOnAlerts;
        _settings.AlertOnWarnings        = AlertOnWarnings;
        _settings.AlertCooldownMinutes   = AlertCooldownMinutes;

        _settings.EmailAlertsEnabled   = EmailAlertsEnabled;
        _settings.SmtpHost             = SmtpHost;
        _settings.SmtpPort             = SmtpPort;
        _settings.SmtpSsl              = SmtpSsl;
        _settings.SmtpUser             = SmtpUser;
        _settings.SmtpPassword         = SmtpPassword;
        _settings.SmtpFrom             = SmtpFrom;
        _settings.AlertEmailTo         = AlertEmailTo;

        _settings.KillSwitchDisabledMonitors = KillSwitchBypassText
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        _settings.DailyDigestEnabled     = DailyDigestEnabled;
        _settings.DailyDigestHour        = DailyDigestHour;

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
        StatusPollInterval           = d.StatusPollInterval;
        FileIntegrityInterval        = d.FileIntegrityInterval;
        AlertLogInterval             = d.AlertLogInterval;
        EgressCheckInterval          = d.EgressCheckInterval;
        PatchCheckInterval           = d.PatchCheckInterval;
        NamespaceCheckInterval       = d.NamespaceCheckInterval;
        PermissionCheckInterval      = d.PermissionCheckInterval;
        ExposureCheckInterval        = d.ExposureCheckInterval;
        TokenAgeCheckInterval        = d.TokenAgeCheckInterval;
        SystemPostureCheckInterval   = d.SystemPostureCheckInterval;
        CronJobCheckInterval         = d.CronJobCheckInterval;
        SystemExtensionCheckInterval = d.SystemExtensionCheckInterval;
        TokenMaxAgeDays          = d.TokenMaxAgeDays;
        ExpectedPatchedFileCount = d.ExpectedPatchedFileCount;
        StartMinimized               = d.StartMinimized;
        ShowNotificationOnKillSwitch = d.ShowNotificationOnKillSwitch;
        AutoReapplyEgress            = d.AutoReapplyEgress;
        NpmGlobalPath          = d.NpmGlobalPath;
        OpenClawConfigPath     = d.OpenClawConfigPath;
        GatewayEnvPath         = d.GatewayEnvPath;
        SecurityAlertsLogPath  = d.SecurityAlertsLogPath;
        WebhookAlertsEnabled   = d.WebhookAlertsEnabled;
        WebhookAlertUrl        = d.WebhookAlertUrl;
        AlertOnAlerts          = d.AlertOnAlerts;
        AlertOnWarnings        = d.AlertOnWarnings;
        AlertCooldownMinutes   = d.AlertCooldownMinutes;
        EmailAlertsEnabled     = d.EmailAlertsEnabled;
        SmtpHost               = d.SmtpHost;
        SmtpPort               = d.SmtpPort;
        SmtpSsl                = d.SmtpSsl;
        SmtpUser               = d.SmtpUser;
        SmtpPassword           = d.SmtpPassword;
        SmtpFrom               = d.SmtpFrom;
        AlertEmailTo           = d.AlertEmailTo;
        KillSwitchBypassText   = string.Join(", ", d.KillSwitchDisabledMonitors);
        DailyDigestEnabled     = d.DailyDigestEnabled;
        DailyDigestHour        = d.DailyDigestHour;
        SaveStatus = "Defaults restored — click Save to apply";
    }

    [RelayCommand]
    private async Task TestWebhook()
    {
        if (string.IsNullOrWhiteSpace(WebhookAlertUrl))
        {
            WebhookTestStatus = "⚠ Enter a webhook URL first";
            await Task.Delay(3000);
            WebhookTestStatus = "";
            return;
        }

        WebhookTestStatus = "Sending test…";
        try
        {
            var testEvt = new OpenClawSecurityMonitorMac.Models.SecurityEvent
            {
                Timestamp = DateTime.Now,
                Monitor   = "WebhookTest",
                Trigger   = "Test webhook from OpenClaw Security Monitor",
                Details   = "This is a test alert fired from Settings.",
                Action    = "TEST"
            };

            // Temporarily enable and send, regardless of the checkbox state
            var svc = new OpenClawSecurityMonitorMac.Services.WebhookAlertService(
                new OpenClawSecurityMonitorMac.Core.TraySettings
                {
                    WebhookAlertsEnabled = true,
                    WebhookAlertUrl      = WebhookAlertUrl
                });
            svc.SendAlert(testEvt);

            await Task.Delay(2000); // give the fire-and-forget time to complete
            WebhookTestStatus = "✓ Test sent";
        }
        catch (Exception ex)
        {
            WebhookTestStatus = $"✗ {ex.Message}";
        }

        await Task.Delay(4000);
        WebhookTestStatus = "";
    }

    /// <summary>
    /// Deletes all persisted baseline files from ~/.openclaw/baselines/.
    /// Monitors will re-establish baselines on the next check cycle.
    /// Use this after acknowledging a legitimate system change that produced false alerts.
    /// </summary>
    [RelayCommand]
    private void ResetBaselines()
    {
        try
        {
            var baselineDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".openclaw", "baselines");
            if (Directory.Exists(baselineDir))
            {
                foreach (var f in Directory.GetFiles(baselineDir))
                    File.Delete(f);
            }
            SaveStatus = "Baselines cleared — will re-establish on next check";
        }
        catch (Exception ex)
        {
            SaveStatus = $"Reset failed: {ex.Message}";
        }
        _ = ClearSaveStatusAsync();
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
