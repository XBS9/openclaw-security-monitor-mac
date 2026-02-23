using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace OpenClawSecurityMonitorMac.Core;

/// <summary>
/// Persists and validates all monitor settings to ~/.openclaw/monitor-settings.json.
///
/// Security hardening on every Save():
///   • chmod 600 applied via bash so other macOS accounts cannot read the file.
///   • SHA-256 integrity sidecar written to settings.integrity for tamper detection.
///     (No DPAPI on macOS — the hash is stored as plain hex, keyed to the file content.)
///
/// Migration: after deserialization, MigrateMonitoredFiles() ensures new default-monitored
/// entries added in later versions are merged into existing settings.
/// </summary>
public class TraySettings
{
    private static readonly string SettingsDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".openclaw");

    private static readonly string SettingsPath    = Path.Combine(SettingsDir, "monitor-settings.json");
    private static readonly string IntegrityPath   = Path.Combine(SettingsDir, "monitor-settings.integrity");
    private static readonly string StartupErrorLog = Path.Combine(SettingsDir, "monitor-startup-errors.log");

    // -------------------------------------------------------------------------
    // Settings properties
    // -------------------------------------------------------------------------

    // Gateway
    [JsonPropertyName("gatewayPort")]
    public int GatewayPort { get; set; } = 18789;

    [JsonPropertyName("commandTimeoutSeconds")]
    public int CommandTimeoutSeconds { get; set; } = 30;

    // macOS launchd service paths (replaces systemd on Linux)
    [JsonPropertyName("serviceBasePath")]
    public string ServiceBasePath { get; set; } = "~/Library/LaunchAgents";

    [JsonPropertyName("gatewayLabel")]
    public string GatewayLabel { get; set; } = "ai.openclaw.gateway";

    // Paths
    [JsonPropertyName("openclawConfigPath")]
    public string OpenClawConfigPath { get; set; } = "~/.openclaw/openclaw.json";

    [JsonPropertyName("gatewayEnvPath")]
    public string GatewayEnvPath { get; set; } = "~/.openclaw/gateway.env";

    [JsonPropertyName("npmGlobalPath")]
    public string NpmGlobalPath { get; set; } = "/usr/local";

    [JsonPropertyName("securityAlertsLogPath")]
    public string SecurityAlertsLogPath { get; set; } = "~/.openclaw/security-alerts.log";

    [JsonPropertyName("trayLogPath")]
    public string TrayLogPath { get; set; } = "~/.openclaw/security-tray.log";

    // Monitor intervals (seconds)
    [JsonPropertyName("statusPollInterval")]
    public int StatusPollInterval { get; set; } = 15;

    [JsonPropertyName("fileIntegrityInterval")]
    public int FileIntegrityInterval { get; set; } = 60;

    [JsonPropertyName("alertLogInterval")]
    public int AlertLogInterval { get; set; } = 30;

    [JsonPropertyName("egressCheckInterval")]
    public int EgressCheckInterval { get; set; } = 300;

    [JsonPropertyName("patchCheckInterval")]
    public int PatchCheckInterval { get; set; } = 300;

    [JsonPropertyName("namespaceCheckInterval")]
    public int NamespaceCheckInterval { get; set; } = 300;

    [JsonPropertyName("permissionCheckInterval")]
    public int PermissionCheckInterval { get; set; } = 300;

    [JsonPropertyName("exposureCheckInterval")]
    public int ExposureCheckInterval { get; set; } = 300;

    // Token age check runs every 6 hours — token creation date changes rarely.
    [JsonPropertyName("tokenAgeCheckInterval")]
    public int TokenAgeCheckInterval { get; set; } = 21600;

    // Warn when the gateway token is older than this many days (CVE-2026-25253 mitigation).
    [JsonPropertyName("tokenMaxAgeDays")]
    public int TokenMaxAgeDays { get; set; } = 30;

    // Thresholds
    [JsonPropertyName("expectedPatchedFileCount")]
    public int ExpectedPatchedFileCount { get; set; } = 7;

    // Monitored files for FIM
    [JsonPropertyName("monitoredFiles")]
    public List<MonitoredFileConfig> MonitoredFiles { get; set; } = new()
    {
        new() { Path = "~/.openclaw/workspace/SOUL.md",      Critical = true },
        new() { Path = "~/.openclaw/workspace/IDENTITY.md",  Critical = false },
        new() { Path = "~/.openclaw/workspace/AGENTS.md",    Critical = false },
        new() { Path = "~/.openclaw/workspace/TOOLS.md",     Critical = false },
        new() { Path = "~/.openclaw/openclaw.json",          Critical = false, CheckPermissions = "600" },
        new() { Path = "~/.openclaw/gateway.env",            Critical = false, CheckPermissions = "600" },
        // Service templates: tampering enables privilege escalation
        new() { Path = "~/Library/LaunchAgents/ai.openclaw.gateway.hardened.plist", Critical = true },
        new() { Path = "~/Library/LaunchAgents/ai.openclaw.gateway.unlocked.plist", Critical = true },
        new() { Path = "~/.zshrc",                           Critical = false },
        // Device identity files: high-value infostealer targets
        new() { Path = "~/.openclaw/identity/device.json",      Critical = false, CheckPermissions = "600" },
        new() { Path = "~/.openclaw/identity/device-auth.json", Critical = false, CheckPermissions = "600" },
        // OAuth/token store
        new() { Path = "~/.openclaw/agents/main/agent/auth-profiles.json", Critical = false, CheckPermissions = "600" },
    };

    // Egress (macOS pf firewall)
    [JsonPropertyName("autoReapplyEgress")]
    public bool AutoReapplyEgress { get; set; } = true;

    [JsonPropertyName("egressScriptPath")]
    public string EgressScriptPath { get; set; } = "~/.openclaw/pf-allowlist.sh";

    [JsonPropertyName("egressDenylistScriptPath")]
    public string EgressDenylistScriptPath { get; set; } = "~/.openclaw/pf-denylist.sh";

    [JsonPropertyName("egressModePath")]
    public string EgressModePath { get; set; } = "~/.openclaw/egress-mode";

    // Behavior
    [JsonPropertyName("startMinimized")]
    public bool StartMinimized { get; set; } = true;

    [JsonPropertyName("showNotificationOnKillSwitch")]
    public bool ShowNotificationOnKillSwitch { get; set; } = true;

    [JsonPropertyName("hasShownFirstRun")]
    public bool HasShownFirstRun { get; set; } = false;

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    private static readonly Regex SafePathRegex    = new(@"^~?/[A-Za-z0-9._/\-]+$", RegexOptions.Compiled);
    private static readonly Regex SafeLabelRegex   = new(@"^[A-Za-z0-9._\-]+$",     RegexOptions.Compiled);
    private static readonly Regex SafeFilenameRegex = new(@"^[A-Za-z0-9._\-]+$",   RegexOptions.Compiled);

    private static bool IsValidPath(string path) =>
        SafePathRegex.IsMatch(path) && !path.Contains("..");

    public static bool IsValidFilename(string name) => SafeFilenameRegex.IsMatch(name);

    private static int Clamp(int value, int min, int max) => Math.Max(min, Math.Min(max, value));

    public void Validate()
    {
        var defaults = new TraySettings();

        if (!SafeLabelRegex.IsMatch(GatewayLabel))         GatewayLabel        = defaults.GatewayLabel;
        if (!IsValidPath(ServiceBasePath))                  ServiceBasePath     = defaults.ServiceBasePath;
        if (!IsValidPath(OpenClawConfigPath))               OpenClawConfigPath  = defaults.OpenClawConfigPath;
        if (!IsValidPath(GatewayEnvPath))                   GatewayEnvPath      = defaults.GatewayEnvPath;
        if (!IsValidPath(NpmGlobalPath))                    NpmGlobalPath       = defaults.NpmGlobalPath;
        if (!IsValidPath(SecurityAlertsLogPath))            SecurityAlertsLogPath = defaults.SecurityAlertsLogPath;
        if (!IsValidPath(TrayLogPath))                      TrayLogPath         = defaults.TrayLogPath;
        if (!IsValidPath(EgressScriptPath))                 EgressScriptPath         = defaults.EgressScriptPath;
        if (!IsValidPath(EgressDenylistScriptPath))         EgressDenylistScriptPath = defaults.EgressDenylistScriptPath;
        if (!IsValidPath(EgressModePath))                   EgressModePath           = defaults.EgressModePath;

        foreach (var f in MonitoredFiles)
        {
            if (!IsValidPath(f.Path))
                f.Path = "";
        }
        MonitoredFiles.RemoveAll(f => string.IsNullOrEmpty(f.Path));

        CommandTimeoutSeconds  = Clamp(CommandTimeoutSeconds,  5,   120);
        GatewayPort            = Clamp(GatewayPort,            1024, 65535);
        StatusPollInterval     = Clamp(StatusPollInterval,     5,   600);
        FileIntegrityInterval  = Clamp(FileIntegrityInterval,  10,  3600);
        AlertLogInterval       = Clamp(AlertLogInterval,       5,   600);
        EgressCheckInterval    = Clamp(EgressCheckInterval,    30,  3600);
        PatchCheckInterval     = Clamp(PatchCheckInterval,     30,  3600);
        NamespaceCheckInterval = Clamp(NamespaceCheckInterval, 30,  3600);
        ExpectedPatchedFileCount = Clamp(ExpectedPatchedFileCount, 1,  50);
        PermissionCheckInterval  = Clamp(PermissionCheckInterval,  30, 3600);
        ExposureCheckInterval    = Clamp(ExposureCheckInterval,    30, 3600);
        TokenAgeCheckInterval    = Clamp(TokenAgeCheckInterval,    300, 86400);
        TokenMaxAgeDays          = Clamp(TokenMaxAgeDays,          7,  365);
    }

    private void MigrateMonitoredFiles()
    {
        var defaults = new TraySettings();
        var existing = new HashSet<string>(
            MonitoredFiles.Select(f => f.Path), StringComparer.Ordinal);

        foreach (var def in defaults.MonitoredFiles)
        {
            if (!existing.Contains(def.Path))
                MonitoredFiles.Add(def);
        }
    }

    // -------------------------------------------------------------------------
    // Load / Save
    // -------------------------------------------------------------------------

    public static TraySettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);

                if (!VerifyIntegrity(json))
                {
                    LogStartupError("monitor-settings.json failed integrity check — using defaults.");
                    var fresh = new TraySettings();
                    fresh.Save();
                    return fresh;
                }

                var settings = JsonSerializer.Deserialize<TraySettings>(json) ?? new TraySettings();
                settings.Validate();
                settings.MigrateMonitoredFiles();
                settings.NpmGlobalPath = DetectNpmGlobalPath(settings.NpmGlobalPath);
                return settings;
            }
        }
        catch (Exception ex)
        {
            LogStartupError($"Settings load failed: {ex.Message}");
        }

        var defaults = new TraySettings();
        defaults.NpmGlobalPath = DetectNpmGlobalPath(defaults.NpmGlobalPath);
        defaults.Save();
        return defaults;
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);

            // chmod 600 — restrict to current user only
            HardenPermissions(SettingsPath);
            SaveIntegrity(json);
        }
        catch (Exception ex)
        {
            LogStartupError($"Settings save failed: {ex.Message}");
        }
    }

    // -------------------------------------------------------------------------
    // macOS permission hardening (chmod 600 via Process)
    // -------------------------------------------------------------------------

    private static void HardenPermissions(string filePath)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "/bin/chmod",
                ArgumentList = { "600", filePath },
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(2000);
        }
        catch (Exception ex)
        {
            LogStartupError($"chmod 600 failed for {filePath}: {ex.Message}");
        }
    }

    // -------------------------------------------------------------------------
    // SHA-256 integrity (no DPAPI on macOS — plain hash sidecar)
    // -------------------------------------------------------------------------

    private static void SaveIntegrity(string json)
    {
        try
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
            // Store as hex string — not encrypted, but detects accidental or adversarial edits
            File.WriteAllText(IntegrityPath, Convert.ToHexString(hash));
            HardenPermissions(IntegrityPath);
        }
        catch (Exception ex)
        {
            LogStartupError($"Integrity sidecar write failed: {ex.Message}");
        }
    }

    private static bool VerifyIntegrity(string json)
    {
        if (!File.Exists(IntegrityPath)) return true;

        try
        {
            var storedHex  = File.ReadAllText(IntegrityPath).Trim();
            var storedHash = Convert.FromHexString(storedHex);
            var currentHash = SHA256.HashData(Encoding.UTF8.GetBytes(json));

            return CryptographicOperations.FixedTimeEquals(storedHash, currentHash);
        }
        catch
        {
            return true;
        }
    }

    // -------------------------------------------------------------------------
    // npm global path auto-detection (Intel vs Apple Silicon)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns the correct npm global path for this machine.
    /// Intel Macs: /usr/local  |  Apple Silicon (Homebrew): /opt/homebrew
    /// Falls back to the configured value if neither location has OpenClaw installed.
    /// </summary>
    private static string DetectNpmGlobalPath(string configured)
    {
        // Check configured path first (respects user override)
        if (Directory.Exists(Path.Combine(configured, "lib", "node_modules", "openclaw")))
            return configured;

        // Apple Silicon Homebrew
        const string arm = "/opt/homebrew";
        if (Directory.Exists(Path.Combine(arm, "lib", "node_modules", "openclaw")))
            return arm;

        // Intel / legacy Homebrew
        const string intel = "/usr/local";
        if (Directory.Exists(Path.Combine(intel, "lib", "node_modules", "openclaw")))
            return intel;

        return configured; // OpenClaw not installed yet — keep configured value
    }

    // -------------------------------------------------------------------------
    // Error logging
    // -------------------------------------------------------------------------

    private static void LogStartupError(string message)
    {
        try
        {
            Directory.CreateDirectory(SettingsDir);
            File.AppendAllText(StartupErrorLog,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
        }
        catch { }
    }
}

public class MonitoredFileConfig
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = "";

    [JsonPropertyName("critical")]
    public bool Critical { get; set; }

    [JsonPropertyName("checkPermissions")]
    public string? CheckPermissions { get; set; }
}
