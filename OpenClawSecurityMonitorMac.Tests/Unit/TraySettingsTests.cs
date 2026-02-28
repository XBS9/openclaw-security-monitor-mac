using OpenClawSecurityMonitorMac.Core;
using Xunit;

namespace OpenClawSecurityMonitorMac.Tests.Unit;

public class TraySettingsTests
{
    // ── Defaults ──────────────────────────────────────────────────────────────

    [Fact]
    public void NewInstance_HasExpectedDefaults()
    {
        var s = new TraySettings();
        Assert.Equal(18789,  s.GatewayPort);
        Assert.Equal(15,     s.StatusPollInterval);
        Assert.Equal(300,    s.SystemPostureCheckInterval);
        Assert.Equal(300,    s.CronJobCheckInterval);
        Assert.Equal(600,    s.SystemExtensionCheckInterval);
        Assert.Equal(587,    s.SmtpPort);
        Assert.True(s.SmtpSsl);
        Assert.False(s.EmailAlertsEnabled);
        Assert.False(s.WebhookAlertsEnabled);
        Assert.True(s.DailyDigestEnabled);
        Assert.Equal(9,      s.DailyDigestHour);
        Assert.Empty(s.KillSwitchDisabledMonitors);
    }

    [Fact]
    public void NewInstance_MonitoredFiles_ContainsEtcHosts()
    {
        var s = new TraySettings();
        Assert.Contains(s.MonitoredFiles, f => f.Path == "/etc/hosts");
    }

    [Fact]
    public void NewInstance_MonitoredFiles_ContainsSshAuthorizedKeys()
    {
        var s = new TraySettings();
        var entry = s.MonitoredFiles.FirstOrDefault(f => f.Path == "~/.ssh/authorized_keys");
        Assert.NotNull(entry);
        Assert.True(entry!.Critical);
    }

    // ── Validate — clamping ───────────────────────────────────────────────────

    [Fact]
    public void Validate_ClampsGatewayPortBelow1024_ToMin()
    {
        var s = new TraySettings { GatewayPort = 80 };
        s.Validate();
        Assert.Equal(1024, s.GatewayPort);
    }

    [Fact]
    public void Validate_ClampsGatewayPortAbove65535_ToMax()
    {
        var s = new TraySettings { GatewayPort = 99999 };
        s.Validate();
        Assert.Equal(65535, s.GatewayPort);
    }

    [Fact]
    public void Validate_ClampsStatusPollInterval_ToMin()
    {
        var s = new TraySettings { StatusPollInterval = 0 };
        s.Validate();
        Assert.Equal(5, s.StatusPollInterval);
    }

    [Fact]
    public void Validate_ClampsSystemPostureCheckInterval_ToMin()
    {
        var s = new TraySettings { SystemPostureCheckInterval = 1 };
        s.Validate();
        Assert.Equal(30, s.SystemPostureCheckInterval);
    }

    [Fact]
    public void Validate_ClampsCronJobCheckInterval_ToMax()
    {
        var s = new TraySettings { CronJobCheckInterval = 99999 };
        s.Validate();
        Assert.Equal(3600, s.CronJobCheckInterval);
    }

    [Fact]
    public void Validate_ClampsSmtpPort_ToMin()
    {
        var s = new TraySettings { SmtpPort = -1 };
        s.Validate();
        Assert.Equal(1, s.SmtpPort);
    }

    [Fact]
    public void Validate_ClampsDailyDigestHour_ToRange()
    {
        var s = new TraySettings { DailyDigestHour = 25 };
        s.Validate();
        Assert.Equal(23, s.DailyDigestHour);
    }

    [Fact]
    public void Validate_ResetsInvalidGatewayLabel_ToDefault()
    {
        var s = new TraySettings { GatewayLabel = "bad label with spaces!" };
        s.Validate();
        Assert.Equal("ai.openclaw.gateway", s.GatewayLabel);
    }

    [Fact]
    public void Validate_RemovesMonitoredFilesWithInvalidPaths()
    {
        var s = new TraySettings();
        s.MonitoredFiles.Add(new MonitoredFileConfig { Path = "../../etc/passwd" });
        s.Validate();
        Assert.DoesNotContain(s.MonitoredFiles, f => f.Path.Contains(".."));
    }

    // ── KillSwitchDisabledMonitors ────────────────────────────────────────────

    [Fact]
    public void KillSwitchDisabledMonitors_ContainsCheck_IsCaseInsensitive()
    {
        var s = new TraySettings
        {
            KillSwitchDisabledMonitors = new List<string> { "Cron Jobs", "System Extensions" }
        };
        Assert.Contains("cron jobs",        s.KillSwitchDisabledMonitors, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("SYSTEM EXTENSIONS",s.KillSwitchDisabledMonitors, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Launch Agents", s.KillSwitchDisabledMonitors, StringComparer.OrdinalIgnoreCase);
    }
}
