using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Tests.Mocks;
using Xunit;

namespace OpenClawSecurityMonitorMac.Tests.Unit;

public class KillSwitchTests : IDisposable
{
    // Use a temp dir for state persistence so tests don't touch ~/.openclaw
    private readonly string _tempStateDir;

    public KillSwitchTests()
    {
        _tempStateDir = Path.Combine(Path.GetTempPath(), $"openclaw-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempStateDir);
        // Override the state path by pointing TrayLogPath at temp dir
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempStateDir, recursive: true); } catch { }
    }

    private (KillSwitch ks, MockGatewayService gw) Make(
        List<string>? bypassList = null)
    {
        var gw       = new MockGatewayService();
        var settings = new TraySettings
        {
            TrayLogPath                 = Path.Combine(_tempStateDir, "tray.log"),
            KillSwitchDisabledMonitors  = bypassList ?? new List<string>()
        };
        var ks = new KillSwitch(gw, settings);
        return (ks, gw);
    }

    // ── Normal fire ──────────────────────────────────────────────────────────

    [Fact]
    public async Task FireAsync_Normal_EngagesKillSwitch()
    {
        var (ks, _) = Make();
        await ks.FireAsync("LaunchAgentScanMonitor", "New plist detected", "test.plist");
        Assert.True(ks.IsEngaged);
    }

    [Fact]
    public async Task FireAsync_Normal_LocksGateway()
    {
        var (ks, gw) = Make();
        await ks.FireAsync("LaunchAgentScanMonitor", "New plist", "test.plist");
        Assert.True(gw.LockCalled);
    }

    [Fact]
    public async Task FireAsync_Normal_RecordsEvent()
    {
        var (ks, _) = Make();
        await ks.FireAsync("FileIntegrity", "File modified", "/etc/hosts changed");
        Assert.Single(ks.Events);
        Assert.Equal("FileIntegrity", ks.Events[0].Monitor);
    }

    [Fact]
    public async Task FireAsync_Normal_EventActionIsKillSwitch()
    {
        var (ks, _) = Make();
        await ks.FireAsync("TestMonitor", "trigger", "details");
        Assert.Contains("KILL_SWITCH", ks.Events[0].Action);
    }

    [Fact]
    public async Task FireAsync_Normal_IncrementsUnreviewedCount()
    {
        var (ks, _) = Make();
        await ks.FireAsync("M1", "t1", "d1");
        await ks.FireAsync("M2", "t2", "d2");
        Assert.Equal(2, ks.UnreviewedCount);
    }

    [Fact]
    public async Task FireAsync_LockFails_RetriesOnce()
    {
        var (ks, gw) = Make();
        gw.LockResult = false;
        await ks.FireAsync("Monitor", "trigger", "details");
        // Should have tried twice on failure
        Assert.Equal(2, gw.LockCallCount);
    }

    [Fact]
    public async Task FireAsync_TriggeredEvent_Fires()
    {
        var (ks, _) = Make();
        Models.SecurityEvent? received = null;
        ks.Triggered += evt => received = evt;

        await ks.FireAsync("Monitor", "Trigger", "Details");

        Assert.NotNull(received);
        Assert.Equal("Monitor", received!.Monitor);
    }

    // ── Bypass list ──────────────────────────────────────────────────────────

    [Fact]
    public async Task FireAsync_BypassedMonitor_DoesNotEngage()
    {
        var (ks, _) = Make(bypassList: new List<string> { "Cron Jobs" });
        await ks.FireAsync("Cron Jobs", "New cron", "crontab -l");
        Assert.False(ks.IsEngaged);
    }

    [Fact]
    public async Task FireAsync_BypassedMonitor_DoesNotLockGateway()
    {
        var (ks, gw) = Make(bypassList: new List<string> { "Binary Integrity" });
        await ks.FireAsync("Binary Integrity", "Hash changed", "sha256 mismatch");
        Assert.False(gw.LockCalled);
    }

    [Fact]
    public async Task FireAsync_BypassedMonitor_StillRecordsEvent()
    {
        var (ks, _) = Make(bypassList: new List<string> { "System Extensions" });
        await ks.FireAsync("System Extensions", "New ext", "com.evil.ext");
        Assert.Single(ks.Events);
    }

    [Fact]
    public async Task FireAsync_BypassedMonitor_EventActionContainsBypassed()
    {
        var (ks, _) = Make(bypassList: new List<string> { "Cron Jobs" });
        await ks.FireAsync("Cron Jobs", "trigger", "details");
        Assert.Contains("bypassed", ks.Events[0].Action, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FireAsync_BypassedMonitor_DoesNotIncrementUnreviewed()
    {
        var (ks, _) = Make(bypassList: new List<string> { "Cron Jobs" });
        await ks.FireAsync("Cron Jobs", "trigger", "details");
        Assert.Equal(0, ks.UnreviewedCount);
    }

    [Fact]
    public async Task FireAsync_BypassCheck_IsCaseInsensitive()
    {
        var (ks, gw) = Make(bypassList: new List<string> { "cron jobs" });
        await ks.FireAsync("Cron Jobs", "trigger", "details");
        Assert.False(gw.LockCalled);
    }

    [Fact]
    public async Task FireAsync_NonBypassed_StillLocksWhenOtherBypassesExist()
    {
        var (ks, gw) = Make(bypassList: new List<string> { "Cron Jobs" });
        await ks.FireAsync("LaunchAgentScanMonitor", "New plist", "evil.plist");
        Assert.True(gw.LockCalled);
        Assert.True(ks.IsEngaged);
    }

    // ── Disengage / ClearAlerts ──────────────────────────────────────────────

    [Fact]
    public async Task Disengage_SetsEngagedFalse()
    {
        var (ks, _) = Make();
        await ks.FireAsync("M", "t", "d");
        Assert.True(ks.IsEngaged);

        ks.Disengage();
        Assert.False(ks.IsEngaged);
    }

    [Fact]
    public async Task ClearAlerts_ResetsUnreviewedCount()
    {
        var (ks, _) = Make();
        await ks.FireAsync("M", "t", "d");
        Assert.Equal(1, ks.UnreviewedCount);

        ks.ClearAlerts();
        Assert.Equal(0, ks.UnreviewedCount);
    }

    [Fact]
    public async Task ClearAlerts_DoesNotRemoveEvents()
    {
        var (ks, _) = Make();
        await ks.FireAsync("M", "t", "d");
        ks.ClearAlerts();
        Assert.Single(ks.Events); // events are audit trail, not cleared
    }
}
