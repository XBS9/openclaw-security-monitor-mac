using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Services;
using OpenClawSecurityMonitorMac.Tests.Mocks;
using Xunit;

namespace OpenClawSecurityMonitorMac.Tests.Unit;

/// <summary>
/// Tests monitor behavior via MockCommandService — verifies that each monitor
/// correctly interprets command output and reports the right MonitorState.
/// These tests do not start the background timer loop; they call CheckAsync
/// indirectly by driving Start() with a very short delay and cancellation.
///
/// Strategy: Start() → immediate first check fires → cancel → inspect hub state.
/// We use a short initial delay override by providing an interval of 1ms via
/// a subclassed settings object so the check fires before the test times out.
///
/// Isolation: each test instance redirects BaselinePersistence to a temp directory
/// so persistent baselines from real ~/.openclaw/baselines don't pollute tests.
/// A minimal self-protection plist is created if absent so SystemPosture tests
/// don't add a spurious "plist missing" warning to otherwise-clean posture checks.
/// </summary>
[Collection("NoParallel")]
public class MonitorBehaviorTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly string? _createdPlist;

    public MonitorBehaviorTests()
    {
        // Redirect all BaselinePersistence I/O to an isolated temp dir
        _tmpDir = Path.Combine(Path.GetTempPath(),
            "openclaw-mbtest-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tmpDir);
        BaselinePersistence.TestBaselineDir = _tmpDir;

        // Ensure self-protection plist exists so SystemPosture "Ok" tests aren't
        // downgraded to Warning by the plist-missing check
        var plistPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Library", "LaunchAgents", "com.openclaw.security-monitor.plist");
        if (!File.Exists(plistPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(plistPath)!);
            File.WriteAllText(plistPath,
                """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0"><dict>
                  <key>Label</key><string>com.openclaw.security-monitor</string>
                  <key>KeepAlive</key><true/>
                </dict></plist>
                """);
            _createdPlist = plistPath;
        }
    }

    public void Dispose()
    {
        BaselinePersistence.TestBaselineDir = null;
        try { Directory.Delete(_tmpDir, recursive: true); } catch { }
        if (_createdPlist != null)
            try { File.Delete(_createdPlist); } catch { }
    }

    private static (MockCommandService cmd, MonitorHub hub, MockGatewayService gw, TraySettings settings)
        BuildEnv(Action<TraySettings>? configure = null)
    {
        var cmd      = new MockCommandService();
        var hub      = new MonitorHub();
        var gw       = new MockGatewayService();
        var settings = new TraySettings
        {
            // Very short intervals so tests don't wait long
            LaunchAgentCheckInterval     = 1,
            SystemPostureCheckInterval   = 1,
            CronJobCheckInterval         = 1,
            SystemExtensionCheckInterval = 1,
        };
        configure?.Invoke(settings);
        return (cmd, hub, gw, settings);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LaunchAgentScanMonitor
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LaunchAgent_FirstCheck_SetsBaseline_ReportsOk()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        // Baseline scan: 2 plists present
        cmd.Enqueue(output: "ai.openclaw.gateway.plist\ncom.apple.other.plist\n");

        var monitor = new LaunchAgentScanMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        // Wait until hub has been updated from Starting
        await WaitForStateAsync(hub, MonitorHub.LaunchAgents,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.LaunchAgents);
        Assert.Equal(MonitorState.Ok, status.State);
        Assert.Contains("Baseline set", status.Detail);
    }

    [Fact]
    public async Task LaunchAgent_NewPlist_TriggersKillSwitch()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        // First call = baseline (1 plist)
        cmd.Enqueue(output: "ai.openclaw.gateway.plist\n");
        // Second call = new plist appeared
        cmd.Enqueue(output: "ai.openclaw.gateway.plist\nevil-backdoor.plist\n");

        var ks      = new KillSwitch(gw, settings);
        var monitor = new LaunchAgentScanMonitor(cmd, ks, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.LaunchAgents,
            s => s == MonitorState.Alert, cts.Token);
        monitor.Stop();

        Assert.True(gw.LockCalled, "Gateway should be locked when new plist is detected");
        Assert.True(ks.IsEngaged);
    }

    [Fact]
    public async Task LaunchAgent_RemovedPlist_ReportsWarning()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        cmd.Enqueue(output: "ai.openclaw.gateway.plist\nlegit.plist\n"); // baseline
        cmd.Enqueue(output: "ai.openclaw.gateway.plist\n");               // legit.plist gone

        var monitor = new LaunchAgentScanMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.LaunchAgents,
            s => s == MonitorState.Warning, cts.Token);
        monitor.Stop();

        Assert.False(gw.LockCalled, "Removed plist should warn, not lock");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SystemExtensionMonitor
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SystemExtension_FirstCheck_SetsBaseline()
    {
        var (cmd, hub, _, settings) = BuildEnv();
        cmd.Enqueue(output: "[activated enabled] com.apple.security.endpoint (1.0)\n");

        var monitor = new SystemExtensionMonitor(cmd, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemExtensions,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemExtensions);
        Assert.Equal(MonitorState.Ok, status.State);
        Assert.Contains("Baseline set", status.Detail);
    }

    [Fact]
    public async Task SystemExtension_NewExtension_ReportsAlert()
    {
        var (cmd, hub, _, settings) = BuildEnv();
        cmd.Enqueue(output: "[activated enabled] com.apple.security.endpoint (1.0)\n");
        cmd.Enqueue(output: "[activated enabled] com.apple.security.endpoint (1.0)\n[activated enabled] com.evil.keylogger (0.1)\n");

        var monitor = new SystemExtensionMonitor(cmd, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemExtensions,
            s => s == MonitorState.Alert, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemExtensions);
        Assert.Contains("com.evil.keylogger", status.Detail);
    }

    [Fact]
    public async Task SystemExtension_ParsesOutputCorrectly_MultipleBundleIds()
    {
        // We test the parsing indirectly: feed output and check that baseline count is 2
        var cmd      = new MockCommandService();
        var hub      = new MonitorHub();
        var settings = new TraySettings { SystemExtensionCheckInterval = 1 };

        var rawOutput =
            "[activated enabled] com.apple.driver.endpoint (1.0)\n" +
            "[activated enabled] com.apple.security.syspolicy (2.3)\n" +
            "  2 extension(s) found\n"; // non-bundle line should be ignored

        cmd.Enqueue(output: rawOutput);

        var monitor = new SystemExtensionMonitor(cmd, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemExtensions,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemExtensions);
        // Baseline OK message includes the count
        Assert.Contains("2", status.Detail);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CronJobMonitor
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CronJob_NoEntries_ReportsOk()
    {
        var (cmd, hub, _, settings) = BuildEnv();
        // crontab -l, cron.d, periodic — all empty
        cmd.EnqueueMany((0, "", ""), (0, "", ""), (0, "", ""));

        var monitor = new CronJobMonitor(cmd, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.CronJobs,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.CronJobs);
        Assert.Equal(MonitorState.Ok, status.State);
        Assert.Contains("No cron jobs", status.Detail);
    }

    [Fact]
    public async Task CronJob_NewEntryAfterBaseline_ReportsWarning()
    {
        var (cmd, hub, _, settings) = BuildEnv();
        // Baseline: no user cron, no cron.d, no periodic
        cmd.EnqueueMany((0, "", ""), (0, "", ""), (0, "", ""));
        // Second check: new user cron appears
        cmd.EnqueueMany((0, "0 3 * * * /usr/bin/evil-script.sh", ""), (0, "", ""), (0, "", ""));

        var monitor = new CronJobMonitor(cmd, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.CronJobs,
            s => s == MonitorState.Warning, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.CronJobs);
        Assert.Contains("New", status.Detail);
    }

    [Fact]
    public async Task CronJob_CommentLines_NotCounted()
    {
        var (cmd, hub, _, settings) = BuildEnv();
        // Only commented lines — should count as 0 user entries
        cmd.EnqueueMany((0, "# this is a comment\n# another comment", ""), (0, "", ""), (0, "", ""));

        var monitor = new CronJobMonitor(cmd, settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.CronJobs,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.CronJobs);
        Assert.Contains("No cron jobs", status.Detail);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SystemPostureMonitor — SIP / Gatekeeper
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SystemPosture_SipEnabled_GkEnabled_ReportsOk()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        // SIP, GK, autoLogin, ALF, admin, SSH, Screen, RD — all good
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: enabled.", ""),    // SIP
            (0, "assessments enabled", ""),                             // GK
            (0, "__disabled__", ""),                                    // auto-login
            (0, "1", ""),                                               // ALF on
            (0, "GroupMembership: root jorge", ""),                     // admin
            (0, "Remote Login: Off", ""),                               // SSH
            (0, "SCREEN_OFF", ""),                                      // screen sharing
            (0, "RD_OFF", "")                                           // remote mgmt
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);
        Assert.Equal(MonitorState.Ok, status.State);
    }

    [Fact]
    public async Task SystemPosture_SipDisabled_ReportsAlert()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: disabled.", ""),
            (0, "assessments enabled", ""),
            (0, "__disabled__", ""),
            (0, "1", ""),
            (0, "GroupMembership: root jorge", ""),
            (0, "Remote Login: Off", ""),
            (0, "SCREEN_OFF", ""),
            (0, "RD_OFF", "")
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s == MonitorState.Alert, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);
        Assert.Contains("SIP disabled", status.Detail);
    }

    [Fact]
    public async Task SystemPosture_GatekeeperDisabled_ReportsAlert()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: enabled.", ""),
            (0, "assessments disabled", ""),
            (0, "__disabled__", ""),
            (0, "1", ""),
            (0, "GroupMembership: root jorge", ""),
            (0, "Remote Login: Off", ""),
            (0, "SCREEN_OFF", ""),
            (0, "RD_OFF", "")
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s == MonitorState.Alert, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);
        Assert.Contains("Gatekeeper disabled", status.Detail);
    }

    [Fact]
    public async Task SystemPosture_AutoLoginEnabled_ReportsWarning()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: enabled.", ""),
            (0, "assessments enabled", ""),
            (0, "jorge", ""),                                           // auto-login user!
            (0, "1", ""),
            (0, "GroupMembership: root jorge", ""),
            (0, "Remote Login: Off", ""),
            (0, "SCREEN_OFF", ""),
            (0, "RD_OFF", "")
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s == MonitorState.Warning, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);
        Assert.Contains("Auto-login", status.Detail);
    }

    [Fact]
    public async Task SystemPosture_AppFirewallOff_ReportsWarning()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: enabled.", ""),
            (0, "assessments enabled", ""),
            (0, "__disabled__", ""),
            (0, "0", ""),                                               // ALF off!
            (0, "GroupMembership: root jorge", ""),
            (0, "Remote Login: Off", ""),
            (0, "SCREEN_OFF", ""),
            (0, "RD_OFF", "")
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s == MonitorState.Warning, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);
        Assert.Contains("App Firewall off", status.Detail);
    }

    [Fact]
    public async Task SystemPosture_RemoteAccessOn_ReportsWarning()
    {
        var (cmd, hub, gw, settings) = BuildEnv();
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: enabled.", ""),
            (0, "assessments enabled", ""),
            (0, "__disabled__", ""),
            (0, "1", ""),
            (0, "GroupMembership: root jorge", ""),
            (0, "Remote Login: On", ""),                               // SSH on!
            (0, "SCREEN_OFF", ""),
            (0, "RD_OFF", "")
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s == MonitorState.Warning, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);
        Assert.Contains("SSH on", status.Detail);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task WaitForStateAsync(MonitorHub hub, string monitorName,
        Func<MonitorState, bool> predicate, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var status = hub.GetAll().FirstOrDefault(s => s.Name == monitorName);
            if (status != null && predicate(status.State)) return;
            await Task.Delay(50, ct);
        }
        throw new TimeoutException($"Monitor '{monitorName}' never reached expected state.");
    }
}
