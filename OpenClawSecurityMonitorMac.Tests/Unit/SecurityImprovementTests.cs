using System.Text;
using System.Text.Json;
using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;
using OpenClawSecurityMonitorMac.Services;
using OpenClawSecurityMonitorMac.Tests.Mocks;
using Xunit;

namespace OpenClawSecurityMonitorMac.Tests.Unit;

/// <summary>
/// Tests for the 5 security improvements shipped in v1.6.0:
///   1. Event-driven FIM (FileSystemWatcher + debounce)
///   2. Persistent baselines (BaselinePersistence load/save)
///   3. Alert-level email/webhook notifications (MonitorHub.StateEscalated)
///   4. App self-protection (SystemPosture plist check)
///   5. Baseline tamper protection (SHA-256 integrity sidecar)
/// </summary>
[Collection("NoParallel")]
public class SecurityImprovementTests
{
    // ─────────────────────────────────────────────────────────────────────────
    // Improvement 5 + 2: BaselinePersistence — load / save / tamper detection
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void BaselinePersistence_NotFound_WhenNoFile()
    {
        using var tmp = new TempBaselineDir();
        WithBaselineDir(tmp.Path, () =>
        {
            var result = BaselinePersistence.TryLoad("does-not-exist", out var loaded);
            Assert.Equal(BaselinePersistence.LoadResult.NotFound, result);
            Assert.Null(loaded);
        });
    }

    [Fact]
    public void BaselinePersistence_SaveAndLoad_RoundTrip()
    {
        using var tmp = new TempBaselineDir();
        WithBaselineDir(tmp.Path, () =>
        {
            var original = new HashSet<string>(StringComparer.Ordinal)
                { "ai.openclaw.gateway.plist", "com.apple.other.plist" };

            BaselinePersistence.Save("launch-agents", original);
            var result = BaselinePersistence.TryLoad("launch-agents", out var loaded);

            Assert.Equal(BaselinePersistence.LoadResult.Ok, result);
            Assert.NotNull(loaded);
            Assert.Equal(original, loaded, StringComparer.Ordinal);
        });
    }

    [Fact]
    public void BaselinePersistence_Tampered_WhenJsonModifiedWithoutSidecar()
    {
        using var tmp = new TempBaselineDir();
        WithBaselineDir(tmp.Path, () =>
        {
            var original = new HashSet<string>(StringComparer.Ordinal) { "legit.plist" };
            BaselinePersistence.Save("launch-agents", original);

            // Silently inject a new entry into the JSON without updating integrity sidecar
            var jsonPath = Path.Combine(tmp.Path, "launch-agents.json");
            var tampered = JsonSerializer.Serialize(new List<string> { "legit.plist", "evil-backdoor.plist" });
            File.WriteAllText(jsonPath, tampered);

            var result = BaselinePersistence.TryLoad("launch-agents", out var loaded);
            Assert.Equal(BaselinePersistence.LoadResult.Tampered, result);
            Assert.Null(loaded);
        });
    }

    [Fact]
    public void BaselinePersistence_Dict_SaveAndLoad_RoundTrip()
    {
        using var tmp = new TempBaselineDir();
        WithBaselineDir(tmp.Path, () =>
        {
            var original = new Dictionary<string, FileBaseline>
            {
                ["~/.ssh/authorized_keys"] = new() { Path = "~/.ssh/authorized_keys", Hash = "abc123", IsCritical = true },
                ["~/.openclaw/openclaw.json"] = new() { Path = "~/.openclaw/openclaw.json", Hash = "def456", IsCritical = false }
            };

            BaselinePersistence.SaveDict("file-integrity", original);
            var result = BaselinePersistence.TryLoadDict("file-integrity", out var loaded);

            Assert.Equal(BaselinePersistence.LoadResult.Ok, result);
            Assert.NotNull(loaded);
            Assert.Equal(2, loaded.Count);
            Assert.Equal("abc123", loaded["~/.ssh/authorized_keys"].Hash);
            Assert.True(loaded["~/.ssh/authorized_keys"].IsCritical);
        });
    }

    [Fact]
    public void BaselinePersistence_Dict_Tampered_WhenJsonModifiedWithoutSidecar()
    {
        using var tmp = new TempBaselineDir();
        WithBaselineDir(tmp.Path, () =>
        {
            var original = new Dictionary<string, FileBaseline>
            {
                ["~/.ssh/authorized_keys"] = new() { Path = "~/.ssh/authorized_keys", Hash = "original-hash" }
            };
            BaselinePersistence.SaveDict("file-integrity", original);

            // Tamper: change the hash in the JSON without updating integrity sidecar
            var jsonPath = Path.Combine(tmp.Path, "file-integrity.json");
            var loaded0  = JsonSerializer.Deserialize<Dictionary<string, FileBaseline>>(File.ReadAllText(jsonPath))!;
            loaded0["~/.ssh/authorized_keys"].Hash = "attacker-replaced-hash";
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(loaded0));

            var result = BaselinePersistence.TryLoadDict("file-integrity", out var loaded);
            Assert.Equal(BaselinePersistence.LoadResult.Tampered, result);
            Assert.Null(loaded);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Improvement 3: MonitorHub.StateEscalated event
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void MonitorHub_StateEscalated_FiresOnOkToAlert()
    {
        var hub = new MonitorHub();
        MonitorStatus? captured = null;
        hub.StateEscalated += s => captured = s;

        hub.Report(MonitorHub.LaunchAgents, MonitorState.Ok, "All good");
        hub.Report(MonitorHub.LaunchAgents, MonitorState.Alert, "Evil plist detected");

        Assert.NotNull(captured);
        Assert.Equal(MonitorHub.LaunchAgents, captured.Name);
        Assert.Equal(MonitorState.Alert, captured.State);
        Assert.Equal("Evil plist detected", captured.Detail);
    }

    [Fact]
    public void MonitorHub_StateEscalated_FiresOnStartingToWarning()
    {
        var hub = new MonitorHub();
        MonitorStatus? captured = null;
        hub.StateEscalated += s => captured = s;

        // Starting → Warning (first check reveals SSH is on)
        hub.Report(MonitorHub.SystemPosture, MonitorState.Warning, "SSH on");

        Assert.NotNull(captured);
        Assert.Equal(MonitorState.Warning, captured.State);
    }

    [Fact]
    public void MonitorHub_StateEscalated_DoesNotFireOnAlertToAlert()
    {
        var hub = new MonitorHub();
        int fireCount = 0;
        hub.StateEscalated += _ => fireCount++;

        hub.Report(MonitorHub.LaunchAgents, MonitorState.Ok, "OK");
        hub.Report(MonitorHub.LaunchAgents, MonitorState.Alert, "First alert");
        hub.Report(MonitorHub.LaunchAgents, MonitorState.Alert, "Repeated alert");

        Assert.Equal(1, fireCount); // fires only on escalation, not on repeated alerts
    }

    [Fact]
    public void MonitorHub_StateEscalated_DoesNotFireOnWarningToAlert_WhenNoOkInBetween()
    {
        var hub = new MonitorHub();
        int fireCount = 0;
        hub.StateEscalated += _ => fireCount++;

        hub.Report(MonitorHub.CronJobs, MonitorState.Ok, "OK");      // Ok → Warning fires
        hub.Report(MonitorHub.CronJobs, MonitorState.Warning, "New cron");
        hub.Report(MonitorHub.CronJobs, MonitorState.Alert, "Alert"); // Warning → Alert does NOT fire (not from Ok/Starting)

        Assert.Equal(1, fireCount);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Improvement 4: SystemPosture self-protection plist check
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SystemPosture_SelfProtectionPlistMissing_IncludesWarning()
    {
        // The self-protection plist almost certainly does NOT exist in a test environment.
        // This test verifies the monitor includes the warning in its output when the plist
        // is absent — without any mock trickery required.
        var cmd      = new MockCommandService();
        var hub      = new MonitorHub();
        var gw       = new MockGatewayService();
        var settings = new TraySettings { SystemPostureCheckInterval = 1 };

        // Feed "all good" responses for all other posture checks
        cmd.EnqueueMany(
            (0, "System Integrity Protection status: enabled.", ""),  // SIP
            (0, "assessments enabled", ""),                           // GK
            (0, "__disabled__", ""),                                  // auto-login
            (0, "1", ""),                                             // ALF on
            (0, "GroupMembership: root testuser", ""),                // admin
            (0, "Remote Login: Off", ""),                             // SSH
            (0, "SCREEN_OFF", ""),                                    // screen sharing
            (0, "RD_OFF", "")                                         // remote mgmt
        );

        var monitor = new SystemPostureMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        monitor.Start();
        await WaitForStateAsync(hub, MonitorHub.SystemPosture,
            s => s != MonitorState.Starting, cts.Token);
        monitor.Stop();

        var status = hub.GetAll().First(s => s.Name == MonitorHub.SystemPosture);

        // If the plist is genuinely missing, we should see Warning with the message.
        // If it somehow exists, the test still passes (just checks other posture is Ok).
        var selfPlistPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Library", "LaunchAgents", "com.openclaw.security-monitor.plist");

        if (!File.Exists(selfPlistPath))
        {
            Assert.Equal(MonitorState.Warning, status.State);
            Assert.Contains("Self-protection plist missing", status.Detail);
        }
        else
        {
            // Plist exists — test is not meaningful but should still pass cleanly
            Assert.True(status.State == MonitorState.Ok || status.State == MonitorState.Warning);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Improvement 2: Persistent baseline — LaunchAgent restart detection
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LaunchAgent_PersistentBaseline_AlertsOnNewPlistAfterRestart()
    {
        using var tmp = new TempBaselineDir();
        await WithBaselineDirAsync(tmp.Path, async () =>
        {
            // Simulate a previous run that saved "legit.plist" as the baseline
            var priorBaseline = new HashSet<string>(StringComparer.Ordinal) { "legit.plist" };
            BaselinePersistence.Save("launch-agents", priorBaseline);

            // Now start the monitor fresh (simulates restart) — current state has an extra plist
            var cmd      = new MockCommandService();
            var hub      = new MonitorHub();
            var gw       = new MockGatewayService();
            var settings = new TraySettings { LaunchAgentCheckInterval = 1 };

            // First check: legit.plist PLUS evil-backdoor.plist
            cmd.Enqueue(output: "legit.plist\nevil-backdoor.plist\n");

            var ks      = new KillSwitch(gw, settings);
            var monitor = new LaunchAgentScanMonitor(cmd, ks, settings, hub);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            monitor.Start();
            await WaitForStateAsync(hub, MonitorHub.LaunchAgents,
                s => s == MonitorState.Alert, cts.Token);
            monitor.Stop();

            // Should have fired kill switch without waiting for a second poll cycle
            Assert.True(gw.LockCalled, "Kill switch should fire on startup when new plist matches persisted baseline diff");
            Assert.True(ks.IsEngaged);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Improvement 1: Event-driven FIM — FSW + debounce
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FileIntegrityFSW_NonCriticalChange_ReportsWarningWithinTwoSeconds()
    {
        // Create a temp file that the monitor will watch
        var tempDir  = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, "testfile.txt");
        File.WriteAllText(tempFile, "original content");

        try
        {
            var cmd      = new MockCommandService();
            var hub      = new MonitorHub();
            var gw       = new MockGatewayService();
            var settings = new TraySettings
            {
                FileIntegrityInterval = 3600, // poll never fires during test
                MonitoredFiles = new()
                {
                    new() { Path = tempFile, Critical = false }
                }
            };

            // First batch check (baseline establishment): return a hash
            const string baselineHash = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
            cmd.Enqueue(output: $"HASH:{tempFile}:{baselineHash}");

            // FSW-triggered single-file check: return a different hash
            const string changedHash = "ffffeeeeddddccccffffeeeeddddccccffffeeeeddddccccffffeeeeddddcccc";
            cmd.Enqueue(output: $"HASH:{tempFile}:{changedHash}");

            using var tmpBaseline = new TempBaselineDir();
            await WithBaselineDirAsync(tmpBaseline.Path, async () =>
            {
                var monitor = new FileIntegrityMonitor(cmd, new KillSwitch(gw, settings), settings, hub);
                monitor.Start();

                // Wait for baseline to be established (initial delay is up to 5s)
                await WaitForStateAsync(hub, MonitorHub.FileIntegrity,
                    s => s == MonitorState.Ok, new CancellationTokenSource(8000).Token);

                // Now modify the file to trigger FSW → 500ms debounce → CheckSingleFileAsync
                var writeTime = DateTime.Now;
                File.WriteAllText(tempFile, "modified content");

                // Assert Warning fires within 2 seconds (500ms debounce + command overhead)
                using var warnCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await WaitForStateAsync(hub, MonitorHub.FileIntegrity,
                    s => s == MonitorState.Warning, warnCts.Token);

                var elapsed = DateTime.Now - writeTime;
                monitor.Stop();
                monitor.Dispose();

                var status = hub.GetAll().First(s => s.Name == MonitorHub.FileIntegrity);
                Assert.Equal(MonitorState.Warning, status.State);
                Assert.Contains("Changed", status.Detail);
                Assert.True(elapsed.TotalSeconds < 2.5,
                    $"FSW alert should fire in < 2s; took {elapsed.TotalSeconds:F1}s");
            });
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
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

    /// <summary>
    /// Temporarily redirects BaselinePersistence I/O to <paramref name="tempDir"/> for the
    /// duration of <paramref name="action"/>, then restores the null (production) path.
    /// </summary>
    private static void WithBaselineDir(string tempDir, Action action)
    {
        BaselinePersistence.TestBaselineDir = tempDir;
        try   { action(); }
        finally { BaselinePersistence.TestBaselineDir = null; }
    }

    private static async Task WithBaselineDirAsync(string tempDir, Func<Task> action)
    {
        BaselinePersistence.TestBaselineDir = tempDir;
        try   { await action(); }
        finally { BaselinePersistence.TestBaselineDir = null; }
    }
}

/// <summary>
/// RAII guard that creates and cleans up a temp directory for baseline isolation.
/// Tests use this to avoid polluting ~/.openclaw/baselines.
/// Since BaselinePersistence.BaselineDir is hardcoded, tests that save/load
/// directly call BaselinePersistence methods and rely on cleanup in Dispose().
/// </summary>
internal sealed class TempBaselineDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(), "openclaw-test-" + Guid.NewGuid().ToString("N")[..8]);

    public TempBaselineDir() => Directory.CreateDirectory(Path);

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch { }
    }
}
