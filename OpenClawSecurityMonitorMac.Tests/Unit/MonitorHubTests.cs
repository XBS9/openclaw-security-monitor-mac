using OpenClawSecurityMonitorMac.Core;
using Xunit;

namespace OpenClawSecurityMonitorMac.Tests.Unit;

public class MonitorHubTests
{
    [Fact]
    public void Constructor_RegistersAll16Monitors()
    {
        var hub = new MonitorHub();
        var all = hub.GetAll();
        Assert.Equal(16, all.Count);
    }

    [Fact]
    public void Constructor_AllMonitors_StartInStartingState()
    {
        var hub = new MonitorHub();
        Assert.All(hub.GetAll(), s => Assert.Equal(MonitorState.Starting, s.State));
    }

    [Fact]
    public void Report_UpdatesStateAndDetail()
    {
        var hub = new MonitorHub();
        hub.Report(MonitorHub.Gateway, MonitorState.Ok, "Running fine");

        var gw = hub.GetAll().First(s => s.Name == MonitorHub.Gateway);
        Assert.Equal(MonitorState.Ok,   gw.State);
        Assert.Equal("Running fine",    gw.Detail);
        Assert.NotNull(gw.LastChecked);
    }

    [Fact]
    public void Report_UpdatedEventFires()
    {
        var hub  = new MonitorHub();
        bool fired = false;
        hub.Updated += () => fired = true;

        hub.Report(MonitorHub.FileIntegrity, MonitorState.Alert, "Modified!");

        Assert.True(fired);
    }

    [Fact]
    public void Report_UnknownMonitorName_DoesNotThrow()
    {
        var hub = new MonitorHub();
        var ex  = Record.Exception(() =>
            hub.Report("NonExistentMonitor", MonitorState.Ok, "ignored"));
        Assert.Null(ex);
    }

    [Fact]
    public void Report_MultipleReports_LastValueWins()
    {
        var hub = new MonitorHub();
        hub.Report(MonitorHub.Egress, MonitorState.Ok,      "OK");
        hub.Report(MonitorHub.Egress, MonitorState.Warning, "Anchor missing");

        var egress = hub.GetAll().First(s => s.Name == MonitorHub.Egress);
        Assert.Equal(MonitorState.Warning, egress.State);
        Assert.Equal("Anchor missing",     egress.Detail);
    }

    [Fact]
    public void GetAll_ReturnsSnapshot_NotLiveReference()
    {
        var hub  = new MonitorHub();
        var snap = hub.GetAll();
        hub.Report(MonitorHub.Gateway, MonitorState.Ok, "Updated after snapshot");

        // Snapshot taken before the report should still show Starting
        var snapshotGw = snap.First(s => s.Name == MonitorHub.Gateway);
        Assert.Equal(MonitorState.Starting, snapshotGw.State);
    }

    [Fact]
    public void AllMonitorNameConstants_AreRegistered()
    {
        var hub   = new MonitorHub();
        var names = hub.GetAll().Select(s => s.Name).ToHashSet();

        Assert.Contains(MonitorHub.Gateway,          names);
        Assert.Contains(MonitorHub.FileIntegrity,    names);
        Assert.Contains(MonitorHub.AlertLog,         names);
        Assert.Contains(MonitorHub.Egress,           names);
        Assert.Contains(MonitorHub.Patches,          names);
        Assert.Contains(MonitorHub.Namespace,        names);
        Assert.Contains(MonitorHub.Permissions,      names);
        Assert.Contains(MonitorHub.Exposure,         names);
        Assert.Contains(MonitorHub.TokenAge,         names);
        Assert.Contains(MonitorHub.LaunchAgents,     names);
        Assert.Contains(MonitorHub.BinaryIntegrity,  names);
        Assert.Contains(MonitorHub.TccPermissions,   names);
        Assert.Contains(MonitorHub.SudoLog,          names);
        Assert.Contains(MonitorHub.SystemPosture,    names);
        Assert.Contains(MonitorHub.CronJobs,         names);
        Assert.Contains(MonitorHub.SystemExtensions, names);
    }
}
