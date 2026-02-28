using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Tests.Mocks;

/// <summary>
/// Fake IGatewayService that records calls without touching launchctl or the filesystem.
/// </summary>
public class MockGatewayService : IGatewayService
{
    public bool LockCalled   { get; private set; }
    public bool UnlockCalled { get; private set; }

    public bool LockResult   { get; set; } = true;
    public bool UnlockResult { get; set; } = true;

    public GatewayStatus StatusToReturn { get; set; } = new GatewayStatus
    {
        IsRunning     = true,
        Mode          = GatewayMode.Unlocked,
        SecurityScore = 6.7
    };

    public int LockCallCount   { get; private set; }
    public int UnlockCallCount { get; private set; }

    public Task<bool> LockAsync()
    {
        LockCalled = true;
        LockCallCount++;
        return Task.FromResult(LockResult);
    }

    public Task<bool> UnlockAsync()
    {
        UnlockCalled = true;
        UnlockCallCount++;
        return Task.FromResult(UnlockResult);
    }

    public Task<GatewayStatus> GetStatusAsync()
        => Task.FromResult(StatusToReturn);

    public Task<bool> RestartAsync()
        => Task.FromResult(true);

    public Task<(bool Success, string Message)> SyncTokenAsync()
        => Task.FromResult((true, "Token synced"));

    public Task<string> GetLogsAsync(int lines = 100)
        => Task.FromResult("mock log output");
}
